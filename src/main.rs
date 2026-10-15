mod acl;
mod auth;
mod checksum;
mod chunked;
mod config;
mod cors;
mod data;
mod error;
mod format;
#[cfg(test)]
mod fuzz_tests;
mod handlers;
mod janitor;
mod meta;
mod metrics;
mod post_policy;
mod util;
mod xml;

use config::{Command, Config, Durability};
use handlers::App;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let cfg = Config::load();
    acl::set_owner(cfg.owner_id.clone(), cfg.owner_name.clone());
    util::raise_fd_limit();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.threads)
        .max_blocking_threads(512)
        .thread_name("s3-worker")
        .enable_all()
        .build()
        .expect("tokio runtime");
    let res = match cfg.command {
        Command::Serve => rt.block_on(serve(cfg)),
        Command::Scrub => scrub(cfg),
    };
    // Don't wait for background blocking work (e.g. a cancelled scrub) at exit.
    rt.shutdown_timeout(Duration::from_secs(5));
    match res {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("fatal: {e}");
            std::process::exit(1);
        }
    }
}

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Opens the data directory. The metadata DB is opened first: it holds an
/// exclusive lock, so a second process fails before touching any files.
fn open_storage(cfg: &Config) -> AnyResult<(meta::Meta, data::DataStore)> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    format::check_or_init(&cfg.data_dir)?;
    let meta = meta::Meta::open(&cfg.data_dir.join("meta.redb"), cfg.cache_mb, cfg.durability).map_err(|e| {
        if e.message.contains("already open") || e.message.contains("lock") {
            format!("{} is in use by another process", cfg.data_dir.display())
        } else {
            e.message.into_owned()
        }
    })?;
    let data = data::DataStore::open(&cfg.data_dir, cfg.durability == Durability::Full, cfg.read_chunk, cfg.write_chunk)?;
    Ok((meta, data))
}

async fn serve(cfg: Config) -> AnyResult<i32> {
    let (meta, data) = open_storage(&cfg)?;
    let auth = auth::Auth::new(cfg.credentials.clone(), cfg.anonymous, cfg.sigv2);
    let mut data = data;
    data.min_free = cfg.min_free_bytes;
    let listener = TcpListener::bind(cfg.address).await?;

    eprintln!("s3 listening on http://{}", listener.local_addr()?);
    eprintln!("  data dir:    {}", cfg.data_dir.display());
    eprintln!("  durability:  {:?}, threads: {}", cfg.durability, cfg.threads);
    if cfg.anonymous {
        eprintln!("  WARNING: anonymous access is enabled; anyone can read and write");
    }

    if cfg.access_log {
        metrics::start_access_log();
    }
    let app = Arc::new(App { cfg, meta, data: Arc::new(data), auth });
    janitor::spawn(app.clone());
    tokio::spawn(reload_credentials_on_sighup(app.clone()));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let graceful = GracefulShutdown::new();
    let conn_limit = Arc::new(tokio::sync::Semaphore::new(app.cfg.max_connections));

    loop {
        // At the connection limit, stop accepting (clients queue in the kernel backlog).
        let permit = tokio::select! {
            p = conn_limit.clone().acquire_owned() => p.expect("semaphore closed"),
            _ = &mut shutdown => break,
        };
        let (stream, remote) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    // e.g. EMFILE: back off instead of spinning.
                    eprintln!("accept error: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);
        let app = app.clone();
        let svc = service_fn(move |req| {
            let app = app.clone();
            async move { Ok::<_, Infallible>(handlers::handle(app, req, remote).await) }
        });
        let conn = http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(Duration::from_secs(30))
            .keep_alive(true)
            .max_buf_size(1 << 20)
            .serve_connection(TokioIo::new(stream), svc);
        let conn = graceful.watch(conn);
        let open = metrics::GaugeGuard::new(&metrics::get().connections);
        tokio::spawn(async move {
            let _ = conn.await;
            drop(open);
            drop(permit);
        });
    }

    eprintln!("shutting down, draining connections (max 30s)");
    janitor::SHUTTING_DOWN.store(true, Ordering::Relaxed);
    drop(listener);
    if tokio::time::timeout(Duration::from_secs(30), graceful.shutdown()).await.is_err() {
        eprintln!("timed out waiting for connections");
    }
    if let Err(e) = app.meta.flush() {
        eprintln!("metadata flush failed: {}", e.message);
    }
    Ok(0)
}

/// `s3 scrub`: offline verification of every data file. Exit code 1 if
/// anything is missing or corrupted.
fn scrub(cfg: Config) -> AnyResult<i32> {
    let (meta, data) = open_storage(&cfg)?;
    eprintln!("verifying data files in {} ...", cfg.data_dir.display());
    let mut last = std::time::Instant::now();
    let report = janitor::scrub(&meta, &data, 0, |r| {
        if last.elapsed() > Duration::from_secs(5) {
            eprintln!("  {} files, {} MiB verified", r.files, r.bytes >> 20);
            last = std::time::Instant::now();
        }
    })?;
    let (orphans, orphan_bytes) = janitor::collect_orphans(&meta, &data, false)?;
    println!("verified files:  {} ({} bytes)", report.files, report.bytes);
    println!("orphaned files:  {orphans} ({orphan_bytes} bytes; removed automatically by the running server)");
    if report.problems.is_empty() {
        println!("problems:        none");
        return Ok(0);
    }
    println!("problems:        {}", report.problems.len());
    let ids = report.problems.iter().map(|(id, _)| id.clone()).collect();
    let owners: std::collections::HashMap<String, String> = meta.owners_of(&ids)?.into_iter().collect();
    for (id, msg) in &report.problems {
        println!("  {} [{}]: {msg}", owners.get(id).map_or("<unknown>", String::as_str), id);
    }
    Ok(1)
}

/// SIGHUP re-reads the credentials file, enabling key rotation without restart.
async fn reload_credentials_on_sighup(app: Arc<App>) {
    let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) else { return };
    while hup.recv().await.is_some() {
        let Some(path) = &app.cfg.credentials_file else {
            eprintln!("SIGHUP: no --credentials-file configured, nothing to reload");
            continue;
        };
        let mut creds = app.cfg.cli_credentials.clone();
        match config::load_credentials_file(path) {
            Ok(file_creds) => {
                creds.extend(file_creds);
                let n = app.auth.set_credentials(creds);
                eprintln!("SIGHUP: reloaded credentials ({n} key(s))");
            }
            Err(e) => eprintln!("SIGHUP: keeping previous credentials: {e}"),
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
}
