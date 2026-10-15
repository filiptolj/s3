//! Background maintenance: expiring abandoned multipart uploads, collecting
//! orphaned data files, and periodically re-verifying every data file
//! against its stored checksum (scrub).

use crate::data::{DataStore, CORRUPTIONS_DETECTED};
use crate::error::S3Result;
use crate::handlers::App;
use crate::meta::{self, Meta};
use crate::util::now_ms;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Set at shutdown so long-running background work stops promptly.
pub static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Files younger than this are never collected: they may belong to an upload
/// whose metadata is about to be committed.
const ORPHAN_MIN_AGE: Duration = Duration::from_secs(3600);
const TMP_MAX_AGE: Duration = Duration::from_secs(24 * 3600);
const LAST_SCRUB_KEY: &str = "last_scrub_ms";

pub fn spawn(app: Arc<App>) {
    tokio::spawn(maintenance_loop(app.clone()));
    if app.cfg.scrub_interval_days > 0.0 {
        tokio::spawn(scrub_loop(app));
    }
}

async fn maintenance_loop(app: Arc<App>) {
    let interval = Duration::from_secs(app.cfg.janitor_interval_secs);
    tokio::time::sleep(interval.min(Duration::from_secs(60))).await;
    loop {
        if let Err(e) = maintenance_once(&app).await {
            eprintln!("janitor: {}", e.message);
        }
        tokio::time::sleep(interval).await;
    }
}

async fn maintenance_once(app: &Arc<App>) -> S3Result<()> {
    if app.cfg.upload_expiry_hours > 0.0 {
        let cutoff = now_ms().saturating_sub((app.cfg.upload_expiry_hours * 3_600_000.0) as u64);
        let mut expired = 0;
        for id in app.meta.expired_uploads(cutoff)? {
            match app.meta.write(move |txn| meta::abort_upload_txn(txn, &id, None)).await {
                Ok(files) => {
                    app.data.remove_later(files);
                    expired += 1;
                }
                Err(e) if e.code == "NoSuchUpload" => {}
                Err(e) => return Err(e),
            }
        }
        if expired > 0 {
            crate::metrics::get().uploads_expired.fetch_add(expired, Ordering::Relaxed);
            eprintln!("janitor: aborted {expired} expired multipart upload(s)");
        }
    }
    let cutoff = now_ms().saturating_sub(24 * 3600 * 1000);
    app.meta.write(move |txn| meta::purge_completed_txn(txn, cutoff)).await?;
    let a = app.clone();
    let (tmp, orphans, bytes) = tokio::task::spawn_blocking(move || -> S3Result<(usize, usize, u64)> {
        let tmp = a.data.clean_tmp(TMP_MAX_AGE);
        let (n, b) = collect_orphans(&a.meta, &a.data, true)?;
        Ok((tmp, n, b))
    })
    .await??;
    if tmp > 0 {
        eprintln!("janitor: removed {tmp} stale temp file(s)");
    }
    if orphans > 0 {
        crate::metrics::get().orphans_removed.fetch_add(orphans as u64, Ordering::Relaxed);
        eprintln!("janitor: removed {orphans} orphaned data file(s) ({bytes} bytes)");
    }
    Ok(())
}

/// Finds data files that no object or upload references (left behind by a
/// crash between writing a file and committing its metadata, or by a failed
/// delete). Removes them if `remove`. Returns (count, bytes).
pub fn collect_orphans(meta: &Meta, data: &DataStore, remove: bool) -> S3Result<(usize, u64)> {
    let cutoff = SystemTime::now() - ORPHAN_MIN_AGE;
    let (mut count, mut bytes) = (0, 0);
    for dir in 0..65536u32 {
        if SHUTTING_DOWN.load(Ordering::Relaxed) {
            break;
        }
        let names = data.files_in(dir);
        if names.is_empty() {
            continue;
        }
        for id in meta.unreferenced(&names)? {
            // Only old files: a fresh one may be about to be referenced.
            if !data.modified_before(&id, cutoff) {
                continue;
            }
            let size = data.file_size(&id).unwrap_or(0);
            if !remove || data.remove_now(&id) {
                count += 1;
                bytes += size;
            }
        }
    }
    Ok((count, bytes))
}

#[derive(Default)]
pub struct ScrubReport {
    pub files: u64,
    pub bytes: u64,
    /// (file id, problem)
    pub problems: Vec<(String, String)>,
    pub cancelled: bool,
}

/// Re-reads every referenced data file and checks size and CRC32C.
/// `rate_mb` limits the read rate (0 = unlimited).
pub fn scrub(meta: &Meta, data: &DataStore, rate_mb: u64, mut progress: impl FnMut(&ScrubReport)) -> S3Result<ScrubReport> {
    let mut report = ScrubReport::default();
    let start = Instant::now();
    let mut read_total = 0u64;
    let rate = rate_mb * 1024 * 1024;
    let mut throttle = |n: usize| -> bool {
        read_total += n as u64;
        if rate > 0 {
            let due = Duration::from_secs_f64(read_total as f64 / rate as f64);
            if let Some(wait) = due.checked_sub(start.elapsed()) {
                std::thread::sleep(wait);
            }
        }
        !SHUTTING_DOWN.load(Ordering::Relaxed)
    };
    let mut after = String::new();
    loop {
        let page = meta.files_page(&after, 1000)?;
        let Some((last, _)) = page.last() else { break };
        after = last.clone();
        for (id, fr) in page {
            let res = data.verify_file(&id, fr.size, fr.crc, &mut throttle);
            if SHUTTING_DOWN.load(Ordering::Relaxed) {
                report.cancelled = true;
                return Ok(report);
            }
            match res {
                Ok(()) => {
                    report.files += 1;
                    report.bytes += fr.size;
                }
                // Ignore files whose object was deleted while we were scrubbing.
                Err(msg) if meta.file_ref(&id)?.is_some() => {
                    CORRUPTIONS_DETECTED.fetch_add(1, Ordering::Relaxed);
                    eprintln!("CORRUPTION: data file {id}: {msg}");
                    report.problems.push((id, msg));
                }
                Err(_) => {}
            }
        }
        progress(&report);
    }
    Ok(report)
}

async fn scrub_loop(app: Arc<App>) {
    let period = (app.cfg.scrub_interval_days * 86_400_000.0) as u64;
    // A fresh installation starts its first period now instead of scrubbing at once.
    match app.meta.system_get(LAST_SCRUB_KEY) {
        Ok(Some(_)) => {}
        Ok(None) => {
            let now = now_ms();
            let _ = app.meta.write(move |txn| meta::system_set(txn, LAST_SCRUB_KEY, now)).await;
        }
        Err(e) => eprintln!("scrub: {}", e.message),
    }
    loop {
        let last = app.meta.system_get(LAST_SCRUB_KEY).ok().flatten().unwrap_or(0);
        let now = now_ms();
        if now < last + period {
            tokio::time::sleep(Duration::from_millis((last + period - now).min(3600 * 1000))).await;
            continue;
        }
        eprintln!("scrub: starting background verification of all data files");
        let a = app.clone();
        let rate = app.cfg.scrub_rate_mb;
        let res = tokio::task::spawn_blocking(move || scrub(&a.meta, &a.data, rate, |_| {})).await;
        match res {
            Ok(Ok(r)) if r.cancelled => return,
            Ok(Ok(r)) => {
                eprintln!("scrub: verified {} files ({} bytes), {} problem(s)", r.files, r.bytes, r.problems.len());
                let m = crate::metrics::get();
                m.scrub_files_verified.fetch_add(r.files, Ordering::Relaxed);
                m.scrub_last_completed.store(now_ms() / 1000, Ordering::Relaxed);
                let now = now_ms();
                let _ = app.meta.write(move |txn| meta::system_set(txn, LAST_SCRUB_KEY, now)).await;
            }
            Ok(Err(e)) => {
                eprintln!("scrub: {}", e.message);
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            Err(e) => {
                eprintln!("scrub: {e}");
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
    }
}
