use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// No fsync of data; metadata is group-committed to disk at most every second.
    Relaxed,
    /// Metadata is fsynced on every (group) commit; data relies on the page cache.
    Meta,
    /// Data files are fdatasync'ed before metadata commit; metadata fsynced.
    Full,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Serve,
    /// Offline integrity check of a data directory.
    Scrub,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub command: Command,
    pub address: SocketAddr,
    pub data_dir: PathBuf,
    /// Accepted (access key, secret key) pairs.
    pub credentials: Vec<(String, String)>,
    pub credentials_file: Option<PathBuf>,
    /// The pair given via --access-key/--secret-key (kept across reloads).
    pub cli_credentials: Vec<(String, String)>,
    pub region: String,
    pub anonymous: bool,
    pub domain: Option<String>,
    pub inline_threshold: usize,
    pub durability: Durability,
    pub threads: usize,
    pub cache_mb: usize,
    pub read_chunk: usize,
    pub write_chunk: usize,
    pub fast_etag: bool,
    /// Incomplete multipart uploads older than this are aborted (0 = never).
    pub upload_expiry_hours: f64,
    /// Background scrub period (0 = disabled).
    pub scrub_interval_days: f64,
    /// Background scrub read rate limit in MiB/s (0 = unlimited).
    pub scrub_rate_mb: u64,
    pub janitor_interval_secs: u64,
    pub sigv2: bool,
    pub max_connections: usize,
    /// Writes are refused when free disk space would drop below this.
    pub min_free_bytes: u64,
    pub owner_id: Option<String>,
    pub owner_name: Option<String>,
    /// Bearer token for GET /_metrics (endpoint disabled when unset).
    pub metrics_token: Option<String>,
    pub access_log: bool,
}

const USAGE: &str = "\
s3 - fast, lightweight S3-compatible object storage

USAGE:
  s3 [OPTIONS]           run the server
  s3 scrub [OPTIONS]     verify every stored file against its checksum (server must be stopped)

Every option can also be set via the env var in brackets.

CREDENTIALS (at least one pair is required unless --anonymous):
  --access-key <KEY>        Access key, min 3 chars        [S3_ACCESS_KEY]
  --secret-key <SECRET>     Secret key, min 8 chars        [S3_SECRET_KEY]
  --credentials-file <PATH> File with one `access_key:secret_key` per line (# comments);
                            reloaded on SIGHUP for key rotation without restart
                                                           [S3_CREDENTIALS_FILE]

OPTIONS:
  --address <ADDR>          Listen address                 [S3_ADDRESS]      (default 0.0.0.0:9000)
  --data <DIR>              Data directory                 [S3_DATA]         (default ./data)
  --region <REGION>         Region reported to clients     [S3_REGION]       (default us-east-1)
  --domain <DOMAIN>         Enable virtual-host style requests for <bucket>.<DOMAIN> [S3_DOMAIN]
  --anonymous               Allow unauthenticated requests [S3_ANONYMOUS=1]
  --durability <MODE>       full | meta | relaxed          [S3_DURABILITY]   (default full)
                              full:    data + metadata fsynced before acknowledging
                              meta:    metadata fsynced, data in page cache (power loss
                                       may lose recently written data)
                              relaxed: nothing fsynced immediately, metadata flushed every
                                       second (fastest; power loss loses recent writes)
  --fast-etag               Use xxh3 instead of MD5 for ETags (much faster uploads; ETag is
                            then not the MD5 of the content)  [S3_FAST_ETAG=1]
  --inline-threshold <B>    Objects up to this size are stored inside the metadata DB
                                                           [S3_INLINE]       (default 65536)
  --upload-expiry-hours <H> Abort incomplete multipart uploads after H hours (0 = never)
                                                           [S3_UPLOAD_EXPIRY_HOURS] (default 168)
  --scrub-interval-days <D> Re-verify all data checksums every D days (0 = never)
                                                           [S3_SCRUB_INTERVAL_DAYS] (default 30)
  --scrub-rate-mb <MB>      Background scrub read limit in MiB/s (0 = unlimited)
                                                           [S3_SCRUB_RATE_MB] (default 64)
  --disable-sigv2           Reject legacy SigV2 signatures (note: boto3 presigns with SigV2
                            unless configured with signature_version='s3v4') [S3_DISABLE_SIGV2=1]
  --max-connections <N>     Max concurrent client connections [S3_MAX_CONNECTIONS] (default 4096)
  --min-free-mb <MB>        Refuse writes when free disk space would fall below this
                                                           [S3_MIN_FREE_MB]  (default 1024)
  --metrics-token <TOKEN>   Enable Prometheus metrics at /_metrics, readable with
                            `Authorization: Bearer <TOKEN>`  [S3_METRICS_TOKEN]
  --access-log              Write one JSON line per request to stdout [S3_ACCESS_LOG=1]
  --owner-id <ID>           Canonical user id reported as owner   [S3_OWNER_ID]
  --owner-name <NAME>       Display name reported as owner        [S3_OWNER_NAME]
  --threads <N>             Worker threads (0 = #cpus)     [S3_THREADS]      (default 0)
  --cache-mb <MB>           Metadata page cache size       [S3_CACHE_MB]     (default 64)
  --read-chunk <B>          Download read size             [S3_READ_CHUNK]   (default 262144)
  --write-chunk <B>         Upload write batch size        [S3_WRITE_CHUNK]  (default 1048576)
  -h, --help                Show this help
";

const FLAGS: &[&str] = &["anonymous", "fast-etag", "disable-sigv2", "access-log"];

impl Config {
    pub fn load() -> Config {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let mut args = std::env::args().skip(1).peekable();
        let command = match args.peek().map(String::as_str) {
            Some("scrub") => {
                args.next();
                Command::Scrub
            }
            Some("serve") => {
                args.next();
                Command::Serve
            }
            _ => Command::Serve,
        };
        let mut opts: std::collections::HashMap<String, String> = Default::default();
        while let Some(a) = args.next() {
            match a.as_str() {
                "-h" | "--help" => {
                    print!("{USAGE}");
                    std::process::exit(0);
                }
                s if s.starts_with("--") && FLAGS.contains(&&s[2..]) => {
                    opts.insert(s[2..].to_string(), "1".into());
                }
                s if s.starts_with("--") => {
                    let (k, v) = match s[2..].split_once('=') {
                        Some((k, v)) => (k.to_string(), v.to_string()),
                        None => (s[2..].to_string(), args.next().unwrap_or_else(|| die(&format!("missing value for {s}")))),
                    };
                    opts.insert(k, v);
                }
                s => die(&format!("unexpected argument: {s}")),
            }
        }
        let get = |k: &str, e: &str| opts.get(k).cloned().or_else(|| env(e));
        let num = |k: &str, e: &str, d: u64| -> u64 {
            get(k, e).map(|v| v.parse().unwrap_or_else(|_| die(&format!("invalid number for --{k}")))).unwrap_or(d)
        };
        let float = |k: &str, e: &str, d: f64| -> f64 {
            let v: f64 = get(k, e).map(|v| v.parse().unwrap_or_else(|_| die(&format!("invalid number for --{k}")))).unwrap_or(d);
            if !v.is_finite() || v < 0.0 {
                die(&format!("invalid value for --{k}"));
            }
            v
        };
        let flag = |k: &str, e: &str| get(k, e).is_some_and(|v| v == "1" || v == "true");
        let durability = match get("durability", "S3_DURABILITY").as_deref().unwrap_or("full") {
            "relaxed" => Durability::Relaxed,
            "meta" => Durability::Meta,
            "full" => Durability::Full,
            other => die(&format!("invalid durability: {other}")),
        };
        let threads = match num("threads", "S3_THREADS", 0) {
            0 => std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4),
            n => n as usize,
        };
        let anonymous = flag("anonymous", "S3_ANONYMOUS");
        let credentials_file: Option<PathBuf> = get("credentials-file", "S3_CREDENTIALS_FILE").map(Into::into);
        let mut credentials = Vec::new();
        match (get("access-key", "S3_ACCESS_KEY"), get("secret-key", "S3_SECRET_KEY")) {
            (Some(a), Some(s)) => credentials.push((a, s)),
            (None, None) => {}
            _ => die("--access-key and --secret-key must be set together"),
        }
        let cli_credentials = credentials.clone();
        if let Some(path) = &credentials_file {
            credentials.extend(load_credentials_file(path).unwrap_or_else(|e| die(&e)));
        }
        if let Err(e) = validate_credentials(&credentials) {
            die(&e);
        }
        if command == Command::Serve && !anonymous && credentials.is_empty() {
            die("no credentials: set --access-key/--secret-key (S3_ACCESS_KEY/S3_SECRET_KEY) or --credentials-file");
        }
        let n = |v: u64| v as usize;
        Config {
            command,
            address: get("address", "S3_ADDRESS")
                .unwrap_or_else(|| "0.0.0.0:9000".into())
                .parse()
                .unwrap_or_else(|_| die("invalid --address")),
            data_dir: get("data", "S3_DATA").unwrap_or_else(|| "./data".into()).into(),
            credentials,
            credentials_file,
            cli_credentials,
            region: get("region", "S3_REGION").unwrap_or_else(|| "us-east-1".into()),
            anonymous,
            domain: get("domain", "S3_DOMAIN").map(|d| d.to_ascii_lowercase()),
            inline_threshold: n(num("inline-threshold", "S3_INLINE", 64 * 1024)).min(1 << 20),
            durability,
            threads,
            cache_mb: n(num("cache-mb", "S3_CACHE_MB", 64)),
            read_chunk: n(num("read-chunk", "S3_READ_CHUNK", 256 * 1024)).clamp(4096, 64 << 20),
            write_chunk: n(num("write-chunk", "S3_WRITE_CHUNK", 1024 * 1024)).clamp(4096, 64 << 20),
            fast_etag: flag("fast-etag", "S3_FAST_ETAG"),
            upload_expiry_hours: float("upload-expiry-hours", "S3_UPLOAD_EXPIRY_HOURS", 168.0),
            scrub_interval_days: float("scrub-interval-days", "S3_SCRUB_INTERVAL_DAYS", 30.0),
            scrub_rate_mb: num("scrub-rate-mb", "S3_SCRUB_RATE_MB", 64),
            janitor_interval_secs: num("janitor-interval-secs", "S3_JANITOR_INTERVAL_SECS", 6 * 3600).max(1),
            sigv2: !flag("disable-sigv2", "S3_DISABLE_SIGV2"),
            max_connections: n(num("max-connections", "S3_MAX_CONNECTIONS", 4096)).max(1),
            min_free_bytes: num("min-free-mb", "S3_MIN_FREE_MB", 1024) * 1024 * 1024,
            owner_id: get("owner-id", "S3_OWNER_ID"),
            owner_name: get("owner-name", "S3_OWNER_NAME"),
            metrics_token: get("metrics-token", "S3_METRICS_TOKEN"),
            access_log: flag("access-log", "S3_ACCESS_LOG"),
        }
    }
}

/// Parses `access_key:secret_key` lines; blank lines and `#` comments are ignored.
pub fn load_credentials_file(path: &std::path::Path) -> Result<Vec<(String, String)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (a, s) = line
            .split_once(':')
            .ok_or_else(|| format!("{}:{}: expected access_key:secret_key", path.display(), i + 1))?;
        out.push((a.trim().to_string(), s.trim().to_string()));
    }
    validate_credentials(&out)?;
    Ok(out)
}

fn validate_credentials(creds: &[(String, String)]) -> Result<(), String> {
    for (a, s) in creds {
        if a.len() < 3 || a.contains(['/', ':', ' ']) {
            return Err(format!("invalid access key {a:?}: min 3 chars, no '/', ':' or spaces"));
        }
        if s.len() < 8 {
            return Err(format!("secret key for {a:?} is too short (min 8 chars)"));
        }
        if s == "s3admin-secret" || s == "minioadmin" {
            return Err("refusing to use a well-known default secret key".into());
        }
    }
    Ok(())
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}\n\nRun `s3 --help` for usage.");
    std::process::exit(2);
}
