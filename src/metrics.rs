//! Prometheus metrics and the JSON access log.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;

/// S3 operations, used as the `op` label.
pub const OPS: &[&str] = &[
    "ListBuckets", "CreateBucket", "DeleteBucket", "HeadBucket", "ListObjects", "ListObjectsV2", "ListObjectVersions",
    "GetBucketLocation", "GetBucketVersioning", "GetBucketAcl", "PutBucketAcl", "GetBucketCors", "PutBucketCors",
    "DeleteBucketCors", "ListMultipartUploads", "DeleteObjects", "PostObject", "GetObject", "HeadObject", "PutObject",
    "CopyObject", "DeleteObject", "GetObjectAcl", "PutObjectAcl", "GetObjectTagging", "GetObjectAttributes",
    "CreateMultipartUpload", "UploadPart", "UploadPartCopy", "CompleteMultipartUpload", "AbortMultipartUpload",
    "ListParts", "Options", "Internal", "Other",
];

const BUCKETS: [f64; 12] = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0];
const STATUS_CLASSES: [&str; 4] = ["2xx", "3xx", "4xx", "5xx"];

struct OpStats {
    by_status: [AtomicU64; 4],
    latency_buckets: [AtomicU64; BUCKETS.len()],
    latency_sum_us: AtomicU64,
}

pub struct Metrics {
    ops: Vec<OpStats>,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub inflight: AtomicI64,
    pub connections: AtomicI64,
    pub orphans_removed: AtomicU64,
    pub uploads_expired: AtomicU64,
    pub scrub_last_completed: AtomicU64,
    pub scrub_files_verified: AtomicU64,
    pub access_log_dropped: AtomicU64,
}

pub fn get() -> &'static Metrics {
    static M: OnceLock<Metrics> = OnceLock::new();
    M.get_or_init(|| Metrics {
        ops: OPS
            .iter()
            .map(|_| OpStats {
                by_status: Default::default(),
                latency_buckets: Default::default(),
                latency_sum_us: AtomicU64::new(0),
            })
            .collect(),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
        inflight: AtomicI64::new(0),
        connections: AtomicI64::new(0),
        orphans_removed: AtomicU64::new(0),
        uploads_expired: AtomicU64::new(0),
        scrub_last_completed: AtomicU64::new(0),
        scrub_files_verified: AtomicU64::new(0),
        access_log_dropped: AtomicU64::new(0),
    })
}

pub fn op_index(op: &str) -> usize {
    OPS.iter().position(|o| *o == op).unwrap_or(OPS.len() - 1)
}

impl Metrics {
    pub fn record(&self, op: &str, status: u16, secs: f64) {
        let s = &self.ops[op_index(op)];
        let class = ((status / 100).clamp(2, 5) - 2) as usize;
        s.by_status[class].fetch_add(1, Relaxed);
        for (i, b) in BUCKETS.iter().enumerate() {
            if secs <= *b {
                s.latency_buckets[i].fetch_add(1, Relaxed);
            }
        }
        s.latency_sum_us.fetch_add((secs * 1e6) as u64, Relaxed);
    }

    /// Prometheus text exposition format.
    pub fn render(&self, disk_free: Option<u64>) -> String {
        let mut x = String::with_capacity(16 * 1024);
        x.push_str("# HELP s3_requests_total Requests by operation and status class.\n# TYPE s3_requests_total counter\n");
        for (op, s) in OPS.iter().zip(&self.ops) {
            for (class, c) in STATUS_CLASSES.iter().zip(&s.by_status) {
                let v = c.load(Relaxed);
                if v > 0 {
                    let _ = writeln!(x, "s3_requests_total{{op=\"{op}\",status=\"{class}\"}} {v}");
                }
            }
        }
        x.push_str("# HELP s3_request_duration_seconds Time to response headers by operation.\n# TYPE s3_request_duration_seconds histogram\n");
        for (op, s) in OPS.iter().zip(&self.ops) {
            let count: u64 = s.by_status.iter().map(|c| c.load(Relaxed)).sum();
            if count == 0 {
                continue;
            }
            for (b, c) in BUCKETS.iter().zip(&s.latency_buckets) {
                let _ = writeln!(x, "s3_request_duration_seconds_bucket{{op=\"{op}\",le=\"{b}\"}} {}", c.load(Relaxed));
            }
            let _ = writeln!(x, "s3_request_duration_seconds_bucket{{op=\"{op}\",le=\"+Inf\"}} {count}");
            let _ = writeln!(x, "s3_request_duration_seconds_sum{{op=\"{op}\"}} {}", s.latency_sum_us.load(Relaxed) as f64 / 1e6);
            let _ = writeln!(x, "s3_request_duration_seconds_count{{op=\"{op}\"}} {count}");
        }
        let counters = [
            ("s3_received_bytes_total", "Request body bytes received (by Content-Length).", self.bytes_in.load(Relaxed)),
            ("s3_sent_bytes_total", "Response body bytes sent (by Content-Length).", self.bytes_out.load(Relaxed)),
            ("s3_corruptions_detected_total", "Data files that failed checksum verification.", crate::data::CORRUPTIONS_DETECTED.load(Relaxed)),
            ("s3_orphans_removed_total", "Unreferenced data files removed by the janitor.", self.orphans_removed.load(Relaxed)),
            ("s3_uploads_expired_total", "Incomplete multipart uploads aborted by the janitor.", self.uploads_expired.load(Relaxed)),
            ("s3_scrub_files_verified_total", "Data files verified by background scrubs.", self.scrub_files_verified.load(Relaxed)),
            ("s3_access_log_dropped_total", "Access log lines dropped because the writer fell behind.", self.access_log_dropped.load(Relaxed)),
        ];
        for (name, help, v) in counters {
            let _ = writeln!(x, "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}");
        }
        let gauges = [
            ("s3_inflight_requests", "Requests currently being processed.", self.inflight.load(Relaxed)),
            ("s3_open_connections", "Open client connections.", self.connections.load(Relaxed)),
            ("s3_scrub_last_completed_timestamp_seconds", "Unix time the last full scrub finished (0 = never).", self.scrub_last_completed.load(Relaxed) as i64),
        ];
        for (name, help, v) in gauges {
            let _ = writeln!(x, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
        }
        if let Some(free) = disk_free {
            let _ = writeln!(x, "# HELP s3_disk_free_bytes Free space on the data filesystem.\n# TYPE s3_disk_free_bytes gauge\ns3_disk_free_bytes {free}");
        }
        x
    }
}

/// Decrements a gauge when dropped.
pub struct GaugeGuard(&'static AtomicI64);

impl GaugeGuard {
    pub fn new(g: &'static AtomicI64) -> GaugeGuard {
        g.fetch_add(1, Relaxed);
        GaugeGuard(g)
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

static ACCESS_LOG: OnceLock<SyncSender<String>> = OnceLock::new();

/// Starts the access log writer (one JSON object per line on stdout). Lines
/// go through a bounded queue to a dedicated thread, so a slow consumer can
/// never stall request handling; overflow is counted and dropped.
pub fn start_access_log() {
    let (tx, rx) = sync_channel::<String>(16 * 1024);
    let _ = std::thread::Builder::new().name("access-log".into()).spawn(move || {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut out = std::io::BufWriter::new(stdout.lock());
        while let Ok(line) = rx.recv() {
            let _ = out.write_all(line.as_bytes());
            // Flush when the queue is drained, batching writes under load.
            let mut more = true;
            while more {
                match rx.try_recv() {
                    Ok(l) => {
                        let _ = out.write_all(l.as_bytes());
                    }
                    Err(_) => more = false,
                }
            }
            let _ = out.flush();
        }
    });
    let _ = ACCESS_LOG.set(tx);
}

pub fn access_log_enabled() -> bool {
    ACCESS_LOG.get().is_some()
}

pub fn access_log(line: String) {
    if let Some(tx) = ACCESS_LOG.get()
        && let Err(TrySendError::Full(_)) = tx.try_send(line)
    {
        get().access_log_dropped.fetch_add(1, Relaxed);
    }
}

/// Minimal JSON string escaping for log fields.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_and_escape() {
        let m = get();
        m.record("GetObject", 200, 0.003);
        m.record("GetObject", 404, 0.5);
        let r = m.render(Some(123));
        assert!(r.contains("s3_requests_total{op=\"GetObject\",status=\"2xx\"}"));
        assert!(r.contains("s3_request_duration_seconds_bucket{op=\"GetObject\",le=\"+Inf\"}"));
        assert!(r.contains("s3_disk_free_bytes 123"));
        assert_eq!(json_str("a\"b\\c\n"), "\"a\\\"b\\\\c\\u000a\"");
    }
}
