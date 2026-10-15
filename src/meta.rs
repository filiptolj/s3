//! Metadata store: an embedded B-tree (redb) with a dedicated writer thread that
//! batches concurrent mutations into a single transaction ("group commit"), so
//! many small PUTs share one fsync.

use crate::config::Durability;
use crate::error::{S3Error, S3Result};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::panic::AssertUnwindSafe;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

pub const BUCKETS: TableDefinition<&str, u64> = TableDefinition::new("buckets");
pub const UPLOADS: TableDefinition<&str, &[u8]> = TableDefinition::new("uploads");
pub const PARTS: TableDefinition<&str, &[u8]> = TableDefinition::new("parts");
/// Reference index of every data file in use (by an object or an upload part):
/// file id -> FileRef. Maintained in the same transaction as the references,
/// so a file on disk that is not in this table is garbage.
pub const FILES: TableDefinition<&str, &[u8]> = TableDefinition::new("files");
/// Small persistent server state (e.g. last scrub time).
pub const SYSTEM: TableDefinition<&str, u64> = TableDefinition::new("system");
/// Recently completed multipart uploads (upload id -> Completed), so a
/// retried CompleteMultipartUpload succeeds instead of failing.
pub const COMPLETED: TableDefinition<&str, &[u8]> = TableDefinition::new("completed");
/// CORS rules per bucket (bincode Vec<CorsRule>).
pub const CORS: TableDefinition<&str, &[u8]> = TableDefinition::new("cors");
/// Canned ACL of each bucket (absent = private).
pub const BUCKET_ACL: TableDefinition<&str, u8> = TableDefinition::new("bucket_acl");

pub fn objects_table_name(bucket: &str) -> String {
    format!("o/{bucket}")
}

pub fn data_table_name(bucket: &str) -> String {
    format!("d/{bucket}")
}

pub fn objects_table(name: &str) -> TableDefinition<'_, &'static str, &'static [u8]> {
    TableDefinition::new(name)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Segment {
    pub id: String,
    pub size: u64,
    /// CRC32C of the whole data file.
    pub crc: u32,
    /// Client-facing checksum of this part (multipart objects with a checksum algorithm).
    pub checksum: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct FileRef {
    pub size: u64,
    pub crc: u32,
}

/// Field order matters: `ListHead` decodes only the leading fields.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObjectMeta {
    pub size: u64,
    pub mtime: u64,
    pub etag: String,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
    /// Data files. Empty means the data is stored inline.
    pub segments: Vec<Segment>,
    /// Canned ACL (see `acl`).
    pub acl: u8,
    /// Flexible checksum supplied by the client (x-amz-checksum-*).
    pub checksum: Option<crate::checksum::Stored>,
    /// Inline data lives in a separate table ("d/<bucket>") so the metadata
    /// B-tree stays compact for HEAD and listing.
    #[serde(skip)]
    pub inline: Vec<u8>,
}

impl ObjectMeta {
    pub fn file_ids(&self) -> Vec<String> {
        self.segments.iter().map(|s| s.id.clone()).collect()
    }
}

#[derive(Deserialize)]
pub struct ListHead<'a> {
    pub size: u64,
    pub mtime: u64,
    pub etag: &'a str,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UploadMeta {
    pub bucket: String,
    pub key: String,
    pub initiated: u64,
    pub content_type: Option<String>,
    pub headers: Vec<(String, String)>,
    pub acl: u8,
    pub checksum: Option<(crate::checksum::Algo, crate::checksum::Kind)>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Completed {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub time: u64,
    pub checksum: Option<crate::checksum::Stored>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PartMeta {
    pub size: u64,
    pub mtime: u64,
    pub etag: String,
    pub id: String,
    pub crc: u32,
    pub checksum: Option<String>,
}

pub fn part_key(upload_id: &str, part: u32) -> String {
    format!("{upload_id}/{part:05}")
}

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("serialize")
}

pub fn decode<'a, T: Deserialize<'a>>(b: &'a [u8]) -> S3Result<T> {
    Ok(bincode::deserialize(b)?)
}

type Completion = Box<dyn FnOnce(Result<(), S3Error>) + Send>;
type Job = Box<dyn FnOnce(&WriteTransaction) -> Completion + Send>;

pub struct Meta {
    db: Arc<Database>,
    tx: mpsc::Sender<Job>,
}

impl Meta {
    pub fn open(path: &Path, cache_mb: usize, durability: Durability) -> S3Result<Meta> {
        let db = Database::builder()
            .set_cache_size(cache_mb.max(1) * 1024 * 1024)
            .create(path)
            .map_err(|e| S3Error::internal(format!("open metadata db: {e}")))?;
        let db = Arc::new(db);
        {
            let txn = db.begin_write()?;
            txn.open_table(BUCKETS)?;
            txn.open_table(UPLOADS)?;
            txn.open_table(PARTS)?;
            txn.open_table(FILES)?;
            txn.open_table(SYSTEM)?;
            txn.open_table(BUCKET_ACL)?;
            txn.open_table(COMPLETED)?;
            txn.open_table(CORS)?;
            txn.commit()?;
        }
        let (tx, rx) = mpsc::channel::<Job>();
        let wdb = db.clone();
        std::thread::Builder::new()
            .name("meta-writer".into())
            .spawn(move || writer_loop(wdb, rx, durability))
            .map_err(S3Error::internal)?;
        Ok(Meta { db, tx })
    }

    /// Runs `f` inside a write transaction shared with other concurrent writers.
    /// The result is delivered only after the transaction has committed.
    /// `f` must validate before mutating: an `Err` does not roll back its writes.
    pub async fn write<T, F>(&self, f: F) -> S3Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&WriteTransaction) -> S3Result<T> + Send + 'static,
    {
        let (otx, orx) = oneshot::channel();
        let job: Job = Box::new(move |txn| {
            let r = std::panic::catch_unwind(AssertUnwindSafe(|| f(txn)))
                .unwrap_or_else(|_| Err(S3Error::internal("metadata operation panicked")));
            Box::new(move |commit: Result<(), S3Error>| {
                let _ = otx.send(commit.and(r));
            })
        });
        self.tx.send(job).map_err(|_| S3Error::internal("metadata writer stopped"))?;
        orx.await.map_err(|_| S3Error::internal("metadata transaction failed"))?
    }

    /// Makes all previous commits durable (used at shutdown in relaxed mode).
    pub fn flush(&self) -> S3Result<()> {
        flush(&self.db)
    }

    pub fn read(&self) -> S3Result<redb::ReadTransaction> {
        Ok(self.db.begin_read()?)
    }

    pub fn bucket_exists(&self, bucket: &str) -> S3Result<bool> {
        let r = self.read()?;
        let t = r.open_table(BUCKETS)?;
        Ok(t.get(bucket)?.is_some())
    }

    pub fn bucket_cors(&self, bucket: &str) -> S3Result<Option<Vec<crate::cors::CorsRule>>> {
        let r = self.read()?;
        Ok(match r.open_table(CORS)?.get(bucket)? {
            Some(v) => Some(decode(v.value())?),
            None => None,
        })
    }

    /// The bucket's canned ACL, or None if the bucket does not exist.
    pub fn bucket_acl(&self, bucket: &str) -> S3Result<Option<u8>> {
        let r = self.read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Ok(None);
        }
        Ok(Some(r.open_table(BUCKET_ACL)?.get(bucket)?.map_or(crate::acl::PRIVATE, |v| v.value())))
    }

    pub fn list_buckets(&self) -> S3Result<Vec<(String, u64)>> {
        let r = self.read()?;
        let t = r.open_table(BUCKETS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            out.push((k.value().to_string(), v.value()));
        }
        Ok(out)
    }

    pub fn get_object(&self, bucket: &str, key: &str) -> S3Result<ObjectMeta> {
        self.get_object_with(bucket, key, false)
    }

    /// Loads object metadata and, if `with_data`, its inline data (same snapshot).
    pub fn get_object_with(&self, bucket: &str, key: &str, with_data: bool) -> S3Result<ObjectMeta> {
        let r = self.read()?;
        let name = objects_table_name(bucket);
        let t = match r.open_table(objects_table(&name)) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Err(S3Error::no_such_bucket()),
            Err(e) => return Err(e.into()),
        };
        let mut m: ObjectMeta = match t.get(key)? {
            Some(v) => decode(v.value())?,
            None => return Err(S3Error::no_such_key()),
        };
        if with_data && m.segments.is_empty() && m.size > 0 {
            let dname = data_table_name(bucket);
            let dt = r.open_table(objects_table(&dname))?;
            m.inline = dt.get(key)?.map(|v| v.value().to_vec()).unwrap_or_default();
        }
        Ok(m)
    }

    pub fn get_upload(&self, upload_id: &str) -> S3Result<UploadMeta> {
        let r = self.read()?;
        let t = r.open_table(UPLOADS)?;
        match t.get(upload_id)? {
            Some(v) => decode(v.value()),
            None => Err(S3Error::no_such_upload()),
        }
    }

    /// Parts with number > `marker`, at most `max` (+1 to detect truncation).
    pub fn list_parts(&self, upload_id: &str, marker: u32, max: usize) -> S3Result<Vec<(u32, PartMeta)>> {
        let r = self.read()?;
        let t = r.open_table(PARTS)?;
        let start = part_key(upload_id, marker + 1);
        let end = format!("{upload_id}0"); // '0' sorts right after '/'
        let mut out = Vec::new();
        for e in t.range(start.as_str()..end.as_str())? {
            let (k, v) = e?;
            let n: u32 = k.value().rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
            out.push((n, decode(v.value())?));
            if out.len() > max {
                break;
            }
        }
        Ok(out)
    }

    /// Upload ids initiated before `cutoff_ms`.
    pub fn expired_uploads(&self, cutoff_ms: u64) -> S3Result<Vec<String>> {
        let r = self.read()?;
        let t = r.open_table(UPLOADS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            if decode::<UploadMeta>(v.value())?.initiated < cutoff_ms {
                out.push(k.value().to_string());
            }
        }
        Ok(out)
    }

    pub fn file_ref(&self, id: &str) -> S3Result<Option<FileRef>> {
        let r = self.read()?;
        let t = r.open_table(FILES)?;
        Ok(match t.get(id)? {
            Some(v) => Some(decode(v.value())?),
            None => None,
        })
    }

    /// The subset of `ids` that is not in the file reference index.
    pub fn unreferenced(&self, ids: &[String]) -> S3Result<Vec<String>> {
        let r = self.read()?;
        let t = r.open_table(FILES)?;
        let mut out = Vec::new();
        for id in ids {
            if t.get(id.as_str())?.is_none() {
                out.push(id.clone());
            }
        }
        Ok(out)
    }

    /// A page of the file index after `after` (short-lived read transactions
    /// so a long scrub never pins old database pages).
    pub fn files_page(&self, after: &str, limit: usize) -> S3Result<Vec<(String, FileRef)>> {
        let r = self.read()?;
        let t = r.open_table(FILES)?;
        let mut out = Vec::with_capacity(limit);
        for e in t.range(after..)? {
            let (k, v) = e?;
            if k.value() == after {
                continue;
            }
            out.push((k.value().to_string(), decode(v.value())?));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn system_get(&self, key: &str) -> S3Result<Option<u64>> {
        let r = self.read()?;
        Ok(r.open_table(SYSTEM)?.get(key)?.map(|v| v.value()))
    }

    /// Maps data file ids to "bucket/key" (or "upload <id>") for reports.
    pub fn owners_of(&self, ids: &std::collections::HashSet<String>) -> S3Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let r = self.read()?;
        for (bucket, _) in self.list_buckets()? {
            let name = objects_table_name(&bucket);
            let t = r.open_table(objects_table(&name))?;
            for e in t.iter()? {
                let (k, v) = e?;
                let m: ObjectMeta = decode(v.value())?;
                for s in &m.segments {
                    if ids.contains(&s.id) {
                        out.push((s.id.clone(), format!("{bucket}/{}", k.value())));
                    }
                }
            }
        }
        let t = r.open_table(PARTS)?;
        for e in t.iter()? {
            let (k, v) = e?;
            let p: PartMeta = decode(v.value())?;
            if ids.contains(&p.id) {
                out.push((p.id, format!("multipart upload part {}", k.value())));
            }
        }
        Ok(out)
    }

    pub fn list_uploads(&self, bucket: &str, prefix: &str) -> S3Result<Vec<(String, UploadMeta)>> {
        let r = self.read()?;
        let t = r.open_table(UPLOADS)?;
        let mut out = Vec::new();
        for e in t.iter()? {
            let (k, v) = e?;
            let u: UploadMeta = decode(v.value())?;
            if u.bucket == bucket && u.key.starts_with(prefix) {
                out.push((k.value().to_string(), u));
            }
        }
        out.sort_by(|a, b| (&a.1.key, a.1.initiated).cmp(&(&b.1.key, b.1.initiated)));
        Ok(out)
    }
}

pub struct ListEntry {
    pub key: String,
    pub size: u64,
    pub mtime: u64,
    pub etag: String,
}

pub struct ListResult {
    pub objects: Vec<ListEntry>,
    pub prefixes: Vec<String>,
    pub truncated: bool,
    /// Last key or common prefix returned (marker for the next page).
    pub last: Option<String>,
}

/// Lexicographic listing with prefix/delimiter grouping. Common prefixes are
/// skipped with a B-tree seek instead of scanning every key below them.
pub fn list_objects(
    meta: &Meta,
    bucket: &str,
    prefix: &str,
    delimiter: &str,
    marker: &str,
    max_keys: usize,
) -> S3Result<ListResult> {
    let r = meta.read()?;
    let name = objects_table_name(bucket);
    let t = match r.open_table(objects_table(&name)) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Err(S3Error::no_such_bucket()),
        Err(e) => return Err(e.into()),
    };
    let mut res = ListResult { objects: Vec::new(), prefixes: Vec::new(), truncated: false, last: None };
    if max_keys == 0 {
        return Ok(res);
    }

    // The common prefix that the marker itself falls into (keys under it were already returned).
    let mut last_cp: Option<String> = None;
    if !delimiter.is_empty() && marker.starts_with(prefix)
        && let Some(i) = marker[prefix.len()..].find(delimiter) {
            last_cp = Some(marker[..prefix.len() + i + delimiter.len()].to_string());
        }

    let mut start: String = if marker > prefix { marker.to_string() } else { prefix.to_string() };
    let mut skip_equal = marker > prefix;
    if let Some(cp) = &last_cp {
        start = format!("{cp}\u{10FFFF}");
        skip_equal = false;
    }
    let mut count = 0usize;
    'outer: loop {
        let mut reseek: Option<String> = None;
        for e in t.range(start.as_str()..)? {
            let (k, v) = e?;
            let key = k.value();
            if !key.starts_with(prefix) {
                break 'outer;
            }
            if skip_equal && key == start {
                continue;
            }
            if let Some(cp) = &last_cp
                && key.starts_with(cp.as_str()) {
                    continue;
                }
            if !delimiter.is_empty()
                && let Some(i) = key[prefix.len()..].find(delimiter) {
                    let cp = &key[..prefix.len() + i + delimiter.len()];
                    if count == max_keys {
                        res.truncated = true;
                        break 'outer;
                    }
                    res.prefixes.push(cp.to_string());
                    res.last = Some(cp.to_string());
                    last_cp = Some(cp.to_string());
                    count += 1;
                    reseek = Some(format!("{cp}\u{10FFFF}"));
                    break;
                }
            if count == max_keys {
                res.truncated = true;
                break 'outer;
            }
            let h: ListHead = decode(v.value())?;
            res.objects.push(ListEntry { key: key.to_string(), size: h.size, mtime: h.mtime, etag: h.etag.to_string() });
            res.last = Some(key.to_string());
            count += 1;
        }
        match reseek {
            Some(s) => {
                start = s;
                skip_equal = false;
            }
            None => break,
        }
    }
    Ok(res)
}

pub fn bucket_is_empty(txn: &WriteTransaction, bucket: &str) -> S3Result<bool> {
    let name = objects_table_name(bucket);
    let t = txn.open_table(objects_table(&name))?;
    Ok(t.is_empty()?)
}

fn writer_loop(db: Arc<Database>, rx: mpsc::Receiver<Job>, durability: Durability) {
    const MAX_BATCH: usize = 512;
    let relaxed = durability == Durability::Relaxed;
    let mut dirty = false;
    let mut last_flush = Instant::now();
    loop {
        let first = if relaxed && dirty {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(j) => Some(j),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match rx.recv() {
                Ok(j) => Some(j),
                Err(_) => break,
            }
        };
        let Some(first) = first else {
            // Idle in relaxed mode: make previous commits durable.
            if flush(&db).is_ok() {
                dirty = false;
                last_flush = Instant::now();
            }
            continue;
        };
        let mut txn = match db.begin_write() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("metadata: begin_write failed: {e}");
                drop(first); // dropping the job reports an error to the caller
                continue;
            }
        };
        if relaxed {
            if last_flush.elapsed() >= Duration::from_secs(1) {
                last_flush = Instant::now();
                dirty = false;
            } else {
                let _ = txn.set_durability(redb::Durability::None);
                dirty = true;
            }
        }
        let mut done: Vec<Completion> = Vec::with_capacity(16);
        done.push(first(&txn));
        while done.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(j) => done.push(j(&txn)),
                Err(_) => break,
            }
        }
        let res = txn.commit().map_err(S3Error::from);
        if let Err(e) = &res {
            eprintln!("metadata: commit failed: {}", e.message);
        }
        for c in done {
            c(res.clone());
        }
    }
    if dirty {
        let _ = flush(&db);
    }
}

fn flush(db: &Database) -> S3Result<()> {
    let txn = db.begin_write()?;
    txn.commit()?;
    Ok(())
}

pub fn parts_in_txn(txn: &WriteTransaction, upload_id: &str) -> S3Result<std::collections::BTreeMap<u32, PartMeta>> {
    let t = txn.open_table(PARTS)?;
    let start = format!("{upload_id}/");
    let end = format!("{upload_id}0");
    let mut out = std::collections::BTreeMap::new();
    for e in t.range(start.as_str()..end.as_str())? {
        let (k, v) = e?;
        let n: u32 = k.value().rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
        out.insert(n, decode::<PartMeta>(v.value())?);
    }
    Ok(out)
}

/// Updates the file reference index: drops `remove`, then adds `add`.
pub fn index_files(txn: &WriteTransaction, add: &[Segment], remove: &[String]) -> S3Result<()> {
    if add.is_empty() && remove.is_empty() {
        return Ok(());
    }
    let mut t = txn.open_table(FILES)?;
    for id in remove {
        t.remove(id.as_str())?;
    }
    for s in add {
        t.insert(s.id.as_str(), encode(&FileRef { size: s.size, crc: s.crc }).as_slice())?;
    }
    Ok(())
}

/// Removes all part entries of an upload, returning (part number, meta).
pub fn take_parts(txn: &WriteTransaction, upload_id: &str) -> S3Result<Vec<(u32, PartMeta)>> {
    let mut t = txn.open_table(PARTS)?;
    let start = format!("{upload_id}/");
    let end = format!("{upload_id}0");
    let mut keys = Vec::new();
    let mut out = Vec::new();
    for e in t.range(start.as_str()..end.as_str())? {
        let (k, v) = e?;
        let n: u32 = k.value().rsplit('/').next().and_then(|s| s.parse().ok()).unwrap_or(0);
        keys.push(k.value().to_string());
        out.push((n, decode::<PartMeta>(v.value())?));
    }
    for k in keys {
        t.remove(k.as_str())?;
    }
    Ok(out)
}

/// Deletes an upload and its parts; returns the part files to remove.
/// With `expect`, the upload must belong to that (bucket, key).
pub fn abort_upload_txn(txn: &WriteTransaction, upload_id: &str, expect: Option<(&str, &str)>) -> S3Result<Vec<String>> {
    let mut ut = txn.open_table(UPLOADS)?;
    let up: UploadMeta = match ut.get(upload_id)? {
        Some(v) => decode(v.value())?,
        None => return Err(S3Error::no_such_upload()),
    };
    if let Some((b, k)) = expect
        && (up.bucket != b || up.key != k)
    {
        return Err(S3Error::no_such_upload());
    }
    ut.remove(upload_id)?;
    drop(ut);
    let ids: Vec<String> = take_parts(txn, upload_id)?.into_iter().map(|(_, p)| p.id).collect();
    index_files(txn, &[], &ids)?;
    Ok(ids)
}

pub fn system_set(txn: &WriteTransaction, key: &str, value: u64) -> S3Result<()> {
    txn.open_table(SYSTEM)?.insert(key, value)?;
    Ok(())
}

/// Drops completion records older than `cutoff_ms`; returns how many.
pub fn purge_completed_txn(txn: &WriteTransaction, cutoff_ms: u64) -> S3Result<usize> {
    let mut t = txn.open_table(COMPLETED)?;
    let mut old = Vec::new();
    for e in t.iter()? {
        let (k, v) = e?;
        if decode::<Completed>(v.value())?.time < cutoff_ms {
            old.push(k.value().to_string());
        }
    }
    for k in &old {
        t.remove(k.as_str())?;
    }
    Ok(old.len())
}
