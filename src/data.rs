//! Object data files and the streaming response body.
//!
//! Every write goes to a fresh, immutable file (random id), so overwrites never
//! disturb in-flight readers and copies can be hard links.

use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::fs::File;
use std::future::Future;
use std::io::{self, IoSlice, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{ready, Context, Poll};
use std::time::{Duration, SystemTime};
use tokio::task::{spawn_blocking, JoinHandle};

use crate::checksum::{self, Algo};
use crate::meta::Segment;

/// Number of checksum mismatches detected on read or scrub since start.
pub static CORRUPTIONS_DETECTED: AtomicU64 = AtomicU64::new(0);

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub struct DataStore {
    pub min_free: u64,
    objects: PathBuf,
    tmp: PathBuf,
    pub fsync: bool,
    pub read_chunk: usize,
    pub write_chunk: usize,
}

impl DataStore {
    pub fn open(root: &Path, fsync: bool, read_chunk: usize, write_chunk: usize) -> io::Result<DataStore> {
        let objects = root.join("objects");
        let tmp = root.join("tmp");
        std::fs::create_dir_all(&objects)?;
        // Leftovers of interrupted uploads.
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        Ok(DataStore { min_free: 0, objects, tmp, fsync, read_chunk, write_chunk })
    }

    /// Free bytes available to this process on the data filesystem.
    pub fn free_bytes(&self) -> Option<u64> {
        let path = std::ffi::CString::new(self.objects.as_os_str().as_encoded_bytes()).ok()?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(path.as_ptr(), &mut st) } != 0 {
            return None;
        }
        Some(st.f_bavail as u64 * st.f_frsize as u64)
    }

    /// Fails if writing `need` more bytes would cut into the free-space reserve.
    pub fn check_space(&self, need: u64) -> crate::error::S3Result<()> {
        match self.free_bytes() {
            Some(free) if free < self.min_free.saturating_add(need) => Err(crate::error::S3Error::insufficient_storage()),
            _ => Ok(()),
        }
    }

    pub fn path(&self, id: &str) -> PathBuf {
        let mut p = self.objects.join(&id[0..2]);
        p.push(&id[2..4]);
        p.push(id);
        p
    }

    fn tmp_path(&self, id: &str) -> PathBuf {
        self.tmp.join(id)
    }

    /// Creates the fan-out directories for `dst` (and makes them durable in fsync mode).
    fn create_parent(&self, dst: &Path) -> io::Result<()> {
        let parent = dst.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        if self.fsync {
            sync_dir(parent.parent().unwrap())?;
            sync_dir(&self.objects)?;
        }
        Ok(())
    }

    /// Moves a finished temp file into place, creating fan-out dirs lazily.
    fn install(&self, tmp: &Path, id: &str) -> io::Result<()> {
        let dst = self.path(id);
        match std::fs::rename(tmp, &dst) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.create_parent(&dst)?;
                std::fs::rename(tmp, &dst)?;
            }
            r => r?,
        }
        if self.fsync {
            sync_dir(dst.parent().unwrap())?;
        }
        Ok(())
    }

    /// Hard-links an existing data file under a new id (O(1) copy).
    pub fn link(&self, src_id: &str, new_id: &str) -> io::Result<()> {
        let src = self.path(src_id);
        let dst = self.path(new_id);
        match std::fs::hard_link(&src, &dst) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && src.exists() => {
                self.create_parent(&dst)?;
                std::fs::hard_link(&src, &dst)?;
            }
            r => r?,
        }
        // A fresh mtime keeps the orphan collector away until the metadata
        // referencing the new link is committed.
        File::open(&dst)?.set_modified(SystemTime::now())?;
        if self.fsync {
            sync_dir(dst.parent().unwrap())?;
        }
        Ok(())
    }

    /// Data file ids in fan-out directory `n` (0..65536).
    pub fn files_in(&self, n: u32) -> Vec<String> {
        let dir = self.objects.join(format!("{:02x}", n >> 8)).join(format!("{:02x}", n & 0xff));
        let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
        rd.filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.len() == 32 && n.bytes().all(|c| c.is_ascii_hexdigit()))
            .collect()
    }

    pub fn modified_before(&self, id: &str, cutoff: SystemTime) -> bool {
        std::fs::metadata(self.path(id)).and_then(|m| m.modified()).is_ok_and(|t| t < cutoff)
    }

    pub fn remove_now(&self, id: &str) -> bool {
        std::fs::remove_file(self.path(id)).is_ok()
    }

    /// Size of a data file, if it exists.
    pub fn file_size(&self, id: &str) -> Option<u64> {
        std::fs::metadata(self.path(id)).ok().map(|m| m.len())
    }

    /// Removes temp files untouched for `max_age` (abandoned uploads after a crash).
    pub fn clean_tmp(&self, max_age: Duration) -> usize {
        let cutoff = SystemTime::now() - max_age;
        let Ok(rd) = std::fs::read_dir(&self.tmp) else { return 0 };
        let mut n = 0;
        for e in rd.flatten() {
            if e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < cutoff) && std::fs::remove_file(e.path()).is_ok() {
                n += 1;
            }
        }
        n
    }

    /// Re-reads a data file and checks its size and CRC32C. `throttle` is
    /// called after every chunk with the number of bytes read; returning
    /// false cancels the check.
    pub fn verify_file(&self, id: &str, size: u64, crc: u32, throttle: &mut dyn FnMut(usize) -> bool) -> Result<(), String> {
        let mut f = File::open(self.path(id)).map_err(|e| format!("cannot open: {e}"))?;
        let mut buf = vec![0u8; 1 << 20];
        let (mut n, mut c) = (0u64, 0u32);
        loop {
            let k = f.read(&mut buf).map_err(|e| format!("read error: {e}"))?;
            if k == 0 {
                break;
            }
            c = crc32c::crc32c_append(c, &buf[..k]);
            n += k as u64;
            if !throttle(k) {
                return Err("cancelled".into());
            }
        }
        if n != size {
            return Err(format!("size mismatch: expected {size}, found {n}"));
        }
        if c != crc {
            return Err(format!("checksum mismatch: expected {crc:08x}, computed {c:08x}"));
        }
        Ok(())
    }

    /// Fire-and-forget removal of data files.
    pub fn remove_later(self: &Arc<Self>, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let s = self.clone();
        spawn_blocking(move || {
            for id in ids {
                let _ = std::fs::remove_file(s.path(&id));
            }
        });
    }
}

/// Incremental hashes computed over the (decoded) payload.
pub struct Hashers {
    pub md5: Option<Md5>,
    /// For x-amz-content-sha256 payload verification.
    pub sha256: Option<Sha256>,
    /// Flexible checksum (x-amz-checksum-*) requested by the client.
    pub checksum: Option<(Algo, checksum::Hasher)>,
    pub xxh3: Option<Box<xxhash_rust::xxh3::Xxh3>>,
    /// CRC32C stored with data files for bitrot detection.
    pub data_crc: Option<u32>,
}

#[derive(Default, Debug)]
pub struct Digests {
    pub md5: Option<[u8; 16]>,
    pub sha256: Option<[u8; 32]>,
    /// Flexible checksum, base64 encoded.
    pub checksum: Option<(Algo, String)>,
    pub xxh3: Option<u128>,
    pub data_crc: Option<u32>,
}

impl Digests {
    /// MD5-based ETag, or the xxh3 one in fast-etag mode. Objects get a "-1"
    /// suffix in fast mode so tools don't mistake it for an MD5.
    pub fn etag(&self, part: bool) -> String {
        match (self.md5, self.xxh3) {
            (Some(m), _) => hex::encode(m),
            (None, Some(x)) if part => format!("{x:032x}"),
            (None, Some(x)) => format!("{x:032x}-1"),
            (None, None) => String::new(),
        }
    }
}

impl Hashers {
    pub fn update(&mut self, b: &[u8]) {
        if let Some(h) = &mut self.md5 {
            h.update(b);
        }
        if let Some(h) = &mut self.sha256 {
            h.update(b);
        }
        if let Some((_, h)) = &mut self.checksum {
            h.update(b);
        }
        if let Some(h) = &mut self.xxh3 {
            h.update(b);
        }
        if let Some(c) = &mut self.data_crc {
            *c = crc32c::crc32c_append(*c, b);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.md5.is_none() && self.sha256.is_none() && self.checksum.is_none() && self.xxh3.is_none() && self.data_crc.is_none()
    }

    pub fn finish(self) -> Digests {
        Digests {
            md5: self.md5.map(|h| h.finalize().into()),
            sha256: self.sha256.map(|h| h.finalize().into()),
            checksum: self.checksum.map(|(a, h)| (a, checksum::encode(&h.finish()))),
            xxh3: self.xxh3.map(|h| h.digest128()),
            data_crc: self.data_crc,
        }
    }
}

/// Streams a payload into a new data file. Three things overlap: receiving
/// the next batch from the network, hashing the current batch, and writing
/// the current batch to disk (hashing and writing run on separate blocking
/// threads over the same zero-copy buffers).
pub struct FileWriter {
    store: Arc<DataStore>,
    pub id: String,
    tmp: PathBuf,
    file: Option<File>,
    hashers: Option<Hashers>,
    write_job: Option<JoinHandle<io::Result<File>>>,
    hash_job: Option<JoinHandle<Hashers>>,
    batch: Vec<Bytes>,
    batch_len: usize,
    pub size: u64,
    done: bool,
}

impl FileWriter {
    pub async fn create(store: Arc<DataStore>, hashers: Hashers) -> io::Result<FileWriter> {
        let id = crate::util::new_id();
        let tmp = store.tmp_path(&id);
        let t = tmp.clone();
        let file = spawn_blocking(move || File::create(t)).await??;
        Ok(FileWriter {
            store,
            id,
            tmp,
            file: Some(file),
            hashers: Some(hashers),
            write_job: None,
            hash_job: None,
            batch: Vec::with_capacity(64),
            batch_len: 0,
            size: 0,
            done: false,
        })
    }

    pub async fn push(&mut self, b: Bytes) -> io::Result<()> {
        if b.is_empty() {
            return Ok(());
        }
        self.size += b.len() as u64;
        self.batch_len += b.len();
        self.batch.push(b);
        if self.batch_len >= self.store.write_chunk || self.batch.len() >= 512 {
            self.flush_batch().await?;
        }
        Ok(())
    }

    async fn wait_idle(&mut self) -> io::Result<()> {
        if let Some(job) = self.write_job.take() {
            self.file = Some(job.await??);
        }
        if let Some(job) = self.hash_job.take() {
            self.hashers = Some(job.await?);
        }
        Ok(())
    }

    async fn flush_batch(&mut self) -> io::Result<()> {
        self.wait_idle().await?;
        let bufs = std::mem::take(&mut self.batch);
        self.batch_len = 0;
        let mut hashers = self.hashers.take().expect("writer state");
        if hashers.is_empty() {
            self.hashers = Some(hashers);
        } else {
            let hb = bufs.clone();
            self.hash_job = Some(spawn_blocking(move || {
                for b in &hb {
                    hashers.update(b);
                }
                hashers
            }));
        }
        let mut file = self.file.take().expect("writer state");
        self.write_job = Some(spawn_blocking(move || {
            write_all_vectored(&mut file, &bufs)?;
            Ok(file)
        }));
        Ok(())
    }

    /// Flushes, optionally fsyncs and moves the file into place.
    pub async fn finish(mut self) -> io::Result<(String, u64, Digests)> {
        if !self.batch.is_empty() {
            self.flush_batch().await?;
        }
        self.wait_idle().await?;
        let file = self.file.take().expect("writer state");
        let hashers = self.hashers.take().expect("writer state");
        let store = self.store.clone();
        let (tmp, id) = (self.tmp.clone(), self.id.clone());
        let fsync = store.fsync;
        spawn_blocking(move || -> io::Result<()> {
            if fsync {
                file.sync_data()?;
            }
            drop(file);
            store.install(&tmp, &id)
        })
        .await??;
        self.done = true;
        Ok((self.id.clone(), self.size, hashers.finish()))
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

fn write_all_vectored(file: &mut File, bufs: &[Bytes]) -> io::Result<()> {
    let mut idx = 0;
    let mut off = 0;
    while idx < bufs.len() {
        let slices: Vec<IoSlice> = std::iter::once(IoSlice::new(&bufs[idx][off..]))
            .chain(bufs[idx + 1..].iter().take(1023).map(|b| IoSlice::new(b)))
            .collect();
        let mut n = file.write_vectored(&slices)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        while idx < bufs.len() && n > 0 {
            let left = bufs[idx].len() - off;
            if n >= left {
                n -= left;
                idx += 1;
                off = 0;
            } else {
                off += n;
                n = 0;
            }
        }
    }
    Ok(())
}

/// Copies `len` bytes starting at `offset` of the given segments into a new
/// data file, returning (id, md5, crc32c, flexible checksum if `algo`).
pub fn copy_range_blocking(
    store: &DataStore,
    segments: &[Segment],
    inline: &[u8],
    offset: u64,
    len: u64,
    algo: Option<Algo>,
) -> io::Result<(String, [u8; 16], u32, Option<String>)> {
    let id = crate::util::new_id();
    let tmp = store.tmp_path(&id);
    let mut out = File::create(&tmp)?;
    let mut md5 = Md5::new();
    let mut crc = 0u32;
    let mut flex = algo.map(checksum::Hasher::new);
    let res = (|| -> io::Result<()> {
        if segments.is_empty() {
            let d = inline
                .get(offset as usize..(offset + len) as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "inline data shorter than object size"))?;
            md5.update(d);
            crc = crc32c::crc32c_append(crc, d);
            if let Some(h) = &mut flex {
                h.update(d);
            }
            out.write_all(d)?;
        } else {
            let mut buf = vec![0u8; 1 << 20];
            for p in plan_range(segments, offset, len) {
                let mut f = File::open(store.path(&p.id))?;
                f.seek(SeekFrom::Start(p.offset))?;
                let mut left = p.len;
                while left > 0 {
                    let k = (left as usize).min(buf.len());
                    f.read_exact(&mut buf[..k])?;
                    md5.update(&buf[..k]);
                    crc = crc32c::crc32c_append(crc, &buf[..k]);
                    if let Some(h) = &mut flex {
                        h.update(&buf[..k]);
                    }
                    out.write_all(&buf[..k])?;
                    left -= k as u64;
                }
            }
        }
        if store.fsync {
            out.sync_data()?;
        }
        Ok(())
    })();
    drop(out);
    if let Err(e) = res.and_then(|_| store.install(&tmp, &id)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok((id, md5.finalize().into(), crc, flex.map(|h| checksum::encode(&h.finish()))))
}

#[derive(Debug, PartialEq)]
pub struct PlanPiece {
    pub id: String,
    pub offset: u64,
    pub len: u64,
    /// Expected CRC32C when the piece covers the whole file (verified while streaming).
    pub crc: Option<u32>,
}

/// Maps a byte range of a segmented object to per-file pieces.
pub fn plan_range(segments: &[Segment], offset: u64, len: u64) -> Vec<PlanPiece> {
    let mut out = Vec::new();
    let (mut pos, end) = (0u64, offset + len);
    for seg in segments {
        let (s, e) = (pos, pos + seg.size);
        pos = e;
        if e <= offset || seg.size == 0 {
            continue;
        }
        if s >= end {
            break;
        }
        let from = offset.max(s);
        let to = end.min(e);
        let whole = from == s && to == e;
        out.push(PlanPiece { id: seg.id.clone(), offset: from - s, len: to - from, crc: whole.then_some(seg.crc) });
    }
    out
}

struct Piece {
    id: String,
    file: Option<Arc<File>>,
    offset: u64,
    left: u64,
    seeked: bool,
    expect_crc: Option<u32>,
    crc: u32,
}

impl Piece {
    /// Called after a chunk is read; reports bitrot once the piece is complete.
    fn check(&self) -> io::Result<()> {
        match self.expect_crc {
            Some(exp) if self.left == 0 && self.crc != exp => {
                CORRUPTIONS_DETECTED.fetch_add(1, Ordering::Relaxed);
                eprintln!("CORRUPTION: data file {} failed checksum verification on read", self.id);
                Err(io::Error::new(io::ErrorKind::InvalidData, format!("data file {} is corrupted", self.id)))
            }
            _ => Ok(()),
        }
    }
}

type ReadJob = JoinHandle<io::Result<(Arc<File>, Bytes, u32)>>;

/// Streams file pieces with one read always in flight ahead of the socket.
pub struct FileStream {
    store: Arc<DataStore>,
    pieces: Vec<Piece>,
    idx: usize,
    remaining: u64,
    ready: Option<Bytes>,
    inflight: Option<ReadJob>,
}

const EAGER_OPEN: usize = 256;

impl FileStream {
    /// Opens the files up front (so a concurrent overwrite/delete cannot break
    /// the download) and reads the first chunk.
    pub async fn open(store: Arc<DataStore>, plan: Vec<PlanPiece>) -> io::Result<FileStream> {
        let total: u64 = plan.iter().map(|p| p.len).sum();
        let mut pieces: Vec<Piece> = plan
            .into_iter()
            .map(|p| Piece { id: p.id, file: None, offset: p.offset, left: p.len, seeked: false, expect_crc: p.crc, crc: 0 })
            .collect();
        let chunk = store.read_chunk;
        let st = store.clone();
        let ids: Vec<String> = pieces.iter().take(EAGER_OPEN).map(|p| p.id.clone()).collect();
        let (first_off, first_len) = pieces.first().map(|p| (p.offset, p.left)).unwrap_or((0, 0));
        let (files, first) = spawn_blocking(move || -> io::Result<(Vec<Arc<File>>, Option<Bytes>)> {
            let files = ids
                .iter()
                .map(|id| File::open(st.path(id)).map(Arc::new))
                .collect::<io::Result<Vec<_>>>()?;
            let first = match files.first() {
                Some(f) => Some(read_chunk(f, Some(first_off), (first_len as usize).min(chunk))?),
                None => None,
            };
            Ok((files, first))
        })
        .await??;
        for (p, f) in pieces.iter_mut().zip(files) {
            p.file = Some(f);
        }
        let mut s = FileStream { store, pieces, idx: 0, remaining: total, ready: None, inflight: None };
        if let Some(b) = first {
            let p = &mut s.pieces[0];
            p.seeked = true;
            p.offset += b.len() as u64;
            p.left -= b.len() as u64;
            if p.expect_crc.is_some() {
                p.crc = crc32c::crc32c(&b);
            }
            p.check()?;
            s.ready = Some(b);
        }
        Ok(s)
    }

    fn start_next(&mut self) -> bool {
        while self.idx < self.pieces.len() && self.pieces[self.idx].left == 0 {
            self.idx += 1;
        }
        let Some(p) = self.pieces.get_mut(self.idx) else { return false };
        let n = (p.left as usize).min(self.store.read_chunk);
        let seek = if p.seeked { None } else { Some(p.offset) };
        p.seeked = true;
        p.offset += n as u64;
        p.left -= n as u64;
        let file = p.file.clone();
        let path = self.store.path(&p.id);
        let verify = p.expect_crc.is_some();
        let crc = p.crc;
        self.inflight = Some(spawn_blocking(move || {
            let f = match file {
                Some(f) => f,
                None => Arc::new(File::open(path)?),
            };
            let b = read_chunk(&f, seek, n)?;
            let crc = if verify { crc32c::crc32c_append(crc, &b) } else { crc };
            Ok((f, b, crc))
        }));
        true
    }
}

fn read_chunk(f: &File, seek: Option<u64>, n: usize) -> io::Result<Bytes> {
    let mut r = f;
    if let Some(off) = seek.filter(|o| *o > 0) {
        r.seek(SeekFrom::Start(off))?;
    }
    // read_to_end fills spare capacity without zeroing it first.
    let mut v = Vec::with_capacity(n);
    r.take(n as u64).read_to_end(&mut v)?;
    if v.len() != n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "data file truncated"));
    }
    Ok(Bytes::from(v))
}

pub enum Body {
    Empty,
    Full(Option<Bytes>),
    File(Box<FileStream>),
}

impl Body {
    pub fn full(b: impl Into<Bytes>) -> Body {
        Body::Full(Some(b.into()))
    }
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Body::Empty => Poll::Ready(None),
            Body::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Body::File(s) => {
                let s = &mut **s;
                if s.ready.is_none() {
                    let Some(job) = s.inflight.as_mut() else { return Poll::Ready(None) };
                    let res = ready!(Pin::new(job).poll(cx));
                    s.inflight = None;
                    match res {
                        Ok(Ok((f, b, crc))) => {
                            if let Some(p) = s.pieces.get_mut(s.idx) {
                                p.file.get_or_insert(f);
                                p.crc = crc;
                                if let Err(e) = p.check() {
                                    return Poll::Ready(Some(Err(e)));
                                }
                            }
                            s.ready = Some(b);
                        }
                        Ok(Err(e)) => return Poll::Ready(Some(Err(e))),
                        Err(e) => return Poll::Ready(Some(Err(io::Error::other(e)))),
                    }
                }
                let b = s.ready.take().unwrap();
                s.remaining -= b.len() as u64;
                // Prefetch the next chunk while this one is written to the socket.
                s.start_next();
                Poll::Ready(Some(Ok(Frame::data(b))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Body::Empty => true,
            Body::Full(b) => b.is_none(),
            Body::File(s) => s.remaining == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Body::Empty => SizeHint::with_exact(0),
            Body::Full(b) => SizeHint::with_exact(b.as_ref().map_or(0, |b| b.len() as u64)),
            Body::File(s) => SizeHint::with_exact(s.remaining),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan() {
        let seg = |id: &str, size, crc| Segment { id: id.into(), size, crc, checksum: None };
        let p = |id: &str, offset, len, crc| PlanPiece { id: id.into(), offset, len, crc };
        let segs = vec![seg("a", 10, 1), seg("b", 10, 2), seg("c", 5, 3)];
        assert_eq!(plan_range(&segs, 0, 25), vec![p("a", 0, 10, Some(1)), p("b", 0, 10, Some(2)), p("c", 0, 5, Some(3))]);
        assert_eq!(plan_range(&segs, 5, 10), vec![p("a", 5, 5, None), p("b", 0, 5, None)]);
        assert_eq!(plan_range(&segs, 20, 5), vec![p("c", 0, 5, Some(3))]);
    }
}
