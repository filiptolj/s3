//! Randomized robustness and model-based tests for everything that parses
//! untrusted input. Deterministic (seeded) so failures are reproducible;
//! set FUZZ_ITERS to run longer.

use crate::chunked::ChunkedDecoder;
use bytes::Bytes;
use std::collections::VecDeque;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.below(max + 1);
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// Random string biased towards characters that matter to the parsers.
    fn text(&mut self, max: usize, alphabet: &[&str]) -> String {
        let n = self.below(max + 1);
        (0..n).map(|_| alphabet[self.below(alphabet.len())]).collect()
    }
}

fn iters(default: usize) -> usize {
    std::env::var("FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn chunked_encode(data: &[u8], rng: &mut Rng, trailer: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let n = (1 + rng.below(300)).min(data.len() - pos);
        out.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        out.extend_from_slice(&data[pos..pos + n]);
        out.extend_from_slice(b"\r\n");
        pos += n;
    }
    out.extend_from_slice(b"0\r\n");
    if trailer {
        out.extend_from_slice(b"x-amz-checksum-crc32:AAAAAA==\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn feed_split(d: &mut ChunkedDecoder, raw: &[u8], rng: &mut Rng, out: &mut VecDeque<Bytes>) -> bool {
    let mut pos = 0;
    while pos < raw.len() {
        let n = (1 + rng.below(64)).min(raw.len() - pos);
        if d.feed(Bytes::copy_from_slice(&raw[pos..pos + n]), out).is_err() {
            return false;
        }
        pos += n;
    }
    true
}

#[test]
fn chunked_roundtrip_random_splits() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for _ in 0..iters(2000) {
        let data = rng.bytes(2000);
        let trailer = rng.below(2) == 0;
        let raw = chunked_encode(&data, &mut rng, trailer);
        let mut d = ChunkedDecoder::new(None);
        let mut q = VecDeque::new();
        assert!(feed_split(&mut d, &raw, &mut rng, &mut q));
        assert!(d.is_done());
        let got: Vec<u8> = q.iter().flat_map(|b| b.iter().copied()).collect();
        assert_eq!(got, data);
    }
}

#[test]
fn chunked_garbage_never_panics() {
    let mut rng = Rng(42);
    for i in 0..iters(5000) {
        let raw = if i % 2 == 0 {
            rng.bytes(500)
        } else {
            // Mutate a valid stream.
            let data = rng.bytes(300);
            let mut raw = chunked_encode(&data, &mut rng, true);
            for _ in 0..1 + rng.below(4) {
                let p = rng.below(raw.len());
                raw[p] = rng.next() as u8;
            }
            raw
        };
        let mut d = ChunkedDecoder::new(None);
        let mut q = VecDeque::new();
        let _ = feed_split(&mut d, &raw, &mut rng, &mut q);
        let decoded: usize = q.iter().map(|b| b.len()).sum();
        assert!(decoded <= raw.len());
    }
}

#[test]
fn xml_never_panics() {
    let alphabet = ["<", ">", "/", "a", "Key", "Part", " ", "\"", "'", "=", "&", "amp;", "#x41;", "#99999999;", "<![CDATA[", "]]>", "<!--", "-->", "<?", "?>", "é", "\n"];
    let mut rng = Rng(7);
    for _ in 0..iters(20000) {
        let s = rng.text(80, &alphabet);
        let _ = crate::xml::parse(&s);
    }
    // Deep nesting must be rejected, not overflow the stack.
    let deep = "<a>".repeat(100_000);
    assert!(crate::xml::parse(&deep).is_none());
}

#[test]
fn range_parser_invariants() {
    let alphabet = ["bytes=", "-", "0", "1", "9", "5", ",", " ", "18446744073709551615", "x"];
    let mut rng = Rng(99);
    for _ in 0..iters(20000) {
        let h = rng.text(8, &alphabet);
        let size = [0u64, 1, 10, 1000, u64::MAX][rng.below(5)];
        if let Some(Ok((start, len))) = crate::handlers::parse_range(&h, size) {
            assert!(len > 0, "{h} {size}");
            assert!(start.checked_add(len).is_some_and(|e| e <= size), "{h} {size} -> {start}+{len}");
        }
    }
}

#[test]
fn query_and_date_parsers_never_panic() {
    let alphabet = ["%", "%2", "%zz", "%e2%82", "%ac", "+", "&", "=", "a", "é", "\u{10FFFF}"];
    let mut rng = Rng(1234);
    for _ in 0..iters(20000) {
        let s = rng.text(30, &alphabet);
        let _ = crate::handlers::parse_query(&s);
        let _ = crate::util::percent_decode(&s);
        let _ = crate::util::parse_amz_date(&s);
        let _ = crate::util::parse_http_date(&s);
        let _ = crate::util::xml_escape(&s);
    }
}

#[test]
fn auth_never_panics_on_hostile_headers() {
    let auth = crate::auth::Auth::new(vec![("access".into(), "secret-secret".into())], false, true);
    let alphabet = [
        "AWS4-HMAC-SHA256 ", "AWS ", "Credential=", "access/", "20240101/", "us-east-1/s3/aws4_request", ",", " ",
        "SignedHeaders=", "host;x-amz-date", ";", "Signature=", "abc", ":", "=", "/",
    ];
    let mut rng = Rng(555);
    for _ in 0..iters(10000) {
        let authz = rng.text(12, &alphabet);
        let date = rng.text(3, &["20240101T000000Z", "2024", "T", "Z", "x"]);
        let uri = format!("/b/{}?{}", rng.text(4, &["k", "%20", "%", "/"]), rng.text(4, &["X-Amz-Algorithm=AWS4-HMAC-SHA256", "&", "X-Amz-Expires=", "99999999999999999999", "Signature=x", "Expires=1", "AWSAccessKeyId=access"]));
        let Ok(req) = http::Request::builder()
            .uri(uri)
            .header("authorization", authz)
            .header("x-amz-date", date)
            .header("x-amz-content-sha256", rng.text(2, &["UNSIGNED-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "zz", "e3b0"]))
            .body(())
        else {
            continue;
        };
        let (parts, _) = req.into_parts();
        let query = crate::handlers::parse_query(parts.uri.query().unwrap_or(""));
        assert!(auth.verify(&parts, &query).is_err());
    }
}

/// Compares paginated ListObjects output against a naive model.
#[test]
fn listing_matches_model() {
    use crate::config::Durability;
    use crate::meta::{self, Meta, ObjectMeta};
    let dir = std::env::temp_dir().join(format!("s3-listing-{}", crate::util::new_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let m = Meta::open(&dir.join("m.redb"), 8, Durability::Relaxed).unwrap();
    let mut rng = Rng(2024);
    let alphabet = ["a", "b", "/", "-", "é", "z", "\u{10FFFF}", "//"];
    let mut keys: Vec<String> = (0..400).map(|_| format!("{}{}", rng.text(6, &alphabet), rng.below(10))).collect();
    keys.sort();
    keys.dedup();
    let k2 = keys.clone();
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(m.write(move |txn| {
        txn.open_table(meta::BUCKETS)?.insert("b", 0)?;
        let mut t = txn.open_table(meta::objects_table("o/b"))?;
        let om = ObjectMeta { size: 1, mtime: 0, etag: "e".into(), content_type: None, headers: vec![], segments: vec![], acl: 0, checksum: None, inline: vec![] };
        for k in &k2 {
            t.insert(k.as_str(), meta::encode(&om).as_slice())?;
        }
        Ok(())
    }))
    .unwrap();

    for _ in 0..iters(300) {
        let prefix = rng.text(2, &alphabet);
        let delimiter = ["", "/", "-", "é", "//"][rng.below(5)];
        let page = 1 + rng.below(7);
        // Model: expected sequence of keys and common prefixes in order.
        let mut expected: Vec<String> = Vec::new();
        for k in keys.iter().filter(|k| k.starts_with(&prefix)) {
            let item = match (!delimiter.is_empty()).then(|| k[prefix.len()..].find(delimiter)).flatten() {
                Some(i) => k[..prefix.len() + i + delimiter.len()].to_string(),
                None => k.clone(),
            };
            if expected.last() != Some(&item) {
                expected.push(item);
            }
        }
        // Paginate through the real implementation.
        let mut got = Vec::new();
        let mut marker = String::new();
        loop {
            let r = meta::list_objects(&m, "b", &prefix, delimiter, &marker, page).unwrap();
            let mut items: Vec<String> = r.objects.iter().map(|o| o.key.clone()).chain(r.prefixes.iter().cloned()).collect();
            items.sort();
            assert!(items.len() <= page);
            got.extend(items);
            if !r.truncated {
                break;
            }
            marker = r.last.unwrap();
        }
        assert_eq!(got, expected, "prefix={prefix:?} delimiter={delimiter:?} page={page}");
    }
    drop(m);
    std::fs::remove_dir_all(&dir).unwrap();
}
