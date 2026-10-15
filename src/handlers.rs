use crate::acl;
use crate::checksum::{self, Algo};
use crate::cors;
use crate::metrics;
use crate::auth::{Auth, Payload};
use crate::chunked::BodyReader;
use crate::config::Config;
use crate::data::{self, Body, DataStore, Digests, FileStream, FileWriter, Hashers};
use crate::error::{S3Error, S3Result};
use crate::meta::{self, decode, encode, objects_table, objects_table_name, Meta, ObjectMeta, PartMeta, Segment, UploadMeta, BUCKETS, PARTS, UPLOADS};
use crate::util::{self, http_date, iso8601, xml_escape as esc};
use base64::Engine;
use bytes::{Bytes, BytesMut};
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use hyper::body::Incoming;
use md5::{Digest, Md5};
use redb::{ReadableTable, WriteTransaction};
use std::fmt::Write as _;
use std::sync::Arc;

const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const XML_DECL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;
const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;
const MAX_XML_BODY: usize = 8 * 1024 * 1024;
/// S3's limit for a single PUT and for one multipart part.
const MAX_PUT_SIZE: u64 = 5 * 1024 * 1024 * 1024;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct App {
    pub cfg: Config,
    pub meta: Meta,
    pub data: Arc<DataStore>,
    pub auth: Auth,
}

struct Req {
    /// Unauthenticated request (access governed by public ACLs).
    anon: bool,
    parts: http::request::Parts,
    query: Vec<(String, String)>,
    payload: Payload,
    body: Option<Incoming>,
}

impl Req {
    fn q(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.query.iter().any(|(k, _)| k == name)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.parts.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn body_reader(&mut self) -> BodyReader {
        let body = self.body.take().expect("body already consumed");
        BodyReader::new(body, &mut self.payload, &self.parts.headers)
    }

    /// The flexible checksum algorithm this request carries (header, trailer
    /// declaration or SDK hint).
    fn checksum_algo(&self) -> Option<Algo> {
        if let Some(a) = checksum::ALL.into_iter().find(|a| self.parts.headers.contains_key(a.header())) {
            return Some(a);
        }
        let trailer = self.header("x-amz-trailer").unwrap_or("").to_ascii_lowercase();
        if let Some(a) = checksum::ALL.into_iter().find(|a| trailer.contains(a.header())) {
            return Some(a);
        }
        self.header("x-amz-sdk-checksum-algorithm").and_then(Algo::parse)
    }

    /// Hashers needed for this request's payload: md5 (or xxh3) for the ETag,
    /// plus whatever the client asked us to verify. `force` computes a
    /// checksum even if the client sent none (multipart uploads with an algorithm).
    fn hashers(&self, etag: bool, fast_etag: bool, force: Option<Algo>) -> Hashers {
        Hashers {
            md5: ((etag && !fast_etag) || self.parts.headers.contains_key("content-md5")).then(Md5::new),
            sha256: matches!(self.payload, Payload::Sha256(_)).then(sha2::Sha256::default),
            checksum: force.or_else(|| self.checksum_algo()).map(|a| (a, checksum::Hasher::new(a))),
            xxh3: (etag && fast_etag).then(|| Box::new(xxhash_rust::xxh3::Xxh3::new())),
            data_crc: None,
        }
    }

    /// Verifies all digests the client supplied against what we computed.
    fn verify(&self, trailers: &[(String, String)], d: &Digests) -> S3Result<()> {
        if let Payload::Sha256(exp) = &self.payload
            && d.sha256.as_ref() != Some(exp) {
                return Err(S3Error::sha256_mismatch());
            }
        if let Some(v) = self.header("content-md5") {
            let exp = B64.decode(v.trim()).map_err(|_| S3Error::invalid_digest())?;
            if exp.len() != 16 {
                return Err(S3Error::invalid_digest());
            }
            if d.md5.map(|m| m.to_vec()) != Some(exp) {
                return Err(S3Error::bad_digest());
            }
        }
        if let Some((algo, got)) = &d.checksum {
            let expected = self
                .header(algo.header())
                .map(str::to_string)
                .or_else(|| trailers.iter().find(|(k, _)| k == algo.header()).map(|(_, v)| v.clone()));
            if expected.is_some_and(|e| e.trim() != got) {
                return Err(S3Error::bad_digest());
            }
        }
        Ok(())
    }

    async fn read_full(&mut self, limit: usize) -> S3Result<Bytes> {
        self.read_full_with(limit, true).await
    }

    /// Reads a small request body. With `body_checksums` false, x-amz-checksum-*
    /// headers are not applied to the body (CompleteMultipartUpload uses them
    /// for the resulting object).
    async fn read_full_with(&mut self, limit: usize, body_checksums: bool) -> S3Result<Bytes> {
        let mut hashers = self.hashers(false, false, None);
        if !body_checksums {
            hashers.checksum = None;
        }
        let mut r = self.body_reader();
        let mut buf = BytesMut::new();
        while let Some(b) = r.next().await? {
            if buf.len() + b.len() > limit {
                return Err(S3Error::entity_too_large());
            }
            hashers.update(&b);
            buf.extend_from_slice(&b);
        }
        self.verify(r.trailers(), &hashers.finish())?;
        Ok(buf.freeze())
    }
}

fn checksum_headers(b: http::response::Builder, d: &Digests) -> http::response::Builder {
    match &d.checksum {
        Some((algo, value)) => b.header(algo.header(), value.as_str()),
        None => b,
    }
}

/// The stored full-object checksum from a request's digests.
fn stored_checksum(d: &Digests) -> Option<checksum::Stored> {
    d.checksum.as_ref().map(|(algo, value)| checksum::Stored { algo: *algo, kind: checksum::Kind::FullObject, value: value.clone() })
}

/// The S3 operation a request maps to (for metrics and access logs).
fn op_name(cfg: &Config, req: &Request<Incoming>) -> &'static str {
    let q = req.uri().query().unwrap_or("");
    let has = |name: &str| q.split('&').any(|kv| kv.split('=').next() == Some(name));
    let (bucket, key) = route_uri(cfg, req.uri(), req.headers());
    let m = req.method();
    if req.uri().path() == "/_health" || req.uri().path() == "/_metrics" {
        return "Internal";
    }
    if *m == Method::OPTIONS {
        return "Options";
    }
    match (bucket.is_some(), key.is_some(), m.as_str()) {
        (false, _, "GET") => "ListBuckets",
        (true, false, "GET") if has("location") => "GetBucketLocation",
        (true, false, "GET") if has("versioning") => "GetBucketVersioning",
        (true, false, "GET") if has("acl") => "GetBucketAcl",
        (true, false, "GET") if has("cors") => "GetBucketCors",
        (true, false, "GET") if has("uploads") => "ListMultipartUploads",
        (true, false, "GET") if has("versions") => "ListObjectVersions",
        (true, false, "GET") if q.contains("list-type=2") => "ListObjectsV2",
        (true, false, "GET") => "ListObjects",
        (true, false, "HEAD") => "HeadBucket",
        (true, false, "PUT") if has("acl") => "PutBucketAcl",
        (true, false, "PUT") if has("cors") => "PutBucketCors",
        (true, false, "PUT") => "CreateBucket",
        (true, false, "DELETE") if has("cors") => "DeleteBucketCors",
        (true, false, "DELETE") => "DeleteBucket",
        (true, false, "POST") if has("delete") => "DeleteObjects",
        (true, false, "POST") => "PostObject",
        (true, true, "GET") if has("uploadId") => "ListParts",
        (true, true, "GET") if has("acl") => "GetObjectAcl",
        (true, true, "GET") if has("tagging") => "GetObjectTagging",
        (true, true, "GET") if has("attributes") => "GetObjectAttributes",
        (true, true, "GET") => "GetObject",
        (true, true, "HEAD") => "HeadObject",
        (true, true, "PUT") if has("uploadId") && req.headers().contains_key("x-amz-copy-source") => "UploadPartCopy",
        (true, true, "PUT") if has("uploadId") => "UploadPart",
        (true, true, "PUT") if has("acl") => "PutObjectAcl",
        (true, true, "PUT") if req.headers().contains_key("x-amz-copy-source") => "CopyObject",
        (true, true, "PUT") => "PutObject",
        (true, true, "POST") if has("uploads") => "CreateMultipartUpload",
        (true, true, "POST") if has("uploadId") => "CompleteMultipartUpload",
        (true, true, "DELETE") if has("uploadId") => "AbortMultipartUpload",
        (true, true, "DELETE") => "DeleteObject",
        _ => "Other",
    }
}

fn content_length(h: &http::HeaderMap) -> u64 {
    let n = |name: &str| h.get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
    n("x-amz-decoded-content-length").or_else(|| n("content-length")).unwrap_or(0)
}

pub async fn handle(app: Arc<App>, req: Request<Incoming>, remote: std::net::SocketAddr) -> Response<Body> {
    let started = std::time::Instant::now();
    let _inflight = metrics::GaugeGuard::new(&metrics::get().inflight);
    let rid = util::request_id();
    let is_head = req.method() == Method::HEAD;
    let resource = req.uri().path().to_string();
    let op = op_name(&app.cfg, &req);
    let bytes_in = content_length(req.headers());
    // Access log fields (only collected when logging is on).
    let log_ctx = metrics::access_log_enabled().then(|| {
        let ak = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| a.split("Credential=").nth(1).or_else(|| a.strip_prefix("AWS ")))
            .and_then(|c| c.split(['/', ':']).next())
            .unwrap_or("")
            .to_string();
        let ua = req.headers().get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        (req.method().to_string(), req.uri().to_string(), ak, ua)
    });
    // CORS context for non-preflight requests: (origin, bucket, method to match).
    let cors_ctx = match (req.method() != Method::OPTIONS, req.headers().get(header::ORIGIN).and_then(|o| o.to_str().ok())) {
        (true, Some(origin)) => route_uri(&app.cfg, req.uri(), req.headers()).0.map(|b| {
            let method = req.headers().get("access-control-request-method").and_then(|m| m.to_str().ok()).unwrap_or(req.method().as_str());
            (origin.to_string(), b, method.to_string())
        }),
        _ => None,
    };
    let mut resp = match dispatch(&app, req).await {
        Ok(r) => r,
        Err(e) => {
            if e.status.is_server_error() && e.status != StatusCode::NOT_IMPLEMENTED {
                eprintln!("error {} {}: {}", resource, e.code, e.message);
            }
            error_response(&e, &resource, &rid, is_head)
        }
    };
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&rid) {
        h.insert("x-amz-request-id", v);
    }
    h.insert(header::SERVER, HeaderValue::from_static("s3"));
    if let Some((origin, bucket, method)) = cors_ctx
        && let Ok(Some(rules)) = app.meta.bucket_cors(&bucket)
        && let Some(rule) = cors::find(&rules, &origin, &method, &[])
    {
        cors::apply(resp.headers_mut(), rule, &origin, &[], false);
    }
    let status = resp.status().as_u16();
    let secs = started.elapsed().as_secs_f64();
    let bytes_out = if is_head { 0 } else { http_body::Body::size_hint(resp.body()).exact().unwrap_or(0) };
    let m = metrics::get();
    m.record(op, status, secs);
    m.bytes_in.fetch_add(bytes_in, std::sync::atomic::Ordering::Relaxed);
    m.bytes_out.fetch_add(bytes_out, std::sync::atomic::Ordering::Relaxed);
    if let Some((method, uri, ak, ua)) = log_ctx {
        metrics::access_log(format!(
            "{{\"time\":\"{}\",\"request_id\":\"{rid}\",\"remote\":\"{remote}\",\"access_key\":{},\"op\":\"{op}\",\"method\":\"{method}\",\"uri\":{},\"status\":{status},\"bytes_in\":{bytes_in},\"bytes_out\":{bytes_out},\"duration_ms\":{:.3},\"user_agent\":{}}}\n",
            iso8601(util::now_ms()),
            metrics::json_str(&ak),
            metrics::json_str(&uri),
            secs * 1000.0,
            metrics::json_str(&ua)
        ));
    }
    resp
}

/// GET /_metrics (Prometheus). Enabled only with --metrics-token.
fn metrics_endpoint(app: &App, parts: &http::request::Parts) -> S3Result<Response<Body>> {
    let Some(token) = &app.cfg.metrics_token else { return Err(S3Error::no_such_bucket()) };
    let given = parts.headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    if !given.is_some_and(|g| util::constant_time_eq(g.trim().as_bytes(), token.as_bytes())) {
        return Err(S3Error::access_denied());
    }
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Body::full(metrics::get().render(app.data.free_bytes())))
        .unwrap())
}

/// CORS preflight (OPTIONS): answered from the bucket's CORS rules, no auth.
fn preflight(app: &App, parts: &http::request::Parts) -> S3Result<Response<Body>> {
    let bad = |m: &'static str| S3Error::new("BadRequest", StatusCode::BAD_REQUEST, m);
    let origin = parts.headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).ok_or_else(|| bad("Insufficient information. Origin request header needed."))?;
    let method = parts
        .headers
        .get("access-control-request-method")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| bad("Insufficient information. Access-Control-Request-Method header needed."))?;
    let bucket = route(&app.cfg, parts).0.ok_or_else(S3Error::access_denied)?;
    let forbidden = || S3Error::new("AccessForbidden", StatusCode::FORBIDDEN, "CORSResponse: This CORS request is not allowed.");
    let rules = match app.meta.bucket_cors(&bucket)? {
        Some(r) => r,
        None if app.meta.bucket_exists(&bucket)? => return Err(forbidden()),
        None => return Err(S3Error::no_such_bucket()),
    };
    let req_headers = cors::requested_headers(&parts.headers);
    let rule = cors::find(&rules, origin, method, &req_headers).ok_or_else(forbidden)?;
    let mut resp = Response::new(Body::Empty);
    cors::apply(resp.headers_mut(), rule, origin, &req_headers, true);
    Ok(resp)
}

async fn put_bucket_cors(app: &App, r: &mut Req, bucket: String) -> S3Result<Response<Body>> {
    bucket_must_exist(app, &bucket)?;
    let body = r.read_full(MAX_XML_BODY).await?;
    let rules = cors::parse(std::str::from_utf8(&body).map_err(|_| S3Error::malformed_xml())?)?;
    app.meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            txn.open_table(meta::CORS)?.insert(bucket.as_str(), encode(&rules).as_slice())?;
            Ok(())
        })
        .await?;
    empty(StatusCode::OK)
}

fn get_bucket_cors(app: &App, bucket: &str) -> S3Result<Response<Body>> {
    match app.meta.bucket_cors(bucket)? {
        Some(rules) => xml_response(StatusCode::OK, cors::to_xml(&rules)),
        None => {
            bucket_must_exist(app, bucket)?;
            Err(S3Error::new("NoSuchCORSConfiguration", StatusCode::NOT_FOUND, "The CORS configuration does not exist"))
        }
    }
}

async fn delete_bucket_cors(app: &App, bucket: String) -> S3Result<Response<Body>> {
    app.meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            txn.open_table(meta::CORS)?.remove(bucket.as_str())?;
            Ok(())
        })
        .await?;
    empty(StatusCode::NO_CONTENT)
}

fn error_response(e: &S3Error, resource: &str, rid: &str, head: bool) -> Response<Body> {
    let body = if head || e.status == StatusCode::NOT_MODIFIED {
        Body::Empty
    } else {
        Body::full(format!(
            "{XML_DECL}<Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>",
            e.code,
            esc(&e.message),
            esc(resource),
            rid
        ))
    };
    Response::builder()
        .status(e.status)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(body)
        .unwrap()
}

fn xml_response(status: StatusCode, body: String) -> S3Result<Response<Body>> {
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/xml")
        .body(Body::full(body))
        .unwrap())
}

fn empty(status: StatusCode) -> S3Result<Response<Body>> {
    Ok(Response::builder().status(status).body(Body::Empty).unwrap())
}

pub(crate) fn parse_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (util::query_decode(k), util::query_decode(v)),
            None => (util::query_decode(kv), String::new()),
        })
        .collect()
}

/// Returns (bucket, key) using virtual-host style if configured, else path style.
fn route(cfg: &Config, parts: &http::request::Parts) -> (Option<String>, Option<String>) {
    route_uri(cfg, &parts.uri, &parts.headers)
}

fn route_uri(cfg: &Config, uri: &http::Uri, headers: &http::HeaderMap) -> (Option<String>, Option<String>) {
    let path = util::percent_decode(uri.path());
    if let Some(domain) = &cfg.domain {
        let host = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.rsplit_once(':').map_or(h, |(a, _)| a).to_ascii_lowercase());
        if let Some(b) = host.as_deref().and_then(|h| h.strip_suffix(domain.as_str())).and_then(|h| h.strip_suffix('.')) {
            let key = path.strip_prefix('/').unwrap_or(&path);
            return (Some(b.to_string()), (!key.is_empty()).then(|| key.to_string()));
        }
    }
    let p = path.strip_prefix('/').unwrap_or(&path);
    if p.is_empty() {
        return (None, None);
    }
    match p.split_once('/') {
        Some((b, k)) if !k.is_empty() => (Some(b.to_string()), Some(k.to_string())),
        Some((b, _)) => (Some(b.to_string()), None),
        None => (Some(p.to_string()), None),
    }
}

const UNSUPPORTED_SUBRESOURCES: &[&str] = &[
    "policy", "lifecycle", "website", "tagging", "replication", "logging", "notification", "encryption",
    "object-lock", "accelerate", "requestPayment", "ownershipControls", "publicAccessBlock", "analytics", "metrics",
    "inventory", "intelligent-tiering", "policyStatus", "retention", "legal-hold", "restore", "select",
    "torrent",
];

async fn dispatch(app: &Arc<App>, req: Request<Incoming>) -> S3Result<Response<Body>> {
    let (parts, body) = req.into_parts();
    if parts.uri.path() == "/_health" {
        return Ok(Response::new(Body::full("OK")));
    }
    if parts.uri.path() == "/_metrics" && parts.method == Method::GET {
        return metrics_endpoint(app, &parts);
    }
    if parts.method == Method::OPTIONS {
        return preflight(app, &parts);
    }
    // Browser form upload: authenticated by the signed policy inside the form.
    if parts.method == Method::POST
        && parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|ct| ct.to_ascii_lowercase().starts_with("multipart/form-data"))
        && let (Some(bucket), None) = route(&app.cfg, &parts)
    {
        return post_object(app, parts, body, bucket).await;
    }
    let query = parse_query(parts.uri.query().unwrap_or(""));
    let anon = !app.cfg.anonymous && !crate::auth::has_credentials(&parts, &query);
    let payload = if anon || app.cfg.anonymous && !crate::auth::has_credentials(&parts, &query) {
        crate::auth::anonymous_payload(&parts)?
    } else {
        app.auth.verify(&parts, &query)?
    };
    let (bucket, key) = route(&app.cfg, &parts);
    let mut r = Req { anon, parts, query, payload, body: Some(body) };
    let m = r.parts.method.clone();
    let unsupported = || UNSUPPORTED_SUBRESOURCES.iter().any(|s| r.has(s));

    // Mutating requests must not carry query parameters we don't understand:
    // e.g. `DELETE /bucket?ownershipControls` must never delete the bucket.
    if matches!(m, Method::PUT | Method::DELETE | Method::POST) {
        let allowed: &[&str] = match (&bucket, &key, &m) {
            (Some(_), None, &Method::PUT) => &["acl", "cors"],
            (Some(_), None, &Method::DELETE) => &["cors"],
            (Some(_), None, &Method::POST) => &["delete"],
            (Some(_), Some(_), &Method::PUT) => &["uploadId", "partNumber", "versionId", "acl"],
            (Some(_), Some(_), &Method::DELETE) => &["uploadId", "versionId"],
            (Some(_), Some(_), &Method::POST) => &["uploads", "uploadId"],
            _ => &[],
        };
        if r.query.iter().any(|(k, _)| !allowed.contains(&k.as_str()) && !is_auth_param(k)) {
            return Err(S3Error::not_implemented());
        }
    }

    if r.anon {
        authorize_anonymous(app, &r, bucket.as_deref(), key.as_deref())?;
    }
    for h in ["x-amz-expected-bucket-owner", "x-amz-source-expected-bucket-owner"] {
        if r.header(h).is_some_and(|o| o.trim() != acl::owner_id()) {
            return Err(S3Error::access_denied());
        }
    }

    match (bucket, key) {
        (None, _) => match m {
            Method::GET => list_buckets(app, &r),
            _ => Err(S3Error::method_not_allowed()),
        },
        (Some(b), None) => match m {
            Method::GET if r.has("location") => get_location(app, &b),
            Method::GET if r.has("versioning") => {
                bucket_must_exist(app, &b)?;
                xml_response(StatusCode::OK, format!(r#"{XML_DECL}<VersioningConfiguration xmlns="{XMLNS}"/>"#))
            }
            Method::GET if r.has("acl") => {
                let acl = app.meta.bucket_acl(&b)?.ok_or_else(S3Error::no_such_bucket)?;
                xml_response(StatusCode::OK, acl::to_xml(acl))
            }
            Method::GET if r.has("uploads") => list_uploads(app, &r, &b),
            Method::GET if r.has("cors") => get_bucket_cors(app, &b),
            Method::PUT if r.has("cors") => put_bucket_cors(app, &mut r, b).await,
            Method::DELETE if r.has("cors") => delete_bucket_cors(app, b).await,
            _ if unsupported() => Err(S3Error::not_implemented()),
            Method::GET if r.has("versions") => list_versions(app, &r, b).await,
            Method::GET => list_objects(app, &r, b).await,
            Method::HEAD => {
                bucket_must_exist(app, &b)?;
                Ok(Response::builder()
                    .header("x-amz-bucket-region", app.cfg.region.as_str())
                    .body(Body::Empty)
                    .unwrap())
            }
            Method::PUT if r.has("acl") => put_bucket_acl(app, &mut r, b).await,
            Method::PUT => create_bucket(app, &mut r, b).await,
            Method::DELETE => delete_bucket(app, b).await,
            Method::POST if r.has("delete") => delete_objects(app, &mut r, b).await,
            _ => Err(S3Error::method_not_allowed()),
        },
        (Some(b), Some(k)) => {
            if k.len() > 1024 {
                return Err(S3Error::key_too_long());
            }
            // Buckets are never versioned: the only version of an object is "null".
            if r.q("versionId").is_some_and(|v| v != "null") {
                return Err(S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "Invalid version id specified"));
            }
            match m {
                Method::GET if r.has("uploadId") => list_parts(app, &r, &b, &k),
                Method::GET if r.has("acl") => xml_response(StatusCode::OK, acl::to_xml(app.meta.get_object(&b, &k)?.acl)),
                Method::PUT if r.has("acl") => put_object_acl(app, &mut r, b, k).await,
                Method::GET if r.has("attributes") => get_object_attributes(app, &r, &b, &k),
                Method::GET if r.has("tagging") => {
                    app.meta.get_object(&b, &k)?;
                    xml_response(StatusCode::OK, format!(r#"{XML_DECL}<Tagging xmlns="{XMLNS}"><TagSet></TagSet></Tagging>"#))
                }
                _ if unsupported() => Err(S3Error::not_implemented()),
                Method::GET => get_object(app, &r, &b, &k, false).await,
                Method::HEAD => get_object(app, &r, &b, &k, true).await,
                Method::PUT if r.has("uploadId") => {
                    if r.header("x-amz-copy-source").is_some() {
                        upload_part_copy(app, &r, b, k).await
                    } else {
                        upload_part(app, &mut r, b, k).await
                    }
                }
                Method::PUT if r.header("x-amz-copy-source").is_some() => copy_object(app, &r, b, k).await,
                Method::PUT => put_object(app, &mut r, b, k).await,
                Method::POST if r.has("uploads") => create_multipart(app, &r, b, k).await,
                Method::POST if r.has("uploadId") => complete_multipart(app, &mut r, b, k).await,
                Method::DELETE if r.has("uploadId") => abort_multipart(app, &r, &b, &k).await,
                Method::DELETE => delete_object(app, b, k).await,
                _ => Err(S3Error::method_not_allowed()),
            }
        }
    }
}

/// Query parameters that carry authentication, signed header values of
/// presigned URLs, or SDK bookkeeping (never an operation/subresource).
fn is_auth_param(k: &str) -> bool {
    k.starts_with("X-Amz-")
        || k.starts_with("x-amz-")
        || matches!(
            k,
            "AWSAccessKeyId" | "Signature" | "Expires" | "x-id" | "content-type" | "content-md5" | "content-disposition" | "content-encoding" | "content-language" | "cache-control"
        )
}

/// Decides whether an unauthenticated request is allowed by the public ACLs.
fn authorize_anonymous(app: &App, r: &Req, bucket: Option<&str>, key: Option<&str>) -> S3Result<()> {
    let Some(bucket) = bucket else { return Err(S3Error::access_denied()) };
    let bucket_acl = app.meta.bucket_acl(bucket)?.ok_or_else(S3Error::no_such_bucket)?;
    let m = &r.parts.method;
    // Configuration and ACL subresources are owner-only.
    let admin = ["acl", "cors", "location", "versioning", "uploads", "policy", "tagging", "lifecycle"].iter().any(|s| r.has(s));
    let allowed = match key {
        None if admin => false,
        None if matches!(*m, Method::GET | Method::HEAD) => acl::anonymous_can_read(bucket_acl),
        None if *m == Method::POST && r.has("delete") => acl::anonymous_can_write(bucket_acl),
        None => false,
        Some(_) if r.has("acl") || r.has("tagging") => false,
        Some(_) if r.has("uploadId") || r.has("uploads") => acl::anonymous_can_write(bucket_acl),
        Some(k) if matches!(*m, Method::GET | Method::HEAD) => match app.meta.get_object(bucket, k) {
            Ok(o) => acl::anonymous_can_read(o.acl),
            // A missing key is only revealed (404) if the bucket is listable.
            Err(e) if e.code == "NoSuchKey" => acl::anonymous_can_read(bucket_acl),
            Err(e) => return Err(e),
        },
        Some(_) if *m == Method::PUT => acl::anonymous_can_write(bucket_acl) && r.header("x-amz-copy-source").is_none(),
        Some(_) if *m == Method::DELETE => acl::anonymous_can_write(bucket_acl),
        Some(_) => false,
    };
    if allowed { Ok(()) } else { Err(S3Error::access_denied()) }
}

/// ACL requested by a PutBucketAcl / PutObjectAcl call (headers or XML body).
async fn requested_acl(r: &mut Req) -> S3Result<u8> {
    if let Some(acl) = acl::from_headers(&r.parts.headers)? {
        return Ok(acl);
    }
    let body = r.read_full(64 * 1024).await?;
    let text = std::str::from_utf8(&body).map_err(|_| S3Error::malformed_xml())?;
    acl::from_xml(text)
}

async fn put_bucket_acl(app: &App, r: &mut Req, bucket: String) -> S3Result<Response<Body>> {
    bucket_must_exist(app, &bucket)?;
    let acl = requested_acl(r).await?;
    app.meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            txn.open_table(meta::BUCKET_ACL)?.insert(bucket.as_str(), acl)?;
            Ok(())
        })
        .await?;
    empty(StatusCode::OK)
}

async fn put_object_acl(app: &App, r: &mut Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    app.meta.get_object(&bucket, &key)?;
    let acl = requested_acl(r).await?;
    app.meta
        .write(move |txn| {
            let name = objects_table_name(&bucket);
            let mut t = txn.open_table(objects_table(&name))?;
            let mut m: ObjectMeta = match t.get(key.as_str())? {
                Some(v) => decode(v.value())?,
                None => return Err(S3Error::no_such_key()),
            };
            m.acl = acl;
            t.insert(key.as_str(), encode(&m).as_slice())?;
            Ok(())
        })
        .await?;
    empty(StatusCode::OK)
}

fn bucket_must_exist(app: &App, bucket: &str) -> S3Result<()> {
    if app.meta.bucket_exists(bucket)? {
        Ok(())
    } else {
        Err(S3Error::no_such_bucket())
    }
}

// ---------------------------------------------------------------- buckets

/// ListBuckets, with the optional max-buckets / continuation-token / prefix pagination.
fn list_buckets(app: &App, r: &Req) -> S3Result<Response<Body>> {
    let owner = acl::owner_xml();
    let max = match r.q("max-buckets") {
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (1..=10000).contains(&n) => n,
            _ => return Err(S3Error::invalid_argument()),
        },
        None => usize::MAX,
    };
    let prefix = r.q("prefix").unwrap_or("");
    let after = match r.q("continuation-token") {
        Some(t) => String::from_utf8(B64URL.decode(t).map_err(|_| S3Error::invalid_argument())?).map_err(|_| S3Error::invalid_argument())?,
        None => String::new(),
    };
    let buckets: Vec<(String, u64)> =
        app.meta.list_buckets()?.into_iter().filter(|(n, _)| n.starts_with(prefix) && n.as_str() > after.as_str()).collect();
    let mut x = format!(r#"{XML_DECL}<ListAllMyBucketsResult xmlns="{XMLNS}">{owner}<Buckets>"#);
    for (name, created) in buckets.iter().take(max) {
        let _ = write!(
            x,
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate><BucketRegion>{}</BucketRegion></Bucket>",
            esc(name),
            iso8601(*created),
            esc(&app.cfg.region)
        );
    }
    x.push_str("</Buckets>");
    if buckets.len() > max {
        let _ = write!(x, "<ContinuationToken>{}</ContinuationToken>", B64URL.encode(&buckets[max - 1].0));
    }
    if r.q("prefix").is_some() {
        let _ = write!(x, "<Prefix>{}</Prefix>", esc(prefix));
    }
    x.push_str("</ListAllMyBucketsResult>");
    xml_response(StatusCode::OK, x)
}

fn get_location(app: &App, bucket: &str) -> S3Result<Response<Body>> {
    bucket_must_exist(app, bucket)?;
    let region = if app.cfg.region == "us-east-1" { "" } else { app.cfg.region.as_str() };
    xml_response(StatusCode::OK, format!(r#"{XML_DECL}<LocationConstraint xmlns="{XMLNS}">{}</LocationConstraint>"#, esc(region)))
}

fn valid_bucket_name(b: &str) -> bool {
    let bytes = b.as_bytes();
    (3..=63).contains(&b.len())
        && bytes.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'.' || *c == b'-')
        && bytes[0].is_ascii_alphanumeric()
        && bytes[b.len() - 1].is_ascii_alphanumeric()
        && !b.contains("..")
        && !(b.split('.').count() == 4 && b.split('.').all(|p| p.parse::<u8>().is_ok()))
}

async fn create_bucket(app: &App, r: &mut Req, bucket: String) -> S3Result<Response<Body>> {
    if !valid_bucket_name(&bucket) {
        return Err(S3Error::invalid_bucket_name());
    }
    let requested_acl = acl::from_headers(&r.parts.headers)?;
    let acl = requested_acl.unwrap_or(acl::PRIVATE);
    // Body (optional CreateBucketConfiguration) is accepted but not needed.
    r.read_full(64 * 1024).await?;
    let location = format!("/{bucket}");
    // Like AWS in us-east-1, re-creating your own bucket succeeds (and only
    // updates its ACL if one is given); other regions answer 409.
    let legacy_recreate = app.cfg.region == "us-east-1";
    app.meta
        .write(move |txn| {
            let mut t = txn.open_table(BUCKETS)?;
            if t.get(bucket.as_str())?.is_some() {
                if !legacy_recreate {
                    return Err(S3Error::bucket_exists());
                }
                if let Some(acl) = requested_acl {
                    txn.open_table(meta::BUCKET_ACL)?.insert(bucket.as_str(), acl)?;
                }
                return Ok(());
            }
            t.insert(bucket.as_str(), util::now_ms())?;
            drop(t);
            let mut at = txn.open_table(meta::BUCKET_ACL)?;
            if acl == acl::PRIVATE {
                at.remove(bucket.as_str())?;
            } else {
                at.insert(bucket.as_str(), acl)?;
            }
            drop(at);
            txn.open_table(objects_table(&objects_table_name(&bucket)))?;
            txn.open_table(objects_table(&meta::data_table_name(&bucket)))?;
            Ok(())
        })
        .await?;
    Ok(Response::builder().header(header::LOCATION, location).body(Body::Empty).unwrap())
}

/// Deletes an empty bucket. Like S3, incomplete multipart uploads do not
/// block deletion; they are discarded together with the bucket.
async fn delete_bucket(app: &App, bucket: String) -> S3Result<Response<Body>> {
    let files = app
        .meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            if !meta::bucket_is_empty(txn, &bucket)? {
                return Err(S3Error::bucket_not_empty());
            }
            let mut uploads = Vec::new();
            for e in txn.open_table(UPLOADS)?.iter()? {
                let (k, v) = e?;
                if decode::<UploadMeta>(v.value())?.bucket == bucket {
                    uploads.push(k.value().to_string());
                }
            }
            let mut files = Vec::new();
            for id in uploads {
                files.extend(meta::abort_upload_txn(txn, &id, None)?);
            }
            txn.open_table(BUCKETS)?.remove(bucket.as_str())?;
            txn.open_table(meta::BUCKET_ACL)?.remove(bucket.as_str())?;
            txn.open_table(meta::CORS)?.remove(bucket.as_str())?;
            txn.delete_table(objects_table(&objects_table_name(&bucket)))?;
            txn.delete_table(objects_table(&meta::data_table_name(&bucket)))?;
            Ok(files)
        })
        .await?;
    app.data.remove_later(files);
    empty(StatusCode::NO_CONTENT)
}

/// ListObjectVersions for unversioned buckets: every object is its own
/// latest (and only) version with version id "null".
async fn list_versions(app: &Arc<App>, r: &Req, bucket: String) -> S3Result<Response<Body>> {
    let owner = acl::owner_xml();
    let prefix = r.q("prefix").unwrap_or("").to_string();
    let delimiter = r.q("delimiter").unwrap_or("").to_string();
    let marker = r.q("key-marker").unwrap_or("").to_string();
    let max_keys = match r.q("max-keys") {
        Some(v) => v.parse::<i64>().map_err(|_| S3Error::invalid_argument())?.clamp(0, 1000) as usize,
        None => 1000,
    };
    let url = r.q("encoding-type") == Some("url");
    let enc = |s: &str| -> String { if url { util::aws_uri_encode(s, false) } else { esc(s).into_owned() } };
    let a = app.clone();
    let (b2, p2, d2, m2) = (bucket.clone(), prefix.clone(), delimiter.clone(), marker.clone());
    let res = tokio::task::spawn_blocking(move || meta::list_objects(&a.meta, &b2, &p2, &d2, &m2, max_keys)).await??;
    let mut x = String::with_capacity(256 + res.objects.len() * 300);
    let _ = write!(
        x,
        r#"{XML_DECL}<ListVersionsResult xmlns="{XMLNS}"><Name>{}</Name><Prefix>{}</Prefix><KeyMarker>{}</KeyMarker><VersionIdMarker>{}</VersionIdMarker><MaxKeys>{max_keys}</MaxKeys>"#,
        esc(&bucket),
        enc(&prefix),
        enc(&marker),
        esc(r.q("version-id-marker").unwrap_or(""))
    );
    if !delimiter.is_empty() {
        let _ = write!(x, "<Delimiter>{}</Delimiter>", enc(&delimiter));
    }
    if url {
        x.push_str("<EncodingType>url</EncodingType>");
    }
    let _ = write!(x, "<IsTruncated>{}</IsTruncated>", res.truncated);
    if res.truncated
        && let Some(last) = &res.last
    {
        let _ = write!(x, "<NextKeyMarker>{}</NextKeyMarker><NextVersionIdMarker>null</NextVersionIdMarker>", enc(last));
    }
    for o in &res.objects {
        let _ = write!(
            x,
            "<Version><Key>{}</Key><VersionId>null</VersionId><IsLatest>true</IsLatest><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size>{owner}<StorageClass>STANDARD</StorageClass></Version>",
            enc(&o.key),
            iso8601(o.mtime),
            o.etag,
            o.size
        );
    }
    for p in &res.prefixes {
        let _ = write!(x, "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", enc(p));
    }
    x.push_str("</ListVersionsResult>");
    xml_response(StatusCode::OK, x)
}

async fn list_objects(app: &Arc<App>, r: &Req, bucket: String) -> S3Result<Response<Body>> {
    let owner = acl::owner_xml();
    let v2 = r.q("list-type") == Some("2");
    let prefix = r.q("prefix").unwrap_or("").to_string();
    let delimiter = r.q("delimiter").unwrap_or("").to_string();
    let max_keys = match r.q("max-keys") {
        Some(v) => v.parse::<i64>().map_err(|_| S3Error::invalid_argument())?.clamp(0, 1000) as usize,
        None => 1000,
    };
    let url = r.q("encoding-type") == Some("url");
    let enc = |s: &str| -> String {
        if url {
            util::aws_uri_encode(s, false)
        } else {
            esc(s).into_owned()
        }
    };
    let token = r.q("continuation-token");
    let start_after = r.q("start-after").unwrap_or("");
    let marker = if v2 {
        match token {
            Some(t) => String::from_utf8(B64URL.decode(t).map_err(|_| S3Error::invalid_argument())?)
                .map_err(|_| S3Error::invalid_argument())?,
            None => start_after.to_string(),
        }
    } else {
        r.q("marker").unwrap_or("").to_string()
    };

    let a = app.clone();
    let (b2, p2, d2, m2) = (bucket.clone(), prefix.clone(), delimiter.clone(), marker.clone());
    let res = tokio::task::spawn_blocking(move || meta::list_objects(&a.meta, &b2, &p2, &d2, &m2, max_keys)).await??;

    let mut x = String::with_capacity(256 + res.objects.len() * 256);
    // ListObjects v1 never URL-encodes the top-level Prefix (clients don't decode it).
    let top_prefix = if v2 { enc(&prefix) } else { esc(&prefix).into_owned() };
    let _ = write!(x, r#"{XML_DECL}<ListBucketResult xmlns="{XMLNS}"><Name>{}</Name><Prefix>{}</Prefix>"#, esc(&bucket), top_prefix);
    if v2 {
        let _ = write!(x, "<KeyCount>{}</KeyCount>", res.objects.len() + res.prefixes.len());
        if let Some(t) = token {
            let _ = write!(x, "<ContinuationToken>{}</ContinuationToken>", esc(t));
        }
        if !start_after.is_empty() {
            let _ = write!(x, "<StartAfter>{}</StartAfter>", enc(start_after));
        }
        if res.truncated
            && let Some(last) = &res.last {
                let _ = write!(x, "<NextContinuationToken>{}</NextContinuationToken>", B64URL.encode(last));
            }
    } else {
        let _ = write!(x, "<Marker>{}</Marker>", enc(&marker));
        if res.truncated
            && let Some(last) = &res.last {
                let _ = write!(x, "<NextMarker>{}</NextMarker>", enc(last));
            }
    }
    let _ = write!(x, "<MaxKeys>{max_keys}</MaxKeys>");
    if !delimiter.is_empty() {
        let _ = write!(x, "<Delimiter>{}</Delimiter>", enc(&delimiter));
    }
    if url {
        x.push_str("<EncodingType>url</EncodingType>");
    }
    let _ = write!(x, "<IsTruncated>{}</IsTruncated>", res.truncated);
    for o in &res.objects {
        let _ = write!(
            x,
            "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size>{}<StorageClass>STANDARD</StorageClass></Contents>",
            enc(&o.key),
            iso8601(o.mtime),
            o.etag,
            o.size,
            if v2 && r.q("fetch-owner") != Some("true") { "" } else { owner.as_str() }
        );
    }
    for p in &res.prefixes {
        let _ = write!(x, "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>", enc(p));
    }
    x.push_str("</ListBucketResult>");
    xml_response(StatusCode::OK, x)
}

// ---------------------------------------------------------------- objects

const STORED_HEADERS: &[&str] = &["cache-control", "content-disposition", "content-language", "expires", "x-amz-website-redirect-location"];

fn collect_meta_headers(h: &http::HeaderMap) -> (Option<String>, Vec<(String, String)>) {
    let ct = h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let mut out = Vec::new();
    for (name, value) in h {
        let n = name.as_str();
        if n.starts_with("x-amz-meta-") || STORED_HEADERS.contains(&n) {
            out.push((n.to_string(), util::header_to_string(value.as_bytes())));
            continue;
        }
        if n == "content-encoding"
            && let Ok(v) = value.to_str()
        {
            let enc: Vec<&str> = v.split(',').map(str::trim).filter(|e| !e.is_empty() && *e != "aws-chunked").collect();
            if !enc.is_empty() {
                out.push((n.to_string(), enc.join(", ")));
            }
        }
    }
    (ct, out)
}

/// Conditional-write headers of PutObject / CompleteMultipartUpload.
#[derive(Default, Clone)]
struct WriteCond {
    if_match: Option<String>,
    if_none_match: Option<String>,
}

impl WriteCond {
    fn from(r: &Req) -> WriteCond {
        WriteCond { if_match: r.header("if-match").map(str::to_string), if_none_match: r.header("if-none-match").map(str::to_string) }
    }

    fn check(&self, existing: Option<&str>) -> S3Result<()> {
        if let Some(m) = &self.if_match {
            match existing {
                None => return Err(S3Error::no_such_key()),
                Some(etag) if !etag_matches(m, etag) => return Err(S3Error::precondition_failed()),
                _ => {}
            }
        }
        if let (Some(m), Some(etag)) = (&self.if_none_match, existing)
            && etag_matches(m, etag)
        {
            return Err(S3Error::precondition_failed());
        }
        Ok(())
    }
}

fn put_object_txn(txn: &WriteTransaction, bucket: &str, key: &str, m: &ObjectMeta, cond: &WriteCond) -> S3Result<Option<ObjectMeta>> {
    if txn.open_table(BUCKETS)?.get(bucket)?.is_none() {
        return Err(S3Error::no_such_bucket());
    }
    let name = objects_table_name(bucket);
    let mut t = txn.open_table(objects_table(&name))?;
    if cond.if_match.is_some() || cond.if_none_match.is_some() {
        let existing = match t.get(key)? {
            Some(v) => Some(decode::<meta::ListHead>(v.value())?.etag.to_string()),
            None => None,
        };
        cond.check(existing.as_deref())?;
    }
    let enc = encode(m);
    let old = match t.insert(key, enc.as_slice())? {
        Some(v) => Some(decode::<ObjectMeta>(v.value())?),
        None => None,
    };
    drop(t);
    let dname = meta::data_table_name(bucket);
    let mut dt = txn.open_table(objects_table(&dname))?;
    if m.segments.is_empty() && !m.inline.is_empty() {
        dt.insert(key, m.inline.as_slice())?;
    } else if old.as_ref().is_some_and(|o| o.segments.is_empty() && o.size > 0) {
        dt.remove(key)?;
    }
    drop(dt);
    let old_ids = old.as_ref().map(|o| o.file_ids()).unwrap_or_default();
    meta::index_files(txn, &m.segments, &old_ids)?;
    Ok(old)
}

/// Receives the request body into an inline buffer or a data file.
/// Returns (segments, inline, size, digests).
async fn receive_body(app: &App, r: &mut Req, allow_inline: bool, force: Option<Algo>) -> S3Result<(Vec<Segment>, Vec<u8>, u64, Digests)> {
    let mut hashers = r.hashers(true, app.cfg.fast_etag, force);
    let mut body = r.body_reader();
    if body.expected.is_some_and(|l| l > MAX_PUT_SIZE) {
        return Err(S3Error::entity_too_large());
    }
    app.data.check_space(body.expected.unwrap_or(0))?;
    let small = body.expected.is_some_and(|l| l as usize <= app.cfg.inline_threshold);
    let (segments, inline, size, digests) = if allow_inline && small {
        let mut buf = Vec::with_capacity(body.expected.unwrap_or(0) as usize);
        while let Some(b) = body.next().await? {
            if buf.len() + b.len() > app.cfg.inline_threshold {
                return Err(S3Error::incomplete_body());
            }
            hashers.update(&b);
            buf.extend_from_slice(&b);
        }
        let n = buf.len() as u64;
        (Vec::new(), buf, n, hashers.finish())
    } else {
        hashers.data_crc = Some(0);
        let mut w = FileWriter::create(app.data.clone(), hashers).await?;
        while let Some(b) = body.next().await? {
            if w.size + b.len() as u64 > MAX_PUT_SIZE {
                return Err(S3Error::entity_too_large());
            }
            w.push(b).await?;
        }
        let (id, size, digests) = w.finish().await?;
        let crc = digests.data_crc.unwrap_or_default();
        (vec![Segment { id, size, crc, checksum: None }], Vec::new(), size, digests)
    };
    if let Err(e) = r.verify(body.trailers(), &digests) {
        app.data.remove_later(segments.into_iter().map(|s| s.id).collect());
        return Err(e);
    }
    Ok((segments, inline, size, digests))
}

async fn put_object(app: &App, r: &mut Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    bucket_must_exist(app, &bucket)?;
    let cond = WriteCond::from(r);
    let acl = acl::from_headers(&r.parts.headers)?.unwrap_or(acl::PRIVATE);
    let (content_type, headers) = collect_meta_headers(&r.parts.headers);
    let (segments, inline, size, digests) = receive_body(app, r, true, None).await?;
    let etag = digests.etag(false);
    let checksum = stored_checksum(&digests);
    let m = ObjectMeta { size, mtime: util::now_ms(), etag: etag.clone(), content_type, headers, segments, acl, checksum, inline };
    let new_ids = m.file_ids();
    let res = app.meta.write(move |txn| put_object_txn(txn, &bucket, &key, &m, &cond)).await;
    match res {
        Ok(old) => app.data.remove_later(old.map(|o| o.file_ids()).unwrap_or_default()),
        Err(e) => {
            app.data.remove_later(new_ids);
            return Err(e);
        }
    }
    let mut b = Response::builder().header(header::ETAG, format!("\"{etag}\""));
    if digests.checksum.is_some() {
        b = b.header("x-amz-checksum-type", "FULL_OBJECT");
    }
    Ok(checksum_headers(b, &digests).body(Body::Empty).unwrap())
}

fn etag_matches(cond: &str, etag: &str) -> bool {
    cond.split(',').any(|t| {
        let t = t.trim();
        t == "*" || t.trim_start_matches("W/").trim_matches('"') == etag
    })
}

/// Evaluates If-Match / If-None-Match / If-(Un)Modified-Since (RFC 7232 order).
fn check_conditions(r: &Req, prefix: &str, etag: &str, mtime_ms: u64) -> S3Result<()> {
    let h = |n: &str| r.header(&format!("{prefix}{n}"));
    let mtime = mtime_ms / 1000;
    if let Some(v) = h("if-match") {
        if !etag_matches(v, etag) {
            return Err(S3Error::precondition_failed());
        }
    } else if let Some(t) = h("if-unmodified-since").and_then(util::parse_http_date)
        && mtime > t {
            return Err(S3Error::precondition_failed());
        }
    let not_modified = if prefix.is_empty() { S3Error::not_modified() } else { S3Error::precondition_failed() };
    if let Some(v) = h("if-none-match") {
        if etag_matches(v, etag) {
            return Err(not_modified);
        }
    } else if let Some(t) = h("if-modified-since").and_then(util::parse_http_date)
        && mtime <= t {
            return Err(not_modified);
        }
    Ok(())
}

/// Parses a single `bytes=` range. None = ignore header; Some(Err) = unsatisfiable.
pub(crate) fn parse_range(h: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = h.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || size == 0 {
            return Some(Err(()));
        }
        let start = size.saturating_sub(n);
        return Some(Ok((start, size - start)));
    }
    let start: u64 = a.parse().ok()?;
    let end: u64 = if b.is_empty() { u64::MAX } else { b.parse().ok()? };
    if end < start {
        return None;
    }
    if start >= size {
        return Some(Err(()));
    }
    let end = end.min(size - 1);
    Some(Ok((start, end - start + 1)))
}

/// x-amz-copy-source-range: strictly "bytes=first-last" inside the source
/// (unlike GET ranges, it is never clamped).
fn parse_copy_range(h: &str, size: u64) -> Option<(u64, u64)> {
    let (a, b) = h.trim().strip_prefix("bytes=")?.split_once('-')?;
    let (first, last): (u64, u64) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (first <= last && last < size).then_some((first, last - first + 1))
}

async fn get_object(app: &App, r: &Req, bucket: &str, key: &str, head: bool) -> S3Result<Response<Body>> {
    // One retry covers the window where an overwrite deletes the files we just looked up.
    let mut attempt = 0;
    loop {
        let m = app.meta.get_object_with(bucket, key, !head)?;
        match get_object_inner(app, r, &m, head).await {
            Err(e) if e.code == "InternalError" && attempt == 0 => attempt += 1,
            res => return res,
        }
    }
}

async fn get_object_inner(app: &App, r: &Req, m: &ObjectMeta, head: bool) -> S3Result<Response<Body>> {
    let etag_q = format!("\"{}\"", m.etag);
    let last_modified = http_date(m.mtime);
    if let Err(e) = check_conditions(r, "", &m.etag, m.mtime) {
        if e.status == StatusCode::NOT_MODIFIED {
            return Ok(Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, etag_q)
                .header(header::LAST_MODIFIED, last_modified)
                .body(Body::Empty)
                .unwrap());
        }
        return Err(e);
    }

    let mut builder = Response::builder();
    let size = m.size;
    let (status, start, len) = if let Some(pn) = r.q("partNumber") {
        let pn: usize = pn.parse().map_err(|_| S3Error::invalid_argument())?;
        let count = m.segments.len().max(1);
        if pn == 0 || pn > count {
            return Err(S3Error::new("InvalidPart", StatusCode::BAD_REQUEST, "The requested partnumber is not satisfiable"));
        }
        let start: u64 = m.segments.iter().take(pn - 1).map(|s| s.size).sum();
        let len = m.segments.get(pn - 1).map_or(size, |s| s.size);
        builder = builder.header("x-amz-mp-parts-count", count);
        if len > 0 {
            builder = builder.header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, start + len - 1, size));
        }
        (StatusCode::PARTIAL_CONTENT, start, len)
    } else if let Some(range) = r.header("range").and_then(|h| parse_range(h, size)) {
        match range {
            Ok((start, len)) => {
                builder = builder.header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, start + len - 1, size));
                (StatusCode::PARTIAL_CONTENT, start, len)
            }
            Err(()) => {
                return Ok(Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                    .header(header::CONTENT_TYPE, "application/xml")
                    .body(if head { Body::Empty } else {
                        Body::full(format!("{XML_DECL}<Error><Code>InvalidRange</Code><Message>The requested range is not satisfiable</Message></Error>"))
                    })
                    .unwrap());
            }
        }
    } else {
        if m.segments.len() > 1 {
            builder = builder.header("x-amz-mp-parts-count", m.segments.len());
        }
        (StatusCode::OK, 0, size)
    };

    let mut builder = builder
        .status(status)
        .header(header::CONTENT_LENGTH, len)
        .header(header::ETAG, etag_q)
        .header(header::LAST_MODIFIED, last_modified)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_TYPE, m.content_type.as_deref().unwrap_or("binary/octet-stream"));
    // Checksums are only returned on request, and only for exactly what they cover.
    if r.header("x-amz-checksum-mode").is_some_and(|v| v.eq_ignore_ascii_case("ENABLED"))
        && let Some(ck) = &m.checksum
    {
        let value = match r.q("partNumber").and_then(|p| p.parse::<usize>().ok()) {
            Some(pn) if m.segments.len() > 1 => m.segments.get(pn - 1).and_then(|s| s.checksum.clone()),
            Some(_) => Some(ck.value.clone()),
            None if status == StatusCode::OK => Some(ck.value.clone()),
            None => None,
        };
        if let Some(v) = value {
            builder = builder.header(ck.algo.header(), v).header("x-amz-checksum-type", ck.kind.name());
        }
    }
    if let Some(hdrs) = builder.headers_mut() {
        for (k, v) in &m.headers {
            if let (Ok(name), Some(value)) = (HeaderName::from_bytes(k.as_bytes()), util::header_value(v)) {
                hdrs.append(name, value);
            }
        }
    }
    for (q, h) in [
        ("response-content-type", "content-type"),
        ("response-content-disposition", "content-disposition"),
        ("response-content-encoding", "content-encoding"),
        ("response-content-language", "content-language"),
        ("response-cache-control", "cache-control"),
        ("response-expires", "expires"),
    ] {
        if let Some(v) = r.q(q)
            && let (Some(hdrs), Ok(v)) = (builder.headers_mut(), HeaderValue::from_str(v)) {
                hdrs.insert(HeaderName::from_static(h), v);
            }
    }

    let body = if head || len == 0 {
        Body::Empty
    } else if m.segments.is_empty() {
        let data = m
            .inline
            .get(start as usize..(start + len) as usize)
            .ok_or_else(|| S3Error::internal("inline object data is missing or truncated"))?;
        Body::full(Bytes::copy_from_slice(data))
    } else {
        let stream = FileStream::open(app.data.clone(), data::plan_range(&m.segments, start, len)).await?;
        Body::File(Box::new(stream))
    };
    Ok(builder.body(body).unwrap())
}

async fn delete_object(app: &App, bucket: String, key: String) -> S3Result<Response<Body>> {
    let old = app
        .meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            let name = objects_table_name(&bucket);
            let mut t = txn.open_table(objects_table(&name))?;
            let ids = match t.remove(key.as_str())? {
                Some(v) => decode::<ObjectMeta>(v.value())?.file_ids(),
                None => Vec::new(),
            };
            drop(t);
            txn.open_table(objects_table(&meta::data_table_name(&bucket)))?.remove(key.as_str())?;
            meta::index_files(txn, &[], &ids)?;
            Ok(ids)
        })
        .await?;
    app.data.remove_later(old);
    empty(StatusCode::NO_CONTENT)
}

async fn delete_objects(app: &App, r: &mut Req, bucket: String) -> S3Result<Response<Body>> {
    let body = r.read_full(MAX_XML_BODY).await?;
    let doc = std::str::from_utf8(&body).ok().and_then(crate::xml::parse).ok_or_else(S3Error::malformed_xml)?;
    if doc.name != "Delete" {
        return Err(S3Error::malformed_xml());
    }
    let quiet = doc.child_text("Quiet").is_some_and(|q| q.trim().eq_ignore_ascii_case("true"));
    let keys: Vec<String> = doc.children_named("Object").filter_map(|o| o.child_text("Key").map(str::to_string)).collect();
    if keys.len() > 1000 {
        return Err(S3Error::malformed_xml());
    }
    let k2 = keys.clone();
    let ids = app
        .meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            let name = objects_table_name(&bucket);
            let mut t = txn.open_table(objects_table(&name))?;
            let mut ids = Vec::new();
            let mut had_inline = Vec::new();
            for k in &k2 {
                if let Some(v) = t.remove(k.as_str())? {
                    let m = decode::<ObjectMeta>(v.value())?;
                    if m.segments.is_empty() {
                        had_inline.push(k);
                    }
                    ids.extend(m.file_ids());
                }
            }
            drop(t);
            let mut dt = txn.open_table(objects_table(&meta::data_table_name(&bucket)))?;
            for k in had_inline {
                dt.remove(k.as_str())?;
            }
            drop(dt);
            meta::index_files(txn, &[], &ids)?;
            Ok(ids)
        })
        .await?;
    app.data.remove_later(ids);
    let mut x = format!(r#"{XML_DECL}<DeleteResult xmlns="{XMLNS}">"#);
    if !quiet {
        for k in &keys {
            let _ = write!(x, "<Deleted><Key>{}</Key></Deleted>", esc(k));
        }
    }
    x.push_str("</DeleteResult>");
    xml_response(StatusCode::OK, x)
}

fn parse_copy_source(v: &str) -> S3Result<(String, String)> {
    let v = v.split_once("?versionId=").map_or(v, |x| x.0);
    let d = util::percent_decode(v);
    let d = d.strip_prefix('/').unwrap_or(&d);
    match d.split_once('/') {
        Some((b, k)) if !b.is_empty() && !k.is_empty() => Ok((b.to_string(), k.to_string())),
        _ => Err(S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "Invalid copy source.")),
    }
}

async fn copy_object(app: &App, r: &Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    let (sb, sk) = parse_copy_source(r.header("x-amz-copy-source").unwrap_or(""))?;
    let src = app.meta.get_object_with(&sb, &sk, true)?;
    check_conditions(r, "x-amz-copy-source-", &src.etag, src.mtime)?;
    bucket_must_exist(app, &bucket)?;
    let replace = r.header("x-amz-metadata-directive").is_some_and(|d| d.eq_ignore_ascii_case("REPLACE"));
    if sb == bucket && sk == key && !replace {
        return Err(S3Error::new(
            "InvalidRequest",
            StatusCode::BAD_REQUEST,
            "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata.",
        ));
    }
    let (content_type, headers) = if replace { collect_meta_headers(&r.parts.headers) } else { (src.content_type.clone(), src.headers.clone()) };
    let acl = acl::from_headers(&r.parts.headers)?.unwrap_or(acl::PRIVATE);

    // Data files are immutable, so a copy is just a hard link per segment.
    let pairs: Vec<(String, String)> = src.segments.iter().map(|s| (s.id.clone(), util::new_id())).collect();
    let store = app.data.clone();
    let p2 = pairs.clone();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        for (i, (from, to)) in p2.iter().enumerate() {
            if let Err(e) = store.link(from, to) {
                for (_, t) in &p2[..i] {
                    let _ = std::fs::remove_file(store.path(t));
                }
                return Err(e);
            }
        }
        Ok(())
    })
    .await??;
    let segments = src.segments.iter().zip(&pairs).map(|(s, (_, id))| Segment { id: id.clone(), ..s.clone() }).collect();
    let mtime = util::now_ms();
    let m = ObjectMeta { size: src.size, mtime, etag: src.etag.clone(), content_type, headers, segments, acl, checksum: src.checksum.clone(), inline: src.inline };
    let new_ids = m.file_ids();
    match app.meta.write(move |txn| put_object_txn(txn, &bucket, &key, &m, &WriteCond::default())).await {
        Ok(old) => app.data.remove_later(old.map(|o| o.file_ids()).unwrap_or_default()),
        Err(e) => {
            app.data.remove_later(new_ids);
            return Err(e);
        }
    }
    xml_response(
        StatusCode::OK,
        format!(
            r#"{XML_DECL}<CopyObjectResult xmlns="{XMLNS}"><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag></CopyObjectResult>"#,
            iso8601(mtime),
            src.etag
        ),
    )
}

// ---------------------------------------------------------------- multipart

async fn create_multipart(app: &App, r: &Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    bucket_must_exist(app, &bucket)?;
    let (content_type, headers) = collect_meta_headers(&r.parts.headers);
    let id = util::new_id();
    let acl = acl::from_headers(&r.parts.headers)?.unwrap_or(acl::PRIVATE);
    let invalid = |m: &'static str| S3Error::new("InvalidRequest", StatusCode::BAD_REQUEST, m);
    let algo = match r.header("x-amz-checksum-algorithm") {
        Some(a) => Some(Algo::parse(a).ok_or_else(|| invalid("Invalid x-amz-checksum-algorithm"))?),
        None => None,
    };
    let kind = match r.header("x-amz-checksum-type") {
        Some(k) => Some(checksum::Kind::parse(k).ok_or_else(|| invalid("Invalid x-amz-checksum-type"))?),
        None => None,
    };
    let checksum = match (algo, kind) {
        (None, None) => None,
        (None, Some(_)) => return Err(invalid("x-amz-checksum-type requires x-amz-checksum-algorithm")),
        (Some(a), k) => {
            // CRC64NVME only supports FULL_OBJECT; SHA algorithms only COMPOSITE.
            let k = k.unwrap_or(if a == Algo::Crc64Nvme { checksum::Kind::FullObject } else { checksum::Kind::Composite });
            if (a == Algo::Crc64Nvme && k == checksum::Kind::Composite) || (!a.is_crc() && k == checksum::Kind::FullObject) {
                return Err(invalid("The checksum type is not supported for this checksum algorithm"));
            }
            Some((a, k))
        }
    };
    let up = UploadMeta { bucket: bucket.clone(), key: key.clone(), initiated: util::now_ms(), content_type, headers, acl, checksum };
    let id2 = id.clone();
    app.meta
        .write(move |txn| {
            if txn.open_table(BUCKETS)?.get(up.bucket.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            txn.open_table(UPLOADS)?.insert(id2.as_str(), encode(&up).as_slice())?;
            Ok(())
        })
        .await?;
    let mut resp = xml_response(
        StatusCode::OK,
        format!(
            r#"{XML_DECL}<InitiateMultipartUploadResult xmlns="{XMLNS}"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId></InitiateMultipartUploadResult>"#,
            esc(&bucket),
            esc(&key),
            id
        ),
    )?;
    if let Some((a, k)) = checksum {
        let h = resp.headers_mut();
        h.insert("x-amz-checksum-algorithm", HeaderValue::from_static(a.name()));
        h.insert("x-amz-checksum-type", HeaderValue::from_static(k.name()));
    }
    Ok(resp)
}

fn upload_params(app: &App, r: &Req, bucket: &str, key: &str) -> S3Result<(String, u32, UploadMeta)> {
    let upload_id = r.q("uploadId").unwrap_or("").to_string();
    let part: u32 = r.q("partNumber").and_then(|p| p.parse().ok()).ok_or_else(S3Error::invalid_argument)?;
    if !(1..=10000).contains(&part) {
        return Err(S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "Part number must be an integer between 1 and 10000, inclusive."));
    }
    let up = app.meta.get_upload(&upload_id)?;
    if up.bucket != bucket || up.key != key {
        return Err(S3Error::no_such_upload());
    }
    Ok((upload_id, part, up))
}

async fn record_part(app: &App, upload_id: String, part: u32, pm: PartMeta) -> S3Result<()> {
    let new_id = pm.id.clone();
    let res = app
        .meta
        .write(move |txn| {
            if txn.open_table(UPLOADS)?.get(upload_id.as_str())?.is_none() {
                return Err(S3Error::no_such_upload());
            }
            let mut t = txn.open_table(PARTS)?;
            let old_id = match t.insert(meta::part_key(&upload_id, part).as_str(), encode(&pm).as_slice())? {
                Some(v) => Some(decode::<PartMeta>(v.value())?.id),
                None => None,
            };
            drop(t);
            let seg = Segment { id: pm.id.clone(), size: pm.size, crc: pm.crc, checksum: None };
            meta::index_files(txn, &[seg], old_id.as_slice())?;
            Ok(old_id)
        })
        .await;
    match res {
        Ok(old) => {
            app.data.remove_later(old.into_iter().collect());
            Ok(())
        }
        Err(e) => {
            app.data.remove_later(vec![new_id]);
            Err(e)
        }
    }
}

async fn upload_part(app: &App, r: &mut Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    let (upload_id, part, up) = upload_params(app, r, &bucket, &key)?;
    let algo = up.checksum.map(|c| c.0);
    if let (Some(want), Some(got)) = (algo, r.checksum_algo())
        && want != got
    {
        return Err(S3Error::new("InvalidRequest", StatusCode::BAD_REQUEST, "Checksum algorithm does not match the one of the multipart upload"));
    }
    let (segments, _, size, digests) = receive_body(app, r, false, algo).await?;
    let etag = digests.etag(true);
    let seg = segments.into_iter().next().ok_or_else(|| S3Error::internal("no part file"))?;
    let checksum = digests.checksum.as_ref().filter(|(a, _)| Some(*a) == algo).map(|(_, v)| v.clone());
    record_part(app, upload_id, part, PartMeta { size, mtime: util::now_ms(), etag: etag.clone(), id: seg.id, crc: seg.crc, checksum }).await?;
    let b = Response::builder().header(header::ETAG, format!("\"{etag}\""));
    Ok(checksum_headers(b, &digests).body(Body::Empty).unwrap())
}

async fn upload_part_copy(app: &App, r: &Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    let (upload_id, part, up) = upload_params(app, r, &bucket, &key)?;
    let algo = up.checksum.map(|c| c.0);
    let (sb, sk) = parse_copy_source(r.header("x-amz-copy-source").unwrap_or(""))?;
    let src = app.meta.get_object_with(&sb, &sk, true)?;
    check_conditions(r, "x-amz-copy-source-", &src.etag, src.mtime)?;
    let (start, len) = match r.header("x-amz-copy-source-range") {
        Some(h) => parse_copy_range(h, src.size).ok_or_else(S3Error::invalid_range)?,
        None => (0, src.size),
    };
    if len > MAX_PUT_SIZE {
        return Err(S3Error::entity_too_large());
    }
    app.data.check_space(len)?;
    let store = app.data.clone();
    let segs = src.segments;
    let inline = src.inline;
    let (id, md5, crc, checksum) = tokio::task::spawn_blocking(move || data::copy_range_blocking(&store, &segs, &inline, start, len, algo)).await??;
    let etag = hex::encode(md5);
    let mtime = util::now_ms();
    let ck_xml = match (algo, &checksum) {
        (Some(a), Some(v)) => format!("<{t}>{v}</{t}>", t = a.xml_tag()),
        _ => String::new(),
    };
    record_part(app, upload_id, part, PartMeta { size: len, mtime, etag: etag.clone(), id, crc, checksum }).await?;
    xml_response(
        StatusCode::OK,
        format!(
            r#"{XML_DECL}<CopyPartResult xmlns="{XMLNS}"><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag>{ck_xml}</CopyPartResult>"#,
            iso8601(mtime),
            etag
        ),
    )
}

/// A part listed in CompleteMultipartUpload: (number, etag, checksums given).
type WantedPart = (u32, String, Vec<(Algo, String)>);

async fn complete_multipart(app: &App, r: &mut Req, bucket: String, key: String) -> S3Result<Response<Body>> {
    let upload_id = r.q("uploadId").unwrap_or("").to_string();
    let body = r.read_full_with(MAX_XML_BODY, false).await?;
    let doc = std::str::from_utf8(&body).ok().and_then(crate::xml::parse).ok_or_else(S3Error::malformed_xml)?;
    let mut wanted: Vec<WantedPart> = Vec::new();
    for p in doc.children_named("Part") {
        let n: u32 = p.child_text("PartNumber").and_then(|n| n.trim().parse().ok()).ok_or_else(S3Error::malformed_xml)?;
        let etag = p.child_text("ETag").unwrap_or("").trim().trim_matches('"').to_string();
        let cks = checksum::ALL.into_iter().filter_map(|a| p.child_text(a.xml_tag()).map(|v| (a, v.trim().to_string()))).collect();
        wanted.push((n, etag, cks));
    }
    // Object-level checksum the client expects for the result.
    let expected_ck: Option<(Algo, String)> = checksum::ALL.into_iter().find_map(|a| r.header(a.header()).map(|v| (a, v.trim().to_string())));
    if wanted.is_empty() {
        return Err(S3Error::malformed_xml());
    }
    if wanted.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(S3Error::invalid_part_order());
    }
    let mtime = util::now_ms();
    let cond = WriteCond::from(r);
    let (b2, k2) = (bucket.clone(), key.clone());
    let (etag, unused, old, obj_ck) = app
        .meta
        .write(move |txn| {
            let up: UploadMeta = match txn.open_table(UPLOADS)?.get(upload_id.as_str())? {
                Some(v) => decode(v.value())?,
                None => {
                    // A retry of a completion that already succeeded returns the same result.
                    if let Some(v) = txn.open_table(meta::COMPLETED)?.get(upload_id.as_str())? {
                        let c: meta::Completed = decode(v.value())?;
                        if c.bucket == b2 && c.key == k2 {
                            return Ok((c.etag, Vec::new(), None, c.checksum));
                        }
                    }
                    return Err(S3Error::no_such_upload());
                }
            };
            if up.bucket != b2 || up.key != k2 {
                return Err(S3Error::no_such_upload());
            }
            if txn.open_table(BUCKETS)?.get(b2.as_str())?.is_none() {
                return Err(S3Error::no_such_bucket());
            }
            // Validate everything before mutating.
            let parts = meta::parts_in_txn(txn, &upload_id)?;
            let mut md5s = Md5::new();
            let mut segments = Vec::with_capacity(wanted.len());
            let mut size = 0u64;
            for (i, (n, etag, cks)) in wanted.iter().enumerate() {
                let p = parts.get(n).ok_or_else(S3Error::invalid_part)?;
                if &p.etag != etag {
                    return Err(S3Error::invalid_part());
                }
                if i + 1 < wanted.len() && p.size < MIN_PART_SIZE {
                    return Err(S3Error::entity_too_small());
                }
                // A part checksum given by the client must match the stored one.
                if let Some((algo, _)) = up.checksum
                    && cks.iter().any(|(a, v)| *a == algo && Some(v) != p.checksum.as_ref())
                {
                    return Err(S3Error::bad_digest());
                }
                md5s.update(hex::decode(&p.etag).map_err(|_| S3Error::invalid_part())?);
                segments.push(Segment { id: p.id.clone(), size: p.size, crc: p.crc, checksum: p.checksum.clone() });
                size += p.size;
            }
            let etag = format!("{}-{}", hex::encode(md5s.finalize()), wanted.len());
            let obj_ck = match up.checksum {
                Some((algo, kind)) => {
                    let values: Vec<&str> = segments.iter().map(|s| s.checksum.as_deref().unwrap_or("")).collect();
                    let value = match kind {
                        checksum::Kind::Composite => checksum::composite(algo, &values),
                        checksum::Kind::FullObject => {
                            let with_len: Vec<(&str, u64)> = values.iter().zip(&segments).map(|(v, s)| (*v, s.size)).collect();
                            checksum::combine_full(algo, &with_len)
                        }
                    }
                    .ok_or_else(S3Error::bad_digest)?;
                    Some(checksum::Stored { algo, kind, value })
                }
                None => None,
            };
            if let Some((ea, ev)) = &expected_ck {
                // Accept the value with or without the "-N" part-count suffix.
                let ok = obj_ck.as_ref().is_some_and(|c| c.algo == *ea && (c.value == *ev || c.value.split('-').next() == Some(ev.as_str())));
                if !ok {
                    return Err(S3Error::bad_digest());
                }
            }
            let used: std::collections::HashSet<&str> = segments.iter().map(|s| s.id.as_str()).collect();
            let unused: Vec<String> = parts.values().filter(|p| !used.contains(p.id.as_str())).map(|p| p.id.clone()).collect();

            meta::take_parts(txn, &upload_id)?;
            txn.open_table(UPLOADS)?.remove(upload_id.as_str())?;
            meta::index_files(txn, &[], &unused)?;
            let m = ObjectMeta {
                size,
                mtime,
                etag: etag.clone(),
                content_type: up.content_type,
                headers: up.headers,
                segments,
                acl: up.acl,
                checksum: obj_ck.clone(),
                inline: Vec::new(),
            };
            let old = put_object_txn(txn, &b2, &k2, &m, &cond)?;
            let done = meta::Completed { bucket: b2.clone(), key: k2.clone(), etag: etag.clone(), time: mtime, checksum: obj_ck.clone() };
            txn.open_table(meta::COMPLETED)?.insert(upload_id.as_str(), encode(&done).as_slice())?;
            Ok((etag, unused, old, obj_ck))
        })
        .await?;
    let mut garbage = unused;
    if let Some(o) = old {
        garbage.extend(o.file_ids());
    }
    app.data.remove_later(garbage);
    xml_response(
        StatusCode::OK,
        format!(
            r#"{XML_DECL}<CompleteMultipartUploadResult xmlns="{XMLNS}"><Location>/{}/{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>&quot;{}&quot;</ETag>{}</CompleteMultipartUploadResult>"#,
            esc(&bucket),
            esc(&key),
            esc(&bucket),
            esc(&key),
            etag,
            obj_ck.map_or(String::new(), |c| format!("<{t}>{v}</{t}><ChecksumType>{k}</ChecksumType>", t = c.algo.xml_tag(), v = c.value, k = c.kind.name()))
        ),
    )
}

async fn abort_multipart(app: &App, r: &Req, bucket: &str, key: &str) -> S3Result<Response<Body>> {
    let upload_id = r.q("uploadId").unwrap_or("").to_string();
    let (b2, k2) = (bucket.to_string(), key.to_string());
    let ids = app.meta.write(move |txn| meta::abort_upload_txn(txn, &upload_id, Some((&b2, &k2)))).await?;
    app.data.remove_later(ids);
    empty(StatusCode::NO_CONTENT)
}

fn list_parts(app: &App, r: &Req, bucket: &str, key: &str) -> S3Result<Response<Body>> {
    let owner = acl::owner_xml();
    let upload_id = r.q("uploadId").unwrap_or("");
    let up = app.meta.get_upload(upload_id)?;
    if up.bucket != bucket || up.key != key {
        return Err(S3Error::no_such_upload());
    }
    let max: usize = r.q("max-parts").and_then(|v| v.parse().ok()).unwrap_or(1000).min(1000);
    let marker: u32 = r.q("part-number-marker").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut parts = app.meta.list_parts(upload_id, marker, max)?;
    let truncated = parts.len() > max;
    parts.truncate(max);
    let mut x = format!(
        r#"{XML_DECL}<ListPartsResult xmlns="{XMLNS}"><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId><PartNumberMarker>{}</PartNumberMarker>"#,
        esc(bucket),
        esc(key),
        esc(upload_id),
        marker
    );
    if let Some((n, _)) = parts.last() {
        let _ = write!(x, "<NextPartNumberMarker>{n}</NextPartNumberMarker>");
    }
    let _ = write!(x, "<MaxParts>{max}</MaxParts><IsTruncated>{truncated}</IsTruncated>");
    for (n, p) in &parts {
        let ck = match (up.checksum, &p.checksum) {
            (Some((a, _)), Some(v)) => format!("<{t}>{v}</{t}>", t = a.xml_tag()),
            _ => String::new(),
        };
        let _ = write!(
            x,
            "<Part><PartNumber>{}</PartNumber><LastModified>{}</LastModified><ETag>&quot;{}&quot;</ETag><Size>{}</Size>{ck}</Part>",
            n,
            iso8601(p.mtime),
            p.etag,
            p.size
        );
    }
    if let Some((a, k)) = up.checksum {
        let _ = write!(x, "<ChecksumAlgorithm>{}</ChecksumAlgorithm><ChecksumType>{}</ChecksumType>", a.name(), k.name());
    }
    let _ = write!(x, "<StorageClass>STANDARD</StorageClass>{}{owner}</ListPartsResult>", owner.replace("Owner>", "Initiator>"));
    xml_response(StatusCode::OK, x)
}

fn list_uploads(app: &App, r: &Req, bucket: &str) -> S3Result<Response<Body>> {
    let owner = acl::owner_xml();
    bucket_must_exist(app, bucket)?;
    let prefix = r.q("prefix").unwrap_or("");
    let max: usize = r.q("max-uploads").and_then(|v| v.parse().ok()).unwrap_or(1000).min(1000);
    let mut ups = app.meta.list_uploads(bucket, prefix)?;
    let truncated = ups.len() > max;
    ups.truncate(max);
    let mut x = format!(
        r#"{XML_DECL}<ListMultipartUploadsResult xmlns="{XMLNS}"><Bucket>{}</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker><Prefix>{}</Prefix><MaxUploads>{}</MaxUploads><IsTruncated>{}</IsTruncated>"#,
        esc(bucket),
        esc(prefix),
        max,
        truncated
    );
    if truncated
        && let Some((id, u)) = ups.last() {
            let _ = write!(x, "<NextKeyMarker>{}</NextKeyMarker><NextUploadIdMarker>{}</NextUploadIdMarker>", esc(&u.key), id);
        }
    for (id, u) in &ups {
        let _ = write!(
            x,
            "<Upload><Key>{}</Key><UploadId>{}</UploadId>{}{owner}<StorageClass>STANDARD</StorageClass><Initiated>{}</Initiated></Upload>",
            esc(&u.key),
            id,
            owner.replace("Owner>", "Initiator>"),
            iso8601(u.initiated)
        );
    }
    x.push_str("</ListMultipartUploadsResult>");
    xml_response(StatusCode::OK, x)
}

/// GetObjectAttributes: ETag, Checksum, ObjectParts, StorageClass, ObjectSize.
fn get_object_attributes(app: &App, r: &Req, bucket: &str, key: &str) -> S3Result<Response<Body>> {
    let m = app.meta.get_object(bucket, key)?;
    let wanted: Vec<String> = r
        .parts
        .headers
        .get_all("x-amz-object-attributes")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if wanted.is_empty() {
        return Err(S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "x-amz-object-attributes header is required"));
    }
    let has = |a: &str| wanted.iter().any(|w| w == a);
    let mut x = format!(r#"{XML_DECL}<GetObjectAttributesResponse xmlns="{XMLNS}">"#);
    if has("ETag") {
        let _ = write!(x, "<ETag>{}</ETag>", m.etag);
    }
    if has("Checksum")
        && let Some(ck) = &m.checksum
    {
        let _ = write!(x, "<Checksum><{t}>{v}</{t}><ChecksumType>{k}</ChecksumType></Checksum>", t = ck.algo.xml_tag(), v = ck.value, k = ck.kind.name());
    }
    let multipart = m.segments.len() > 1 || (!app.cfg.fast_etag && m.etag.contains('-'));
    if has("ObjectParts") && multipart {
        let max: usize = r.header("x-amz-max-parts").and_then(|v| v.parse().ok()).unwrap_or(1000).clamp(1, 1000);
        let marker: usize = r.header("x-amz-part-number-marker").and_then(|v| v.parse().ok()).unwrap_or(0);
        let parts: Vec<(usize, &Segment)> = m.segments.iter().enumerate().map(|(i, s)| (i + 1, s)).filter(|(n, _)| *n > marker).collect();
        let truncated = parts.len() > max;
        let shown = &parts[..parts.len().min(max)];
        let _ = write!(x, "<ObjectParts><PartsCount>{}</PartsCount><PartNumberMarker>{marker}</PartNumberMarker>", m.segments.len());
        if let Some((n, _)) = shown.last() {
            let _ = write!(x, "<NextPartNumberMarker>{n}</NextPartNumberMarker>");
        }
        let _ = write!(x, "<MaxParts>{max}</MaxParts><IsTruncated>{truncated}</IsTruncated>");
        for (n, s) in shown {
            let _ = write!(x, "<Part><PartNumber>{n}</PartNumber><Size>{}</Size>", s.size);
            if let (Some(ck), Some(v)) = (&m.checksum, &s.checksum) {
                let _ = write!(x, "<{t}>{v}</{t}>", t = ck.algo.xml_tag());
            }
            x.push_str("</Part>");
        }
        x.push_str("</ObjectParts>");
    }
    if has("StorageClass") {
        x.push_str("<StorageClass>STANDARD</StorageClass>");
    }
    if has("ObjectSize") {
        let _ = write!(x, "<ObjectSize>{}</ObjectSize>", m.size);
    }
    x.push_str("</GetObjectAttributesResponse>");
    let mut resp = xml_response(StatusCode::OK, x)?;
    if let Ok(v) = HeaderValue::from_str(&http_date(m.mtime)) {
        resp.headers_mut().insert(header::LAST_MODIFIED, v);
    }
    Ok(resp)
}

// ---------------------------------------------------------------- POST object

fn malformed_post(msg: &'static str) -> S3Error {
    S3Error::new("MalformedPOSTRequest", StatusCode::BAD_REQUEST, msg)
}

/// POST Object: browser-based upload described by a signed policy
/// (multipart/form-data). The file part is streamed straight to disk.
async fn post_object(app: &App, parts: http::request::Parts, body: Incoming, bucket: String) -> S3Result<Response<Body>> {
    use crate::post_policy;
    const IDLE: std::time::Duration = std::time::Duration::from_secs(60);
    let content_type = parts.headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let boundary = multer::parse_boundary(content_type).map_err(|_| malformed_post("Missing multipart boundary."))?;
    let bucket_acl = app.meta.bucket_acl(&bucket)?.ok_or_else(S3Error::no_such_bucket)?;
    let limits = multer::SizeLimit::new().per_field(64 * 1024).for_field("file", MAX_PUT_SIZE + 1);
    let mut form = multer::Multipart::with_constraints(http_body_util::BodyDataStream::new(body), boundary, multer::Constraints::new().size_limit(limits));

    // Fields before the file part (fields after it are ignored, as in S3).
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut file = loop {
        let field = tokio::time::timeout(IDLE, form.next_field())
            .await
            .map_err(|_| S3Error::request_timeout())?
            .map_err(|_| malformed_post("The body of your POST request is not well-formed multipart/form-data."))?
            .ok_or_else(|| S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "POST requires exactly one file upload per request."))?;
        let name = field.name().unwrap_or("").to_ascii_lowercase();
        if name == "file" {
            break field;
        }
        let value = tokio::time::timeout(IDLE, field.text())
            .await
            .map_err(|_| S3Error::request_timeout())?
            .map_err(|_| malformed_post("Form field too large or not well-formed."))?;
        if fields.len() >= 200 {
            return Err(malformed_post("Too many form fields."));
        }
        fields.push((name, value));
    };
    let get = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
    let filename = file.file_name().unwrap_or("").to_string();
    let key = get("key")
        .ok_or_else(|| S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "Bucket POST must contain a field named 'key'."))?
        .replace("${filename}", &filename);
    if key.is_empty() {
        return Err(S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, "User key must have a length greater than 0."));
    }
    if key.len() > 1024 {
        return Err(S3Error::key_too_long());
    }

    let mut range = None;
    if let Some(policy_b64) = get("policy") {
        app.auth.verify_post_policy(&fields, policy_b64)?;
        let json = B64.decode(policy_b64.trim()).map_err(|_| S3Error::new("InvalidPolicyDocument", StatusCode::BAD_REQUEST, "Invalid Policy: Invalid Base64 encoding."))?;
        let policy = post_policy::parse(&json)?;
        let all: Vec<(String, String)> = fields.iter().map(|(k, v)| (k.clone(), if k == "key" { key.clone() } else { v.clone() })).collect();
        post_policy::check(&policy, &all, &bucket, (util::now_ms() / 1000) as i64)?;
        range = post_policy::length_range(&policy);
    } else if !(app.cfg.anonymous || acl::anonymous_can_write(bucket_acl)) {
        return Err(S3Error::access_denied());
    }
    let acl = match get("acl") {
        Some(a) => acl::parse_canned(a)?,
        None => acl::PRIVATE,
    };
    let content_type = get("content-type").map(str::to_string);
    let headers: Vec<(String, String)> = fields
        .iter()
        .filter(|(k, _)| k.starts_with("x-amz-meta-") || STORED_HEADERS.contains(&k.as_str()) || k == "content-encoding")
        .cloned()
        .collect();

    let max = range.map_or(MAX_PUT_SIZE, |(_, max)| max.min(MAX_PUT_SIZE));
    app.data.check_space(0)?;
    let fast = app.cfg.fast_etag;
    let hashers = Hashers {
        md5: (!fast).then(Md5::new),
        sha256: None,
        checksum: checksum::ALL.into_iter().find(|a| get(a.header()).is_some()).map(|a| (a, checksum::Hasher::new(a))),
        xxh3: fast.then(|| Box::new(xxhash_rust::xxh3::Xxh3::new())),
        data_crc: Some(0),
    };
    let mut w = FileWriter::create(app.data.clone(), hashers).await?;
    while let Some(chunk) = tokio::time::timeout(IDLE, file.chunk())
        .await
        .map_err(|_| S3Error::request_timeout())?
        .map_err(|_| malformed_post("The body of your POST request is not well-formed multipart/form-data."))?
    {
        if w.size + chunk.len() as u64 > max {
            return Err(S3Error::entity_too_large());
        }
        w.push(chunk).await?;
    }
    let (id, size, digests) = w.finish().await?;
    if let Some((min, _)) = range
        && size < min
    {
        app.data.remove_later(vec![id]);
        return Err(S3Error::entity_too_small());
    }
    if let Some((algo, got)) = &digests.checksum
        && get(algo.header()).map(str::trim) != Some(got.as_str())
    {
        app.data.remove_later(vec![id]);
        return Err(S3Error::bad_digest());
    }
    let etag = digests.etag(false);
    let segments = vec![Segment { id, size, crc: digests.data_crc.unwrap_or_default(), checksum: None }];
    let checksum = stored_checksum(&digests);
    let m = ObjectMeta { size, mtime: util::now_ms(), etag: etag.clone(), content_type, headers, segments, acl, checksum, inline: Vec::new() };
    let new_ids = m.file_ids();
    let (b2, k2) = (bucket.clone(), key.clone());
    match app.meta.write(move |txn| put_object_txn(txn, &b2, &k2, &m, &WriteCond::default())).await {
        Ok(old) => app.data.remove_later(old.map(|o| o.file_ids()).unwrap_or_default()),
        Err(e) => {
            app.data.remove_later(new_ids);
            return Err(e);
        }
    }

    let location = format!("/{}/{}", bucket, util::aws_uri_encode(&key, false));
    let etag_q = format!("\"{etag}\"");
    if let Some(redirect) = get("success_action_redirect").or_else(|| get("redirect"))
        && (redirect.starts_with("http://") || redirect.starts_with("https://"))
    {
        let sep = if redirect.contains('?') { '&' } else { '?' };
        let target = format!(
            "{redirect}{sep}bucket={}&key={}&etag={}",
            util::aws_uri_encode(&bucket, true),
            util::aws_uri_encode(&key, true),
            util::aws_uri_encode(&etag_q, true)
        );
        if let Ok(v) = HeaderValue::from_str(&target) {
            return Ok(Response::builder().status(StatusCode::SEE_OTHER).header(header::LOCATION, v).header(header::ETAG, etag_q).body(Body::Empty).unwrap());
        }
    }
    let builder = Response::builder().header(header::ETAG, etag_q.as_str()).header(header::LOCATION, location.as_str());
    Ok(match get("success_action_status") {
        Some("200") => builder.status(StatusCode::OK).body(Body::Empty).unwrap(),
        Some("201") => builder
            .status(StatusCode::CREATED)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::full(format!(
                "{XML_DECL}<PostResponse><Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag></PostResponse>",
                esc(&location),
                esc(&bucket),
                esc(&key),
                esc(&etag_q)
            )))
            .unwrap(),
        _ => builder.status(StatusCode::NO_CONTENT).body(Body::Empty).unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-9", 100), Some(Ok((0, 10))));
        assert_eq!(parse_range("bytes=90-", 100), Some(Ok((90, 10))));
        assert_eq!(parse_range("bytes=-10", 100), Some(Ok((90, 10))));
        assert_eq!(parse_range("bytes=95-200", 100), Some(Ok((95, 5))));
        assert_eq!(parse_range("bytes=100-", 100), Some(Err(())));
        assert_eq!(parse_range("bytes=5-1", 100), None);
        assert_eq!(parse_range("items=0-1", 100), None);
    }

    #[test]
    fn copy_ranges() {
        assert_eq!(parse_copy_range("bytes=0-4", 5), Some((0, 5)));
        assert_eq!(parse_copy_range("bytes=0-21", 5), None);
        assert_eq!(parse_copy_range("bytes=-3", 5), None);
        assert_eq!(parse_copy_range("bytes=3-", 5), None);
        assert_eq!(parse_copy_range("bytes=4-2", 5), None);
    }

    #[test]
    fn auth_params() {
        assert!(is_auth_param("X-Amz-Signature") && is_auth_param("x-id") && is_auth_param("Signature") && is_auth_param("content-type"));
        assert!(!is_auth_param("versions") && !is_auth_param("ownershipControls") && !is_auth_param("cors"));
    }

    #[test]
    fn bucket_names() {
        assert!(valid_bucket_name("my-bucket.1"));
        assert!(!valid_bucket_name("My-Bucket"));
        assert!(!valid_bucket_name("ab"));
        assert!(!valid_bucket_name("192.168.1.1"));
        assert!(!valid_bucket_name("a..b"));
    }
}
