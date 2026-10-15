//! AWS Signature Version 4: header auth, presigned URLs and streaming
//! (aws-chunked) chunk/trailer signatures.

use crate::error::{S3Error, S3Result};
use crate::util::{aws_uri_encode, constant_time_eq, parse_amz_date, percent_decode};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const MAX_SKEW_SECS: i64 = 15 * 60;

type HmacSha256 = Hmac<Sha256>;

const V2_SUBRESOURCES: &[&str] = &[
    "acl", "cors", "delete", "lifecycle", "location", "logging", "notification", "partNumber", "policy",
    "requestPayment", "response-cache-control", "response-content-disposition", "response-content-encoding",
    "response-content-language", "response-content-type", "response-expires", "restore", "tagging", "torrent",
    "uploadId", "uploads", "versionId", "versioning", "versions", "website",
];

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac key");
    m.update(data);
    m.finalize().into_bytes().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub enum Payload {
    /// Body is not covered by the signature.
    Unsigned,
    /// Body must hash to this value.
    Sha256([u8; 32]),
    /// aws-chunked encoding, optionally with per-chunk signatures and trailers.
    Streaming { signer: Option<ChunkSigner> },
}

pub struct ChunkSigner {
    key: [u8; 32],
    timestamp: String,
    scope: String,
    prev: String,
}

impl ChunkSigner {
    pub fn verify_chunk(&mut self, chunk_sha256_hex: &str, sig: &str) -> bool {
        let sts = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.timestamp, self.scope, self.prev, EMPTY_SHA256, chunk_sha256_hex
        );
        self.check(&sts, sig)
    }

    pub fn verify_trailer(&mut self, canonical_trailers: &[u8], sig: &str) -> bool {
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.timestamp,
            self.scope,
            self.prev,
            sha256_hex(canonical_trailers)
        );
        self.check(&sts, sig)
    }

    fn check(&mut self, sts: &str, sig: &str) -> bool {
        let calc = hex::encode(hmac(&self.key, sts.as_bytes()));
        let ok = constant_time_eq(calc.as_bytes(), sig.as_bytes());
        self.prev = calc;
        ok
    }
}

/// True if the request carries any form of credentials (header or presigned).
pub fn has_credentials(parts: &http::request::Parts, query: &[(String, String)]) -> bool {
    parts.headers.contains_key("authorization")
        || query.iter().any(|(k, _)| k == "X-Amz-Algorithm" || k == "X-Amz-Credential" || k == "AWSAccessKeyId" || k == "Signature")
}

/// Payload handling for an unauthenticated request.
pub fn anonymous_payload(parts: &http::request::Parts) -> S3Result<Payload> {
    payload_mode(header(parts, "x-amz-content-sha256").unwrap_or("UNSIGNED-PAYLOAD"), None)
}

pub struct Auth {
    /// access key -> secret key (hot-reloadable)
    creds: RwLock<HashMap<String, String>>,
    anonymous: bool,
    sigv2: bool,
    keys: Mutex<HashMap<String, [u8; 32]>>,
}

struct SigParams<'a> {
    access_key: &'a str,
    date: &'a str,
    region: &'a str,
    service: &'a str,
    signed_headers: &'a str,
    signature: &'a str,
    timestamp: &'a str,
}

impl Auth {
    pub fn new(creds: Vec<(String, String)>, anonymous: bool, sigv2: bool) -> Auth {
        Auth { creds: RwLock::new(creds.into_iter().collect()), anonymous, sigv2, keys: Mutex::new(HashMap::new()) }
    }

    /// Replaces the credential set (e.g. on SIGHUP); returns the number of keys.
    pub fn set_credentials(&self, creds: Vec<(String, String)>) -> usize {
        let n = creds.len();
        *self.creds.write().unwrap() = creds.into_iter().collect();
        self.keys.lock().unwrap().clear();
        n
    }

    fn secret_for(&self, access_key: &str) -> S3Result<String> {
        self.creds.read().unwrap().get(access_key).cloned().ok_or_else(S3Error::invalid_access_key)
    }

    fn signing_key(&self, secret: &str, access_key: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
        let cache_key = format!("{access_key}/{date}/{region}/{service}");
        if let Some(k) = self.keys.lock().unwrap().get(&cache_key) {
            return *k;
        }
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
        let k_region = hmac(&k_date, region.as_bytes());
        let k_service = hmac(&k_region, service.as_bytes());
        let k = hmac(&k_service, b"aws4_request");
        let mut cache = self.keys.lock().unwrap();
        if cache.len() > 64 {
            cache.clear();
        }
        cache.insert(cache_key, k);
        k
    }

    /// Authenticates the request and returns how its payload must be handled.
    pub fn verify(&self, parts: &http::request::Parts, query: &[(String, String)]) -> S3Result<Payload> {
        let content_sha = header(parts, "x-amz-content-sha256");
        if let Some(rest) = header(parts, "authorization").and_then(|a| a.strip_prefix("AWS4-HMAC-SHA256")) {
            let mut credential = None;
            let mut signed_headers = None;
            let mut signature = None;
            for kv in rest.split(',') {
                match kv.trim().split_once('=') {
                    Some(("Credential", v)) => credential = Some(v),
                    Some(("SignedHeaders", v)) => signed_headers = Some(v),
                    Some(("Signature", v)) => signature = Some(v),
                    _ => {}
                }
            }
            let (Some(credential), Some(signed_headers), Some(signature)) = (credential, signed_headers, signature) else {
                return Err(S3Error::new("AuthorizationHeaderMalformed", http::StatusCode::BAD_REQUEST, "The authorization header is malformed."));
            };
            let timestamp = header(parts, "x-amz-date")
                .or_else(|| header(parts, "date"))
                .ok_or_else(S3Error::access_denied)?;
            let t = parse_amz_date(timestamp).ok_or_else(S3Error::access_denied)?;
            if (now_secs() - t).abs() > MAX_SKEW_SECS {
                return Err(S3Error::request_time_skewed());
            }
            let p = parse_credential(credential, signed_headers, signature, timestamp)?;
            let payload_hash = content_sha.unwrap_or("UNSIGNED-PAYLOAD");
            let key = self.check_signature(parts, query, &p, payload_hash, false)?;
            return payload_mode(
                payload_hash,
                Some(ChunkSigner {
                    key,
                    timestamp: timestamp.to_string(),
                    scope: format!("{}/{}/{}/aws4_request", p.date, p.region, p.service),
                    prev: p.signature.to_string(),
                }),
            );
        }

        let q = |name: &str| query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        if q("X-Amz-Algorithm").is_some() {
            if q("X-Amz-Algorithm") != Some("AWS4-HMAC-SHA256") {
                return Err(S3Error::access_denied());
            }
            let (Some(credential), Some(timestamp), Some(expires), Some(signed_headers), Some(signature)) = (
                q("X-Amz-Credential"),
                q("X-Amz-Date"),
                q("X-Amz-Expires"),
                q("X-Amz-SignedHeaders"),
                q("X-Amz-Signature"),
            ) else {
                return Err(S3Error::access_denied());
            };
            let t = parse_amz_date(timestamp).ok_or_else(S3Error::access_denied)?;
            let expires: i64 = expires.parse().map_err(|_| S3Error::access_denied())?;
            let now = now_secs();
            if !(1..=604800).contains(&expires) {
                return Err(S3Error::expired_presign());
            }
            if now > t + expires {
                return Err(S3Error::expired_presign());
            }
            if t - now > MAX_SKEW_SECS {
                return Err(S3Error::request_time_skewed());
            }
            let p = parse_credential(credential, signed_headers, signature, timestamp)?;
            let payload_hash = content_sha.unwrap_or("UNSIGNED-PAYLOAD");
            self.check_signature(parts, query, &p, payload_hash, true)?;
            return payload_mode(payload_hash, None);
        }

        // Legacy SigV2 (still the default for boto3 presigned URLs).
        if self.sigv2
            && let Some(authz) = header(parts, "authorization").and_then(|a| a.strip_prefix("AWS "))
        {
            let (ak, sig) = authz
                .split_once(':')
                .ok_or_else(|| S3Error::new("InvalidArgument", http::StatusCode::BAD_REQUEST, "AWS authorization header is invalid. Expected AwsAccessKeyId:signature"))?;
            let date = if parts.headers.contains_key("x-amz-date") { "" } else { header(parts, "date").unwrap_or("") };
            // Missing or unparseable (incl. pre-epoch) dates are denied; valid but distant ones are "skewed".
            let t = header(parts, "x-amz-date").or(Some(date)).and_then(crate::util::parse_http_date).ok_or_else(S3Error::access_denied)?;
            if (now_secs() - t as i64).abs() > MAX_SKEW_SECS {
                return Err(S3Error::request_time_skewed());
            }
            self.check_v2(parts, query, ak, sig, date)?;
            return payload_mode(content_sha.unwrap_or("UNSIGNED-PAYLOAD"), None);
        }
        if self.sigv2
            && let (Some(ak), Some(sig), Some(expires)) = (q("AWSAccessKeyId"), q("Signature"), q("Expires"))
        {
            let exp: i64 = expires.parse().map_err(|_| S3Error::access_denied())?;
            if now_secs() > exp {
                return Err(S3Error::expired_presign());
            }
            self.check_v2(parts, query, ak, sig, expires)?;
            return payload_mode(content_sha.unwrap_or("UNSIGNED-PAYLOAD"), None);
        }

        if self.anonymous {
            return payload_mode(content_sha.unwrap_or("UNSIGNED-PAYLOAD"), None);
        }
        Err(S3Error::access_denied())
    }

    /// Verifies the signature of a POST Object policy. `fields` are the form
    /// fields with lower-cased names.
    pub fn verify_post_policy(&self, fields: &[(String, String)], policy_b64: &str) -> S3Result<()> {
        let get = |n: &str| fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str());
        let missing = || S3Error::new("InvalidArgument", http::StatusCode::BAD_REQUEST, "POST requires a policy signature");
        if let Some(algo) = get("x-amz-algorithm") {
            if algo != "AWS4-HMAC-SHA256" {
                return Err(S3Error::new("InvalidArgument", http::StatusCode::BAD_REQUEST, "Unsupported x-amz-algorithm"));
            }
            let (credential, signature) = (get("x-amz-credential").ok_or_else(missing)?, get("x-amz-signature").ok_or_else(missing)?);
            let mut it = credential.splitn(5, '/');
            let (Some(ak), Some(date), Some(region), Some(service), Some("aws4_request")) = (it.next(), it.next(), it.next(), it.next(), it.next()) else {
                return Err(S3Error::new("InvalidArgument", http::StatusCode::BAD_REQUEST, "Malformed x-amz-credential"));
            };
            let secret = self.secret_for(ak)?;
            let key = self.signing_key(&secret, ak, date, region, service);
            let calc = hex::encode(hmac(&key, policy_b64.as_bytes()));
            if !constant_time_eq(calc.as_bytes(), signature.as_bytes()) {
                return Err(S3Error::signature_mismatch());
            }
            return Ok(());
        }
        let (ak, signature) = (get("awsaccesskeyid").ok_or_else(missing)?, get("signature").ok_or_else(missing)?);
        if !self.sigv2 {
            return Err(S3Error::access_denied());
        }
        let secret = self.secret_for(ak)?;
        let mut m = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes()).expect("hmac key");
        m.update(policy_b64.as_bytes());
        let calc = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, m.finalize().into_bytes());
        if !constant_time_eq(calc.as_bytes(), signature.as_bytes()) {
            return Err(S3Error::signature_mismatch());
        }
        Ok(())
    }

    fn check_v2(&self, parts: &http::request::Parts, query: &[(String, String)], ak: &str, sig: &str, date: &str) -> S3Result<()> {
        let secret = self.secret_for(ak)?;
        let h = |n: &str| header(parts, n).unwrap_or("");
        let mut sts = format!("{}\n{}\n{}\n{}\n", parts.method.as_str(), h("content-md5"), h("content-type"), date);
        let mut amz: Vec<(String, String)> = Vec::new();
        for (name, value) in &parts.headers {
            let n = name.as_str();
            if n.starts_with("x-amz-") {
                let v = String::from_utf8_lossy(value.as_bytes()).trim().to_string();
                match amz.iter_mut().find(|(k, _)| k == n) {
                    Some((_, prev)) => {
                        prev.push(',');
                        prev.push_str(&v);
                    }
                    None => amz.push((n.to_string(), v)),
                }
            }
        }
        amz.sort();
        for (k, v) in &amz {
            sts.push_str(&format!("{k}:{v}\n"));
        }
        sts.push_str(parts.uri.path());
        let mut sub: Vec<&(String, String)> = query.iter().filter(|(k, _)| V2_SUBRESOURCES.contains(&k.as_str())).collect();
        sub.sort();
        for (i, (k, v)) in sub.iter().enumerate() {
            sts.push(if i == 0 { '?' } else { '&' });
            sts.push_str(k);
            if !v.is_empty() {
                sts.push('=');
                sts.push_str(v);
            }
        }
        let mut m = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes()).expect("hmac key");
        m.update(sts.as_bytes());
        let calc = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, m.finalize().into_bytes());
        if !constant_time_eq(calc.as_bytes(), sig.as_bytes()) {
            return Err(S3Error::signature_mismatch());
        }
        Ok(())
    }

    fn check_signature(
        &self,
        parts: &http::request::Parts,
        query: &[(String, String)],
        p: &SigParams,
        payload_hash: &str,
        presigned: bool,
    ) -> S3Result<[u8; 32]> {
        let secret = self.secret_for(p.access_key)?;
        let canonical = canonical_request(parts, query, p.signed_headers, payload_hash, presigned);
        let scope = format!("{}/{}/{}/aws4_request", p.date, p.region, p.service);
        let sts = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", p.timestamp, scope, sha256_hex(canonical.as_bytes()));
        let key = self.signing_key(&secret, p.access_key, p.date, p.region, p.service);
        let calc = hex::encode(hmac(&key, sts.as_bytes()));
        if !constant_time_eq(calc.as_bytes(), p.signature.as_bytes()) {
            return Err(S3Error::signature_mismatch());
        }
        Ok(key)
    }
}

fn now_secs() -> i64 {
    (crate::util::now_ms() / 1000) as i64
}

fn header<'a>(parts: &'a http::request::Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

fn parse_credential<'a>(
    credential: &'a str,
    signed_headers: &'a str,
    signature: &'a str,
    timestamp: &'a str,
) -> S3Result<SigParams<'a>> {
    let mut it = credential.splitn(5, '/');
    let (Some(access_key), Some(date), Some(region), Some(service), Some("aws4_request")) =
        (it.next(), it.next(), it.next(), it.next(), it.next())
    else {
        return Err(S3Error::new("AuthorizationHeaderMalformed", http::StatusCode::BAD_REQUEST, "The credential is malformed."));
    };
    if !timestamp.starts_with(date) {
        return Err(S3Error::signature_mismatch());
    }
    Ok(SigParams { access_key, date, region, service, signed_headers, signature, timestamp })
}

fn payload_mode(hash: &str, signer: Option<ChunkSigner>) -> S3Result<Payload> {
    Ok(match hash {
        "UNSIGNED-PAYLOAD" => Payload::Unsigned,
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER" => Payload::Streaming { signer: None },
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" => Payload::Streaming { signer },
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => Payload::Streaming { signer },
        h => {
            let mut out = [0u8; 32];
            hex::decode_to_slice(h, &mut out).map_err(|_| {
                S3Error::new("InvalidArgument", http::StatusCode::BAD_REQUEST, "x-amz-content-sha256 must be UNSIGNED-PAYLOAD, a streaming mode or a valid sha256 value.")
            })?;
            Payload::Sha256(out)
        }
    })
}

fn canonical_request(
    parts: &http::request::Parts,
    query: &[(String, String)],
    signed_headers: &str,
    payload_hash: &str,
    presigned: bool,
) -> String {
    let uri = aws_uri_encode(&percent_decode(parts.uri.path()), false);

    let mut q: Vec<(String, String)> = query
        .iter()
        .filter(|(k, _)| !(presigned && k == "X-Amz-Signature"))
        .map(|(k, v)| (aws_uri_encode(k, true), aws_uri_encode(v, true)))
        .collect();
    q.sort();
    let mut cq = String::new();
    for (i, (k, v)) in q.iter().enumerate() {
        if i > 0 {
            cq.push('&');
        }
        cq.push_str(k);
        cq.push('=');
        cq.push_str(v);
    }

    let mut ch = String::new();
    for name in signed_headers.split(';') {
        ch.push_str(name);
        ch.push(':');
        let mut first = true;
        for v in parts.headers.get_all(name) {
            if !first {
                ch.push(',');
            }
            first = false;
            let v = String::from_utf8_lossy(v.as_bytes());
            let mut prev_space = false;
            for c in v.trim().chars() {
                if c == ' ' {
                    if !prev_space {
                        ch.push(' ');
                    }
                    prev_space = true;
                } else {
                    ch.push(c);
                    prev_space = false;
                }
            }
        }
        if name == "host" && parts.headers.get("host").is_none()
            && let Some(a) = parts.uri.authority() {
                ch.push_str(a.as_str());
            }
        ch.push('\n');
    }

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        parts.method.as_str(),
        uri,
        cq,
        ch,
        signed_headers,
        payload_hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Example from the AWS docs ("GET Object" with range).
    #[test]
    fn aws_example_get_object() {
        let auth = Auth::new(vec![("AKIAIOSFODNN7EXAMPLE".into(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into())], false, true);
        let req = http::Request::builder()
            .method("GET")
            .uri("/test.txt")
            .header("host", "examplebucket.s3.amazonaws.com")
            .header("range", "bytes=0-9")
            .header("x-amz-content-sha256", EMPTY_SHA256)
            .header("x-amz-date", "20130524T000000Z")
            .body(())
            .unwrap();
        let (parts, _) = req.into_parts();
        let p = SigParams {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            date: "20130524",
            region: "us-east-1",
            service: "s3",
            signed_headers: "host;range;x-amz-content-sha256;x-amz-date",
            signature: "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
            timestamp: "20130524T000000Z",
        };
        auth.check_signature(&parts, &[], &p, EMPTY_SHA256, false).unwrap();
    }

    // Example from the AWS docs (streaming upload, first chunk signature).
    #[test]
    fn aws_example_chunk_signature() {
        let auth = Auth::new(vec![("AKIAIOSFODNN7EXAMPLE".into(), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into())], false, true);
        let mut s = ChunkSigner {
            key: auth.signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE", "20130524", "us-east-1", "s3"),
            timestamp: "20130524T000000Z".into(),
            scope: "20130524/us-east-1/s3/aws4_request".into(),
            prev: "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9".into(),
        };
        let chunk = vec![b'a'; 65536];
        assert!(s.verify_chunk(&sha256_hex(&chunk), "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648"));
    }
}
