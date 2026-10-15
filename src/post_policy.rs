//! POST Object (browser form upload) policy documents.

use crate::error::{S3Error, S3Result};
use http::StatusCode;

#[derive(Debug, PartialEq)]
pub enum Condition {
    Eq(String, String),
    StartsWith(String, String),
    LengthRange(u64, u64),
}

#[derive(Debug)]
pub struct Policy {
    pub expiration: i64,
    pub conditions: Vec<Condition>,
}

fn invalid(msg: &str) -> S3Error {
    S3Error::new("InvalidPolicyDocument", StatusCode::BAD_REQUEST, format!("Invalid Policy: {msg}"))
}

fn denied(msg: String) -> S3Error {
    S3Error::new("AccessDenied", StatusCode::FORBIDDEN, format!("Invalid according to Policy: {msg}"))
}

/// Parses "2026-10-16T10:00:00Z" / "2026-10-16T10:00:00.000Z" into unix seconds.
fn parse_expiration(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let time = time.split('.').next()?;
    let d: Vec<&str> = date.split('-').collect();
    let t: Vec<&str> = time.split(':').collect();
    if d.len() != 3 || t.len() != 3 || d[0].len() != 4 {
        return None;
    }
    let compact = format!("{}{:0>2}{:0>2}T{:0>2}{:0>2}{:0>2}Z", d[0], d[1], d[2], t[0], t[1], t[2]);
    crate::util::parse_amz_date(&compact)
}

/// Field names in conditions are written as "$name"; matching is case-insensitive.
fn field_name(v: &serde_json::Value) -> S3Result<String> {
    let s = v.as_str().ok_or_else(|| invalid("condition field must be a string"))?;
    let name = s.strip_prefix('$').ok_or_else(|| invalid("condition field must start with $"))?;
    Ok(name.to_ascii_lowercase())
}

pub fn parse(json: &[u8]) -> S3Result<Policy> {
    let doc: serde_json::Value = serde_json::from_slice(json).map_err(|_| invalid("not valid JSON"))?;
    let obj = doc.as_object().ok_or_else(|| invalid("not a JSON object"))?;
    let expiration = obj
        .get("expiration")
        .ok_or_else(|| invalid("missing expiration"))?
        .as_str()
        .and_then(parse_expiration)
        .ok_or_else(|| invalid("invalid expiration"))?;
    let list = obj.get("conditions").and_then(|c| c.as_array()).ok_or_else(|| invalid("missing conditions"))?;
    if list.is_empty() {
        return Err(invalid("empty conditions"));
    }
    let mut conditions = Vec::new();
    for c in list {
        if let Some(map) = c.as_object() {
            for (k, v) in map {
                let v = v.as_str().ok_or_else(|| invalid("condition value must be a string"))?;
                conditions.push(Condition::Eq(k.to_ascii_lowercase(), v.to_string()));
            }
            continue;
        }
        let arr = c.as_array().ok_or_else(|| invalid("condition must be an object or array"))?;
        let op = arr.first().and_then(|o| o.as_str()).ok_or_else(|| invalid("missing condition operator"))?.to_ascii_lowercase();
        match op.as_str() {
            "content-length-range" => {
                if arr.len() != 3 {
                    return Err(invalid("content-length-range needs a minimum and maximum"));
                }
                let n = |v: &serde_json::Value| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()));
                let (min, max) = (n(&arr[1]), n(&arr[2]));
                match (min, max) {
                    (Some(a), Some(b)) if a <= b => conditions.push(Condition::LengthRange(a, b)),
                    _ => return Err(invalid("invalid content-length-range")),
                }
            }
            "eq" | "starts-with" => {
                if arr.len() != 3 {
                    return Err(invalid("condition needs three elements"));
                }
                let field = field_name(&arr[1])?;
                let value = arr[2].as_str().ok_or_else(|| invalid("condition value must be a string"))?.to_string();
                conditions.push(if op == "eq" { Condition::Eq(field, value) } else { Condition::StartsWith(field, value) });
            }
            _ => return Err(invalid("unknown condition operator")),
        }
    }
    if conditions.is_empty() {
        return Err(invalid("empty conditions"));
    }
    Ok(Policy { expiration, conditions })
}

/// Fields that never need to be covered by a condition.
fn exempt(name: &str) -> bool {
    matches!(name, "awsaccesskeyid" | "signature" | "file" | "policy" | "x-amz-signature" | "x-amz-algorithm" | "x-amz-credential" | "x-amz-date" | "x-amz-security-token")
        || name.starts_with("x-ignore-")
        || name.starts_with("x-amz-checksum-")
}

/// Checks the form fields (lower-cased names) against the policy. The
/// "bucket" condition is always evaluated against the actual target
/// `bucket`, never against a client-supplied form field.
pub fn check(policy: &Policy, fields: &[(String, String)], bucket: &str, now: i64) -> S3Result<()> {
    if now > policy.expiration {
        return Err(denied("Policy expired.".into()));
    }
    let get = |name: &str| {
        if name == "bucket" {
            return Some(bucket);
        }
        fields.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    };
    for c in &policy.conditions {
        match c {
            Condition::Eq(f, v) => {
                if get(f) != Some(v.as_str()) {
                    return Err(denied(format!("Policy Condition failed: [\"eq\", \"${f}\", \"{v}\"]")));
                }
            }
            Condition::StartsWith(f, p) => {
                if !get(f).is_some_and(|v| v.starts_with(p.as_str())) {
                    return Err(denied(format!("Policy Condition failed: [\"starts-with\", \"${f}\", \"{p}\"]")));
                }
            }
            Condition::LengthRange(..) => {}
        }
    }
    for (name, _) in fields {
        let covered = policy.conditions.iter().any(|c| matches!(c, Condition::Eq(f, _) | Condition::StartsWith(f, _) if f == name));
        if !covered && !exempt(name) && name != "bucket" {
            return Err(denied(format!("Extra input fields: {name}")));
        }
    }
    Ok(())
}

pub fn length_range(policy: &Policy) -> Option<(u64, u64)> {
    policy.conditions.iter().find_map(|c| match c {
        Condition::LengthRange(a, b) => Some((*a, *b)),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn policy_checks() {
        let p = parse(br#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [{"bucket": "b"}, ["StArTs-WiTh", "$KeY", "up/"], ["content-length-range", 0, 1024]]}"#).unwrap();
        assert_eq!(length_range(&p), Some((0, 1024)));
        check(&p, &fields(&[("key", "up/x"), ("x-ignore-a", "1"), ("awsaccesskeyid", "k")]), "b", 0).unwrap();
        assert!(check(&p, &fields(&[("key", "other")]), "b", 0).is_err());
        assert!(check(&p, &fields(&[("key", "up/x"), ("acl", "public-read")]), "b", 0).is_err());
        assert!(check(&p, &fields(&[("key", "up/x")]), "b", 5_000_000_000).is_err());
        // A policy signed for bucket "b" must not authorize uploads to "evil",
        // even if the form claims bucket=b.
        assert!(check(&p, &fields(&[("bucket", "b"), ("key", "up/x")]), "evil", 0).is_err());
    }

    #[test]
    fn malformed_policies() {
        for doc in [
            &br#"{"conditions": [["eq", "$key", "a"]]}"#[..],
            br#"{"expiration": "2099-01-01T00:00:00Z"}"#,
            br#"{"expiration": "2099-01-01T00:00:00Z", "conditions": []}"#,
            br#"{"expiration": "2099-01-01 00:00:00", "conditions": [["eq", "$key", "a"]]}"#,
            br#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [["content-length-range", -1, 0]]}"#,
            br#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [["content-length-range", 0]]}"#,
            br#"{"Expiration": "2099-01-01T00:00:00Z", "conditions": [["eq", "$key", "a"]]}"#,
            b"not json",
        ] {
            assert!(parse(doc).is_err(), "{}", String::from_utf8_lossy(doc));
        }
        assert_eq!(parse_expiration("2099-01-01T00:00:00.000Z"), parse_expiration("2099-01-01T00:00:00Z"));
    }
}
