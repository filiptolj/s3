//! Bucket CORS configuration (Put/Get/DeleteBucketCors), preflight
//! (OPTIONS) handling and CORS headers on regular responses.

use crate::error::{S3Error, S3Result};
use crate::util::xml_escape as esc;
use crate::xml;
use http::{HeaderMap, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};

const METHODS: [&str; 5] = ["GET", "PUT", "POST", "DELETE", "HEAD"];

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CorsRule {
    pub id: Option<String>,
    pub origins: Vec<String>,
    pub methods: Vec<String>,
    pub headers: Vec<String>,
    pub expose: Vec<String>,
    pub max_age: Option<u32>,
}

/// Parses and validates a CORSConfiguration document.
pub fn parse(body: &str) -> S3Result<Vec<CorsRule>> {
    let doc = xml::parse(body).ok_or_else(S3Error::malformed_xml)?;
    if doc.name != "CORSConfiguration" {
        return Err(S3Error::malformed_xml());
    }
    let texts = |e: &xml::Elem, n: &str| -> Vec<String> { e.children_named(n).map(|c| c.text.trim().to_string()).collect() };
    let mut rules = Vec::new();
    for r in doc.children_named("CORSRule") {
        let rule = CorsRule {
            id: r.child_text("ID").map(|s| s.trim().to_string()),
            origins: texts(r, "AllowedOrigin"),
            methods: texts(r, "AllowedMethod"),
            headers: texts(r, "AllowedHeader"),
            expose: texts(r, "ExposeHeader"),
            max_age: match r.child_text("MaxAgeSeconds") {
                Some(v) => Some(v.trim().parse().map_err(|_| S3Error::malformed_xml())?),
                None => None,
            },
        };
        if rule.origins.is_empty() || rule.methods.is_empty() {
            return Err(S3Error::malformed_xml());
        }
        if let Some(m) = rule.methods.iter().find(|m| !METHODS.contains(&m.as_str())) {
            return Err(S3Error::new("InvalidRequest", StatusCode::BAD_REQUEST, format!("Found unsupported HTTP method in CORS config. Unsupported method is {m}")));
        }
        if rule.origins.iter().chain(&rule.headers).any(|o| o.matches('*').count() > 1) {
            return Err(S3Error::new("InvalidRequest", StatusCode::BAD_REQUEST, "AllowedOrigin and AllowedHeader may contain at most one wildcard"));
        }
        rules.push(rule);
    }
    if rules.is_empty() || rules.len() > 100 {
        return Err(S3Error::malformed_xml());
    }
    Ok(rules)
}

pub fn to_xml(rules: &[CorsRule]) -> String {
    let mut x = String::from(r#"<?xml version="1.0" encoding="UTF-8"?><CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#);
    for r in rules {
        x.push_str("<CORSRule>");
        if let Some(id) = &r.id {
            x.push_str(&format!("<ID>{}</ID>", esc(id)));
        }
        for (tag, vals) in [("AllowedOrigin", &r.origins), ("AllowedMethod", &r.methods), ("AllowedHeader", &r.headers), ("ExposeHeader", &r.expose)] {
            for v in vals {
                x.push_str(&format!("<{tag}>{}</{tag}>", esc(v)));
            }
        }
        if let Some(a) = r.max_age {
            x.push_str(&format!("<MaxAgeSeconds>{a}</MaxAgeSeconds>"));
        }
        x.push_str("</CORSRule>");
    }
    x.push_str("</CORSConfiguration>");
    x
}

/// Matches `value` against a pattern with at most one `*` wildcard.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == value,
        Some((pre, suf)) => value.len() >= pre.len() + suf.len() && value.starts_with(pre) && value.ends_with(suf),
    }
}

/// The first rule allowing `origin`, `method` and every requested header.
pub fn find<'a>(rules: &'a [CorsRule], origin: &str, method: &str, req_headers: &[String]) -> Option<&'a CorsRule> {
    rules.iter().find(|r| {
        r.origins.iter().any(|o| wildcard_match(o, origin))
            && r.methods.iter().any(|m| m == method)
            && req_headers.iter().all(|h| r.headers.iter().any(|p| wildcard_match(&p.to_ascii_lowercase(), &h.to_ascii_lowercase())))
    })
}

/// Requested headers from `Access-Control-Request-Headers`.
pub fn requested_headers(h: &HeaderMap) -> Vec<String> {
    h.get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// Adds the CORS response headers for a matched rule.
pub fn apply(out: &mut HeaderMap, rule: &CorsRule, origin: &str, req_headers: &[String], preflight: bool) {
    let set = |out: &mut HeaderMap, name: &'static str, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            out.insert(name, v);
        }
    };
    let wildcard = rule.origins.iter().any(|o| o == "*");
    set(out, "access-control-allow-origin", if wildcard { "*" } else { origin });
    if !wildcard {
        set(out, "access-control-allow-credentials", "true");
    }
    set(out, "access-control-allow-methods", &rule.methods.join(", "));
    if !rule.expose.is_empty() {
        set(out, "access-control-expose-headers", &rule.expose.join(", "));
    }
    if preflight {
        if !req_headers.is_empty() {
            set(out, "access-control-allow-headers", &req_headers.join(", "));
        }
        if let Some(a) = rule.max_age {
            set(out, "access-control-max-age", &a.to_string());
        }
    }
    out.append(http::header::VARY, HeaderValue::from_static("Origin"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*suffix", "foo.suffix"));
        assert!(wildcard_match("start*end", "startend"));
        assert!(wildcard_match("start*end", "start12end"));
        assert!(!wildcard_match("start*end", "0start12end"));
        assert!(!wildcard_match("start*end", "startdend0"));
        assert!(wildcard_match("prefix*", "prefix"));
        assert!(!wildcard_match("prefix*", "bla.prefix"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("ab*ba", "aba"));
    }

    #[test]
    fn parse_roundtrip() {
        let x = "<CORSConfiguration><CORSRule><AllowedOrigin>*.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedHeader>*</AllowedHeader><MaxAgeSeconds>60</MaxAgeSeconds></CORSRule></CORSConfiguration>";
        let rules = parse(x).unwrap();
        assert_eq!(parse(&to_xml(&rules)).unwrap()[0].origins, vec!["*.example.com"]);
        assert!(find(&rules, "a.example.com", "GET", &["X-Custom".into()]).is_some());
        assert!(find(&rules, "a.example.com", "PUT", &[]).is_none());
        assert!(parse("<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod></CORSRule></CORSConfiguration>").is_err());
    }
}
