use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 128-bit random id rendered as 32 lowercase hex chars.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom");
    hex::encode(b)
}

static REQ_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn request_id() -> String {
    let n = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:X}{:08X}", now_ms(), n as u32)
}

// Howard Hinnant's civil date algorithms.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + d as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// 2006-01-02T15:04:05.000Z
pub fn iso8601(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let (y, mo, d) = civil_from_days(secs.div_euclid(86400));
    let rem = secs.rem_euclid(86400);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        mo,
        d,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60,
        ms % 1000
    )
}

pub fn http_date(ms: u64) -> String {
    httpdate::fmt_http_date(UNIX_EPOCH + std::time::Duration::from_millis(ms))
}

/// Parses an HTTP date. RFC 1123 dates are parsed leniently (the weekday is
/// not validated, as S3 does); other formats fall back to httpdate.
/// Dates before the epoch yield None.
pub fn parse_http_date(s: &str) -> Option<u64> {
    parse_rfc1123_lenient(s).or_else(|| {
        httpdate::parse_http_date(s)
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
    })
}

fn parse_rfc1123_lenient(s: &str) -> Option<u64> {
    // "Tue, 07 Jul 2030 21:53:04 GMT"
    let rest = s.trim().split_once(", ")?.1;
    let mut it = rest.split(' ');
    let day: u32 = it.next()?.parse().ok()?;
    let mon = it.next()?;
    let year: i64 = it.next()?.parse().ok()?;
    let time = it.next()?;
    if it.next()? != "GMT" || it.next().is_some() {
        return None;
    }
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let m = MONTHS.iter().position(|x| *x == mon)? as u32 + 1;
    let mut t = time.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi, se) = (t.next()??, t.next()??, t.next()??);
    if t.next().is_some() || !(1..=31).contains(&day) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let secs = days_from_civil(year, m, day) * 86400 + h * 3600 + mi * 60 + se;
    (secs >= 0).then_some(secs as u64)
}

/// Parses an ISO8601 basic timestamp (20130524T000000Z) into unix seconds.
pub fn parse_amz_date(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s.get(r)?.parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (h, mi, se) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days_from_civil(y, mo as u32, d as u32) * 86400 + h * 3600 + mi * 60 + se)
}

fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~')
}

/// URI encoding as specified by AWS SigV4 (RFC 3986 unreserved set kept).
pub fn aws_uri_encode(s: &str, encode_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len() + 8);
    for &c in s.as_bytes() {
        if is_unreserved(c) || (c == b'/' && !encode_slash) {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(HEX[(c >> 4) as usize] as char);
            out.push(HEX[(c & 15) as usize] as char);
        }
    }
    out
}

pub fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Decodes a query component (`+` means space in form encoding).
pub fn query_decode(s: &str) -> String {
    if s.contains('+') {
        percent_decode(&s.replace('+', " "))
    } else {
        percent_decode(s)
    }
}

pub fn xml_escape(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.bytes().any(|c| matches!(c, b'<' | b'>' | b'&' | b'"' | b'\'') || c < 0x20) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if (c as u32) < 0x20 => out.push_str(&format!("&#x{:X};", c as u32)),
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Header bytes -> String, one char per byte (lossless for non-UTF-8 values).
pub fn header_to_string(b: &[u8]) -> String {
    b.iter().map(|&c| c as char).collect()
}

/// Inverse of `header_to_string`.
pub fn header_value(s: &str) -> Option<http::HeaderValue> {
    let bytes: Vec<u8> = s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).collect();
    http::HeaderValue::from_bytes(&bytes).ok()
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn raise_fd_limit() {
    unsafe {
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 && rl.rlim_cur < rl.rlim_max {
            rl.rlim_cur = rl.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_roundtrip() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_700_000_000_123), "2023-11-14T22:13:20.123Z");
        assert_eq!(parse_amz_date("20231114T221320Z"), Some(1_700_000_000));
    }

    #[test]
    fn http_dates() {
        // Weekday is not validated (2010-07-07 was a Wednesday).
        assert_eq!(parse_http_date("Tue, 07 Jul 2010 21:53:04 GMT"), Some(1278539584));
        assert_eq!(parse_http_date("Wed, 07 Jul 2010 21:53:04 GMT"), Some(1278539584));
        assert_eq!(parse_http_date("Tue, 07 Jul 1950 21:53:04 GMT"), None);
        assert_eq!(parse_http_date("Bad Date"), None);
        assert_eq!(parse_http_date(""), None);
    }

    #[test]
    fn uri_encode() {
        assert_eq!(aws_uri_encode("a b/c+d~", false), "a%20b/c%2Bd~");
        assert_eq!(aws_uri_encode("a/b", true), "a%2Fb");
    }
}
