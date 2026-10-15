//! Canned ACLs for buckets and objects (single-account model).
//!
//! All configured credentials belong to one account (the owner), so the only
//! grants that change behaviour are the ones to the AllUsers and
//! AuthenticatedUsers groups. Those map onto the canned ACLs below, which
//! control anonymous (unauthenticated) access.

use crate::error::{S3Error, S3Result};
use crate::xml;
use http::{HeaderMap, StatusCode};

pub const PRIVATE: u8 = 0;
pub const PUBLIC_READ: u8 = 1;
pub const PUBLIC_READ_WRITE: u8 = 2;
pub const AUTHENTICATED_READ: u8 = 3;
/// All grants removed (even the owner's explicit one); behaves like private.
pub const NO_GRANTS: u8 = 4;

const DEFAULT_OWNER_ID: &str = "02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4";
const DEFAULT_OWNER_NAME: &str = "s3";
static OWNER: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();

/// Sets the account's canonical id and display name (once, at startup).
pub fn set_owner(id: Option<String>, name: Option<String>) {
    let _ = OWNER.set((id.unwrap_or_else(|| DEFAULT_OWNER_ID.into()), name.unwrap_or_else(|| DEFAULT_OWNER_NAME.into())));
}

pub fn owner_id() -> &'static str {
    OWNER.get().map_or(DEFAULT_OWNER_ID, |o| o.0.as_str())
}

fn owner_name() -> &'static str {
    OWNER.get().map_or(DEFAULT_OWNER_NAME, |o| o.1.as_str())
}
const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
const AUTH_USERS: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

pub fn anonymous_can_read(acl: u8) -> bool {
    acl == PUBLIC_READ || acl == PUBLIC_READ_WRITE
}

pub fn anonymous_can_write(acl: u8) -> bool {
    acl == PUBLIC_READ_WRITE
}

fn invalid(msg: &'static str) -> S3Error {
    S3Error::new("InvalidArgument", StatusCode::BAD_REQUEST, msg)
}

pub fn parse_canned(s: &str) -> S3Result<u8> {
    Ok(match s.trim() {
        "private" | "bucket-owner-read" | "bucket-owner-full-control" | "aws-exec-read" | "log-delivery-write" => PRIVATE,
        "public-read" => PUBLIC_READ,
        "public-read-write" => PUBLIC_READ_WRITE,
        "authenticated-read" => AUTHENTICATED_READ,
        _ => return Err(invalid("Invalid canned ACL.")),
    })
}

#[derive(Default)]
struct Grants {
    all_read: bool,
    all_write: bool,
    auth_read: bool,
}

impl Grants {
    fn add(&mut self, grantee: Grantee, permission: &str) -> S3Result<()> {
        let (read, write) = match permission {
            "READ" => (true, false),
            "WRITE" => (false, true),
            "FULL_CONTROL" => (true, true),
            "READ_ACP" | "WRITE_ACP" => (false, false),
            _ => return Err(S3Error::malformed_xml()),
        };
        match grantee {
            Grantee::Owner => {}
            Grantee::AllUsers => {
                self.all_read |= read;
                self.all_write |= write;
            }
            Grantee::AuthenticatedUsers => self.auth_read |= read,
        }
        Ok(())
    }

    fn canned(&self) -> u8 {
        match (self.all_read, self.all_write, self.auth_read) {
            (_, true, _) => PUBLIC_READ_WRITE,
            (true, false, _) => PUBLIC_READ,
            (false, false, true) => AUTHENTICATED_READ,
            _ => PRIVATE,
        }
    }
}

enum Grantee {
    Owner,
    AllUsers,
    AuthenticatedUsers,
}

fn grantee_from_uri(uri: &str) -> S3Result<Grantee> {
    match uri {
        ALL_USERS => Ok(Grantee::AllUsers),
        AUTH_USERS => Ok(Grantee::AuthenticatedUsers),
        _ => Err(invalid("Invalid group uri")),
    }
}

fn grantee_from_id(id: &str) -> S3Result<Grantee> {
    if id == owner_id() {
        Ok(Grantee::Owner)
    } else {
        Err(invalid("Invalid id"))
    }
}

fn unresolvable_email() -> S3Error {
    S3Error::new("UnresolvableGrantByEmailAddress", StatusCode::BAD_REQUEST, "The e-mail address you provided does not match any account on record.")
}

/// ACL requested via `x-amz-acl` or `x-amz-grant-*` headers, if any.
pub fn from_headers(h: &HeaderMap) -> S3Result<Option<u8>> {
    let hv = |n: &str| h.get(n).and_then(|v| v.to_str().ok());
    let grant_headers = [
        ("x-amz-grant-read", "READ"),
        ("x-amz-grant-write", "WRITE"),
        ("x-amz-grant-full-control", "FULL_CONTROL"),
        ("x-amz-grant-read-acp", "READ_ACP"),
        ("x-amz-grant-write-acp", "WRITE_ACP"),
    ];
    let has_grants = grant_headers.iter().any(|(n, _)| h.contains_key(*n));
    if let Some(canned) = hv("x-amz-acl") {
        if has_grants {
            return Err(invalid("Specifying both Canned ACLs and Header Grants is not allowed"));
        }
        return parse_canned(canned).map(Some);
    }
    if !has_grants {
        return Ok(None);
    }
    let mut g = Grants::default();
    for (name, perm) in grant_headers {
        let Some(v) = hv(name) else { continue };
        for item in v.split(',') {
            let (kind, val) = item.trim().split_once('=').ok_or_else(|| invalid("Invalid grant header"))?;
            let val = val.trim().trim_matches('"');
            let grantee = match kind.trim().to_ascii_lowercase().as_str() {
                "uri" => grantee_from_uri(val)?,
                "id" => grantee_from_id(val)?,
                "emailaddress" => return Err(unresolvable_email()),
                _ => return Err(invalid("Invalid grant header")),
            };
            g.add(grantee, perm)?;
        }
    }
    Ok(Some(g.canned()))
}

/// ACL from an AccessControlPolicy XML document.
pub fn from_xml(body: &str) -> S3Result<u8> {
    let doc = xml::parse(body).ok_or_else(S3Error::malformed_xml)?;
    if doc.name != "AccessControlPolicy" {
        return Err(S3Error::malformed_xml());
    }
    let list = doc.child("AccessControlList").ok_or_else(S3Error::malformed_xml)?;
    let mut g = Grants::default();
    if list.children_named("Grant").next().is_none() {
        return Ok(NO_GRANTS);
    }
    for grant in list.children_named("Grant") {
        let grantee = grant.child("Grantee").ok_or_else(S3Error::malformed_xml)?;
        let who = if let Some(uri) = grantee.child_text("URI") {
            grantee_from_uri(uri.trim())?
        } else if let Some(id) = grantee.child_text("ID") {
            grantee_from_id(id.trim())?
        } else if grantee.child("EmailAddress").is_some() {
            return Err(unresolvable_email());
        } else {
            return Err(S3Error::malformed_xml());
        };
        g.add(who, grant.child_text("Permission").unwrap_or("").trim())?;
    }
    Ok(g.canned())
}

pub fn owner_xml() -> String {
    format!("<Owner><ID>{}</ID><DisplayName>{}</DisplayName></Owner>", crate::util::xml_escape(owner_id()), crate::util::xml_escape(owner_name()))
}

pub fn to_xml(acl: u8) -> String {
    let group = |uri: &str, perm: &str| {
        format!(
            r#"<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>{uri}</URI></Grantee><Permission>{perm}</Permission></Grant>"#
        )
    };
    // Group grants first, then the owner (the order AWS returns).
    let mut grants = String::new();
    match acl {
        PUBLIC_READ => grants.push_str(&group(ALL_USERS, "READ")),
        PUBLIC_READ_WRITE => {
            grants.push_str(&group(ALL_USERS, "READ"));
            grants.push_str(&group(ALL_USERS, "WRITE"));
        }
        AUTHENTICATED_READ => grants.push_str(&group(AUTH_USERS, "READ")),
        _ => {}
    }
    if acl != NO_GRANTS {
        grants.push_str(&format!(
        r#"<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>{}</ID><DisplayName>{}</DisplayName></Grantee><Permission>FULL_CONTROL</Permission></Grant>"#,
        crate::util::xml_escape(owner_id()),
        crate::util::xml_escape(owner_name())
    ));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{}<AccessControlList>{grants}</AccessControlList></AccessControlPolicy>"#,
        owner_xml()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_xml() {
        for acl in [PRIVATE, PUBLIC_READ, PUBLIC_READ_WRITE, AUTHENTICATED_READ, NO_GRANTS] {
            assert_eq!(from_xml(&to_xml(acl)).unwrap(), acl);
        }
    }

    #[test]
    fn headers() {
        let mut h = HeaderMap::new();
        assert_eq!(from_headers(&h).unwrap(), None);
        h.insert("x-amz-acl", "public-read".parse().unwrap());
        assert_eq!(from_headers(&h).unwrap(), Some(PUBLIC_READ));
        h.insert("x-amz-acl", "bogus".parse().unwrap());
        assert!(from_headers(&h).is_err());
        let mut h = HeaderMap::new();
        h.insert("x-amz-grant-read", format!("uri=\"{ALL_USERS}\", id=\"{}\"", owner_id()).parse().unwrap());
        assert_eq!(from_headers(&h).unwrap(), Some(PUBLIC_READ));
        h.insert("x-amz-grant-read", "id=\"someone-else\"".parse().unwrap());
        assert!(from_headers(&h).is_err());
    }
}
