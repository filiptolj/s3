//! On-disk format version of the data directory (`format.json`).

use std::io::Write;
use std::path::Path;

pub const VERSION: u32 = 1;
const FILE: &str = "format.json";

/// Verifies the data directory's format version, or stamps a new directory.
pub fn check_or_init(dir: &Path) -> Result<(), String> {
    let path = dir.join(FILE);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let v = parse_version(&s).ok_or_else(|| format!("{} is malformed", path.display()))?;
            if v != VERSION {
                return Err(format!(
                    "data directory {} has format version {v}, but this build supports version {VERSION}",
                    dir.display()
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if dir.join("meta.redb").exists() {
                return Err(format!(
                    "{} contains data but no {FILE}; it was created by an incompatible build",
                    dir.display()
                ));
            }
            let tmp = dir.join(format!("{FILE}.tmp"));
            let write = || -> std::io::Result<()> {
                let mut f = std::fs::File::create(&tmp)?;
                writeln!(f, "{{\"format\": \"s3\", \"version\": {VERSION}}}")?;
                f.sync_all()?;
                std::fs::rename(&tmp, &path)?;
                std::fs::File::open(dir)?.sync_all()
            };
            write().map_err(|e| format!("cannot write {}: {e}", path.display()))
        }
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

fn parse_version(s: &str) -> Option<u32> {
    let rest = &s[s.find("\"version\"")? + 9..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version(r#"{"format": "s3", "version": 1}"#), Some(1));
        assert_eq!(parse_version(r#"{"version":12}"#), Some(12));
        assert_eq!(parse_version("{}"), None);
    }

    #[test]
    fn init_then_check() {
        let dir = std::env::temp_dir().join(format!("s3-format-{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        check_or_init(&dir).unwrap();
        check_or_init(&dir).unwrap();
        std::fs::write(dir.join(FILE), r#"{"version": 99}"#).unwrap();
        assert!(check_or_init(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
