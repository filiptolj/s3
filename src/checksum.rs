//! S3 flexible checksums (CRC32, CRC32C, CRC64NVME, SHA1, SHA256): per-object
//! and per-part values, COMPOSITE ("checksum of checksums") and FULL_OBJECT
//! (CRCs combined across parts) multipart checksums.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Algo {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

pub const ALL: [Algo; 5] = [Algo::Crc32, Algo::Crc32c, Algo::Crc64Nvme, Algo::Sha1, Algo::Sha256];

impl Algo {
    pub fn parse(s: &str) -> Option<Algo> {
        Some(match s.trim().to_ascii_uppercase().as_str() {
            "CRC32" => Algo::Crc32,
            "CRC32C" => Algo::Crc32c,
            "CRC64NVME" => Algo::Crc64Nvme,
            "SHA1" => Algo::Sha1,
            "SHA256" => Algo::Sha256,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Algo::Crc32 => "CRC32",
            Algo::Crc32c => "CRC32C",
            Algo::Crc64Nvme => "CRC64NVME",
            Algo::Sha1 => "SHA1",
            Algo::Sha256 => "SHA256",
        }
    }

    /// Request/response header carrying this checksum.
    pub fn header(self) -> &'static str {
        match self {
            Algo::Crc32 => "x-amz-checksum-crc32",
            Algo::Crc32c => "x-amz-checksum-crc32c",
            Algo::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Algo::Sha1 => "x-amz-checksum-sha1",
            Algo::Sha256 => "x-amz-checksum-sha256",
        }
    }

    /// XML element name (e.g. in ListParts / CompleteMultipartUpload).
    pub fn xml_tag(self) -> &'static str {
        match self {
            Algo::Crc32 => "ChecksumCRC32",
            Algo::Crc32c => "ChecksumCRC32C",
            Algo::Crc64Nvme => "ChecksumCRC64NVME",
            Algo::Sha1 => "ChecksumSHA1",
            Algo::Sha256 => "ChecksumSHA256",
        }
    }

    pub fn is_crc(self) -> bool {
        matches!(self, Algo::Crc32 | Algo::Crc32c | Algo::Crc64Nvme)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    FullObject,
    Composite,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_ascii_uppercase().as_str() {
            "FULL_OBJECT" => Some(Kind::FullObject),
            "COMPOSITE" => Some(Kind::Composite),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::FullObject => "FULL_OBJECT",
            Kind::Composite => "COMPOSITE",
        }
    }
}

/// A stored checksum value (base64, as on the wire).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Stored {
    pub algo: Algo,
    pub kind: Kind,
    pub value: String,
}

pub enum Hasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Crc64(crc64fast_nvme::Digest),
    Sha1(Sha1),
    Sha256(Sha256),
}

impl Hasher {
    pub fn new(algo: Algo) -> Hasher {
        match algo {
            Algo::Crc32 => Hasher::Crc32(crc32fast::Hasher::new()),
            Algo::Crc32c => Hasher::Crc32c(0),
            Algo::Crc64Nvme => Hasher::Crc64(crc64fast_nvme::Digest::new()),
            Algo::Sha1 => Hasher::Sha1(Sha1::new()),
            Algo::Sha256 => Hasher::Sha256(Sha256::new()),
        }
    }

    pub fn update(&mut self, b: &[u8]) {
        match self {
            Hasher::Crc32(h) => h.update(b),
            Hasher::Crc32c(c) => *c = crc32c::crc32c_append(*c, b),
            Hasher::Crc64(h) => h.write(b),
            Hasher::Sha1(h) => h.update(b),
            Hasher::Sha256(h) => h.update(b),
        }
    }

    /// Raw (big-endian for CRCs) checksum bytes.
    pub fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
            Hasher::Crc32c(c) => c.to_be_bytes().to_vec(),
            Hasher::Crc64(h) => h.sum64().to_be_bytes().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
        }
    }
}

pub fn encode(raw: &[u8]) -> String {
    B64.encode(raw)
}

pub fn decode(b64: &str) -> Option<Vec<u8>> {
    B64.decode(b64.trim()).ok()
}

/// COMPOSITE checksum: hash of the concatenated raw part checksums, "-N".
pub fn composite(algo: Algo, parts_b64: &[&str]) -> Option<String> {
    let mut h = Hasher::new(algo);
    for p in parts_b64 {
        h.update(&decode(p)?);
    }
    Some(format!("{}-{}", encode(&h.finish()), parts_b64.len()))
}

/// FULL_OBJECT checksum of a multipart object from its parts' CRCs.
pub fn combine_full(algo: Algo, parts: &[(&str, u64)]) -> Option<String> {
    let poly = match algo {
        Algo::Crc32 => 0xEDB8_8320u64,
        Algo::Crc32c => 0x82F6_3B78,
        Algo::Crc64Nvme => 0x9A6C_9329_AC4B_C9B5,
        _ => return None,
    };
    let width = if algo == Algo::Crc64Nvme { 64 } else { 32 };
    let mut acc: Option<u64> = None;
    for (b64, len) in parts {
        let raw = decode(b64)?;
        if raw.len() != width / 8 {
            return None;
        }
        let v = raw.iter().fold(0u64, |a, b| (a << 8) | *b as u64);
        acc = Some(match acc {
            None => v,
            Some(a) => crc_combine(a, v, *len, poly, width),
        });
    }
    let v = acc?;
    let bytes = v.to_be_bytes();
    Some(encode(&bytes[8 - width / 8..]))
}

// zlib's crc32_combine, generalized to reflected CRCs of width 32 or 64.
fn gf2_times(mat: &[u64], mut vec: u64) -> u64 {
    let mut sum = 0;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_square(square: &mut [u64], mat: &[u64]) {
    for n in 0..mat.len() {
        square[n] = gf2_times(mat, mat[n]);
    }
}

fn crc_combine(mut crc1: u64, crc2: u64, mut len2: u64, poly: u64, width: usize) -> u64 {
    if len2 == 0 {
        return crc1;
    }
    let mut even = vec![0u64; width];
    let mut odd = vec![0u64; width];
    // Operator for one zero bit.
    odd[0] = poly;
    let mut row = 1u64;
    for o in odd.iter_mut().skip(1) {
        *o = row;
        row <<= 1;
    }
    gf2_square(&mut even, &odd); // two zero bits
    gf2_square(&mut odd, &even); // four zero bits
    loop {
        gf2_square(&mut even, &odd);
        if len2 & 1 != 0 {
            crc1 = gf2_times(&even, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
        gf2_square(&mut odd, &even);
        if len2 & 1 != 0 {
            crc1 = gf2_times(&odd, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1 ^ crc2
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(algo: Algo, data: &[u8]) -> String {
        let mut h = Hasher::new(algo);
        h.update(data);
        encode(&h.finish())
    }

    #[test]
    fn check_values() {
        let crc64 = u64::from_be_bytes(decode(&digest(Algo::Crc64Nvme, b"123456789")).unwrap().try_into().unwrap());
        assert_eq!(crc64, 0xAE8B_1486_0A79_9888);
        let crc32 = u32::from_be_bytes(decode(&digest(Algo::Crc32, b"123456789")).unwrap().try_into().unwrap());
        assert_eq!(crc32, 0xCBF4_3926);
    }

    #[test]
    fn combine_matches_direct() {
        let a: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        let b: Vec<u8> = (0..3_333u32).map(|i| (i * 13 + 1) as u8).collect();
        let whole = [a.as_slice(), b.as_slice()].concat();
        for algo in [Algo::Crc32, Algo::Crc32c, Algo::Crc64Nvme] {
            let (da, db) = (digest(algo, &a), digest(algo, &b));
            let combined = combine_full(algo, &[(&da, a.len() as u64), (&db, b.len() as u64)]).unwrap();
            assert_eq!(combined, digest(algo, &whole), "{algo:?}");
        }
    }

    /// Values from the Ceph s3-tests multipart checksum tests (5 MiB of 'A', 'B', 'C').
    #[test]
    fn s3_tests_vectors() {
        let size = 5 * 1024 * 1024;
        let parts: Vec<Vec<u8>> = [b'A', b'B', b'C'].iter().map(|c| vec![*c; size]).collect();
        let cks: Vec<String> = parts.iter().map(|p| digest(Algo::Crc32, p)).collect();
        assert_eq!(cks, ["JRTCyQ==", "QoZTGg==", "YAgjqw=="]);
        let refs: Vec<(&str, u64)> = cks.iter().map(|c| (c.as_str(), size as u64)).collect();
        assert_eq!(combine_full(Algo::Crc32, &refs).unwrap(), "WgDhBQ==");
        let sha: Vec<String> = parts.iter().map(|p| digest(Algo::Sha256, p)).collect();
        let sha_refs: Vec<&str> = sha.iter().map(String::as_str).collect();
        assert_eq!(composite(Algo::Sha256, &sha_refs).unwrap(), "uWBwpe1dxI4Vw8Gf0X9ynOdw/SS6VBzfWm9giiv1sf4=-3");
    }
}
