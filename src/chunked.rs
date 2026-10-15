//! Request body reader with zero-copy aws-chunked decoding.

use crate::auth::{ChunkSigner, Payload};
use crate::error::{S3Error, S3Result};
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

const MAX_LINE: usize = 8192;
/// A request body that sends nothing for this long is aborted.
const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

enum State {
    Header,
    Data(u64),
    DataCrlf(u8),
    Trailer,
    Done,
}

pub struct ChunkedDecoder {
    state: State,
    line: Vec<u8>,
    signer: Option<ChunkSigner>,
    chunk_sig: Option<String>,
    chunk_hash: Option<Sha256>,
    trailer_canonical: Vec<u8>,
    pub trailers: Vec<(String, String)>,
}

impl ChunkedDecoder {
    pub fn new(signer: Option<ChunkSigner>) -> Self {
        ChunkedDecoder {
            state: State::Header,
            line: Vec::new(),
            signer,
            chunk_sig: None,
            chunk_hash: None,
            trailer_canonical: Vec::new(),
            trailers: Vec::new(),
        }
    }

    /// Takes one line (without CRLF) from `input`, buffering partial lines.
    fn take_line(&mut self, input: &mut Bytes) -> S3Result<Option<String>> {
        match input.iter().position(|&c| c == b'\n') {
            None => {
                self.line.extend_from_slice(input);
                input.clear();
                if self.line.len() > MAX_LINE {
                    return Err(S3Error::invalid_request());
                }
                Ok(None)
            }
            Some(pos) => {
                self.line.extend_from_slice(&input[..pos]);
                input.advance(pos + 1);
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                let s = String::from_utf8(std::mem::take(&mut self.line)).map_err(|_| S3Error::invalid_request())?;
                Ok(Some(s))
            }
        }
    }

    pub fn feed(&mut self, mut input: Bytes, out: &mut VecDeque<Bytes>) -> S3Result<()> {
        while !input.is_empty() {
            match self.state {
                State::Header => {
                    let Some(line) = self.take_line(&mut input)? else { return Ok(()) };
                    let (size, ext) = match line.split_once(';') {
                        Some((s, e)) => (s, Some(e)),
                        None => (line.as_str(), None),
                    };
                    let size = u64::from_str_radix(size.trim(), 16).map_err(|_| S3Error::invalid_request())?;
                    self.chunk_sig = ext.and_then(|e| e.trim().strip_prefix("chunk-signature=")).map(str::to_string);
                    if self.signer.is_some() && self.chunk_sig.is_none() {
                        return Err(S3Error::signature_mismatch());
                    }
                    if size == 0 {
                        self.verify_chunk(crate::auth::EMPTY_SHA256.to_string())?;
                        self.state = State::Trailer;
                    } else {
                        self.chunk_hash = self.signer.as_ref().map(|_| Sha256::new());
                        self.state = State::Data(size);
                    }
                }
                State::Data(rem) => {
                    let n = (rem as usize).min(input.len());
                    let data = input.split_to(n);
                    if let Some(h) = &mut self.chunk_hash {
                        h.update(&data);
                    }
                    out.push_back(data);
                    if rem - n as u64 == 0 {
                        if let Some(h) = self.chunk_hash.take() {
                            self.verify_chunk(hex::encode(h.finalize()))?;
                        }
                        self.state = State::DataCrlf(0);
                    } else {
                        self.state = State::Data(rem - n as u64);
                    }
                }
                State::DataCrlf(i) => {
                    let c = input[0];
                    input.advance(1);
                    match (i, c) {
                        (0, b'\r') => self.state = State::DataCrlf(1),
                        (0, b'\n') | (1, b'\n') => self.state = State::Header,
                        _ => return Err(S3Error::invalid_request()),
                    }
                }
                State::Trailer => {
                    let Some(line) = self.take_line(&mut input)? else { return Ok(()) };
                    if line.is_empty() {
                        self.state = State::Done;
                        continue;
                    }
                    let (name, value) = line.split_once(':').ok_or_else(S3Error::invalid_request)?;
                    let (name, value) = (name.trim().to_ascii_lowercase(), value.trim().to_string());
                    if name == "x-amz-trailer-signature" {
                        if let Some(s) = &mut self.signer
                            && !s.verify_trailer(&self.trailer_canonical, &value) {
                                return Err(S3Error::signature_mismatch());
                            }
                    } else {
                        self.trailer_canonical.extend_from_slice(format!("{name}:{value}\n").as_bytes());
                        self.trailers.push((name, value));
                    }
                }
                State::Done => {
                    input.clear();
                }
            }
        }
        Ok(())
    }

    fn verify_chunk(&mut self, hash_hex: String) -> S3Result<()> {
        if let (Some(s), Some(sig)) = (&mut self.signer, &self.chunk_sig)
            && !s.verify_chunk(&hash_hex, sig) {
                return Err(S3Error::signature_mismatch());
            }
        Ok(())
    }

    #[cfg(test)]
    pub fn is_done(&self) -> bool {
        self.finish().is_ok()
    }

    fn finish(&self) -> S3Result<()> {
        match self.state {
            State::Done => Ok(()),
            // Tolerate a missing final CRLF after the last chunk/trailers.
            State::Trailer if self.line.is_empty() => Ok(()),
            _ => Err(S3Error::incomplete_body()),
        }
    }
}

pub struct BodyReader {
    body: Incoming,
    decoder: Option<ChunkedDecoder>,
    queue: VecDeque<Bytes>,
    eof: bool,
    pub received: u64,
    pub expected: Option<u64>,
}

impl BodyReader {
    pub fn new(body: Incoming, payload: &mut Payload, headers: &http::HeaderMap) -> BodyReader {
        let num = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse::<u64>().ok());
        let (decoder, expected) = match payload {
            Payload::Streaming { signer, .. } => (Some(ChunkedDecoder::new(signer.take())), num("x-amz-decoded-content-length")),
            _ => (None, num("content-length")),
        };
        BodyReader { body, decoder, queue: VecDeque::new(), eof: false, received: 0, expected }
    }

    pub async fn next(&mut self) -> S3Result<Option<Bytes>> {
        loop {
            if let Some(b) = self.queue.pop_front() {
                self.received += b.len() as u64;
                if self.expected.is_some_and(|e| self.received > e) {
                    return Err(S3Error::incomplete_body());
                }
                return Ok(Some(b));
            }
            if self.eof {
                return Ok(None);
            }
            let frame = tokio::time::timeout(BODY_IDLE_TIMEOUT, self.body.frame())
                .await
                .map_err(|_| S3Error::request_timeout())?;
            match frame {
                None => {
                    self.eof = true;
                    if let Some(d) = &self.decoder {
                        d.finish()?;
                    }
                    if self.expected.is_some_and(|e| e != self.received) {
                        return Err(S3Error::incomplete_body());
                    }
                }
                Some(Err(_)) => return Err(S3Error::incomplete_body()),
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        match &mut self.decoder {
                            Some(d) => d.feed(data, &mut self.queue)?,
                            None => self.queue.push_back(data),
                        }
                    }
                }
            }
        }
    }

    pub fn trailers(&self) -> &[(String, String)] {
        self.decoder.as_ref().map_or(&[], |d| &d.trailers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_unsigned_trailer() {
        let mut d = ChunkedDecoder::new(None);
        let mut q = VecDeque::new();
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n";
        // Feed byte-by-byte-ish to exercise partial states.
        for c in raw.chunks(3) {
            d.feed(Bytes::copy_from_slice(c), &mut q).unwrap();
        }
        d.finish().unwrap();
        let data: Vec<u8> = q.iter().flat_map(|b| b.iter().copied()).collect();
        assert_eq!(data, b"hello world");
        assert_eq!(d.trailers, vec![("x-amz-checksum-crc32".to_string(), "DUoRhQ==".to_string())]);
    }
}
