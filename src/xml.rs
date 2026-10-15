//! Minimal XML reader for the small request documents S3 clients send
//! (CompleteMultipartUpload, Delete, CreateBucketConfiguration).

#[derive(Debug, Default)]
pub struct Elem {
    pub name: String,
    pub text: String,
    pub children: Vec<Elem>,
}

impl Elem {
    pub fn child(&self, name: &str) -> Option<&Elem> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Elem> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_str())
    }
}

pub fn parse(input: &str) -> Option<Elem> {
    let mut p = Parser { s: input.as_bytes(), i: 0 };
    p.skip_misc();
    let e = p.element(0)?;
    Some(e)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn starts(&self, pat: &str) -> bool {
        self.s[self.i..].starts_with(pat.as_bytes())
    }

    fn skip_until(&mut self, pat: &str) -> Option<()> {
        let pos = find(&self.s[self.i..], pat.as_bytes())?;
        self.i += pos + pat.len();
        Some(())
    }

    fn skip_ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    /// Skips whitespace, the XML declaration, comments and doctype.
    fn skip_misc(&mut self) {
        loop {
            self.skip_ws();
            if self.starts("<?") {
                if self.skip_until("?>").is_none() {
                    return;
                }
            } else if self.starts("<!--") {
                if self.skip_until("-->").is_none() {
                    return;
                }
            } else if self.starts("<!") && !self.starts("<![CDATA[") {
                if self.skip_until(">").is_none() {
                    return;
                }
            } else {
                return;
            }
        }
    }

    fn name(&mut self) -> Option<String> {
        let start = self.i;
        while self.i < self.s.len() && !self.s[self.i].is_ascii_whitespace() && !matches!(self.s[self.i], b'>' | b'/') {
            self.i += 1;
        }
        let full = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if full.is_empty() {
            return None;
        }
        // Strip namespace prefix.
        Some(full.rsplit(':').next().unwrap_or(full).to_string())
    }

    fn element(&mut self, depth: usize) -> Option<Elem> {
        if depth > 16 || !self.starts("<") {
            return None;
        }
        self.i += 1;
        let name = self.name()?;
        // Skip attributes (quoted values may contain '>').
        let mut quote = 0u8;
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            match c {
                b'"' | b'\'' if quote == 0 => quote = c,
                c if c == quote => quote = 0,
                b'/' if quote == 0 && self.s.get(self.i) == Some(&b'>') => {
                    self.i += 1;
                    return Some(Elem { name, ..Default::default() });
                }
                b'>' if quote == 0 => break,
                _ => {}
            }
        }
        let mut elem = Elem { name, ..Default::default() };
        let mut raw = Vec::new();
        loop {
            if self.i >= self.s.len() {
                return None;
            }
            if self.starts("</") {
                self.skip_until(">")?;
                elem.text = decode_entities(std::str::from_utf8(&raw).ok()?);
                return Some(elem);
            } else if self.starts("<![CDATA[") {
                self.i += 9;
                let end = find(&self.s[self.i..], b"]]>")?;
                // Escape so the later entity decoding leaves the content intact.
                raw.extend_from_slice(String::from_utf8_lossy(&self.s[self.i..self.i + end]).replace('&', "&amp;").as_bytes());
                self.i += end + 3;
            } else if self.starts("<!--") {
                // An unterminated comment is an error (skipping would not advance).
                self.skip_until("-->")?;
            } else if self.starts("<?") {
                self.skip_until("?>")?;
            } else if self.starts("<") {
                elem.children.push(self.element(depth + 1)?);
            } else {
                raw.push(self.s[self.i]);
                self.i += 1;
            }
        }
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('&') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let Some(end) = rest.find(';') else { break };
        let ent = &rest[1..end];
        let decoded = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
            e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_complete() {
        let x = r#"<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Part><ETag>"abc"</ETag><PartNumber>1</PartNumber></Part>
  <Part><PartNumber>2</PartNumber><ETag>&quot;def&quot;</ETag></Part>
</CompleteMultipartUpload>"#;
        let e = parse(x).unwrap();
        let parts: Vec<_> = e.children_named("Part").map(|p| (p.child_text("PartNumber").unwrap().to_string(), p.child_text("ETag").unwrap().to_string())).collect();
        assert_eq!(parts, vec![("1".into(), "\"abc\"".into()), ("2".into(), "\"def\"".into())]);
    }

    #[test]
    fn parse_delete() {
        let x = "<Delete><Quiet>true</Quiet><Object><Key>a&amp;b</Key></Object><Object><Key><![CDATA[x<y]]></Key></Object></Delete>";
        let e = parse(x).unwrap();
        assert_eq!(e.child_text("Quiet"), Some("true"));
        let keys: Vec<_> = e.children_named("Object").map(|o| o.child_text("Key").unwrap()).collect();
        assert_eq!(keys, vec!["a&b", "x<y"]);
    }
}
