//! Minimal **canonical (deterministic) CBOR** codec for the subset the IdentiKey-auth
//! protocol uses: unsigned integers, byte strings, text strings, definite-length
//! arrays, and text-keyed maps.
//!
//! It implements the dCBOR determinism rules (RFC 8949 §4.2.1) documented in
//! `docs/standards/dcbor-determinism.md`:
//!   - integers in smallest form,
//!   - definite-length items,
//!   - map keys sorted by **encoded-byte lexicographic order**, no duplicates,
//!   - no floats / no indefinite lengths / no tags.
//!
//! Decoding is **strict**: any non-canonical encoding (non-minimal integer,
//! out-of-order or duplicate map keys, trailing bytes, unsupported major type) is
//! rejected. This matters for a security protocol — a peer must not be able to send a
//! second, differently-encoded form of the same logical value.
//!
//! This is intentionally hand-rolled and dependency-free so the encoding the protocol
//! signs over is small, auditable, and fully under our control. It is isolated here so
//! it can be swapped for the `dcbor` crate if cross-implementation interop testing ever
//! calls for it.

use crate::error::{AuthError, Result};

/// A CBOR value in the supported subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Map with text keys. Stored unsorted; canonical order is applied on encode and
    /// enforced on decode.
    Map(Vec<(String, Value)>),
}

impl Value {
    /// Serialize to canonical (deterministic) CBOR bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }

    /// Parse canonical CBOR bytes, requiring the entire input to be consumed.
    pub fn from_bytes(data: &[u8]) -> Result<Value> {
        let mut cur = Cursor { data, pos: 0 };
        let v = cur.read_value()?;
        if cur.pos != data.len() {
            return Err(AuthError::Cbor("trailing bytes after top-level value".into()));
        }
        Ok(v)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Value::Uint(n) => encode_head(0, *n, out),
            Value::Bytes(b) => {
                encode_head(2, b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Value::Text(s) => {
                encode_head(3, s.len() as u64, out);
                out.extend_from_slice(s.as_bytes());
            }
            Value::Array(items) => {
                encode_head(4, items.len() as u64, out);
                for it in items {
                    it.encode(out);
                }
            }
            Value::Map(entries) => {
                // Canonical order: sort by the encoded bytes of each key.
                let mut encoded: Vec<(Vec<u8>, &Value)> = entries
                    .iter()
                    .map(|(k, v)| {
                        let mut kb = Vec::new();
                        encode_head(3, k.len() as u64, &mut kb);
                        kb.extend_from_slice(k.as_bytes());
                        (kb, v)
                    })
                    .collect();
                encoded.sort_by(|a, b| a.0.cmp(&b.0));
                encode_head(5, entries.len() as u64, out);
                for (kb, v) in encoded {
                    out.extend_from_slice(&kb);
                    v.encode(out);
                }
            }
        }
    }

    // ---- typed accessors used by the protocol structs ----

    pub fn as_uint(&self) -> Result<u64> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(AuthError::Cbor("expected uint".into())),
        }
    }
    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(AuthError::Cbor("expected byte string".into())),
        }
    }
    pub fn as_text(&self) -> Result<&str> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(AuthError::Cbor("expected text string".into())),
        }
    }
    /// Look up a key in a map value.
    pub fn get(&self, key: &str) -> Result<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v)
                .ok_or(AuthError::MissingField(leak(key))),
            _ => Err(AuthError::Cbor("expected map".into())),
        }
    }
    /// Optional map lookup (returns None if the key is absent).
    pub fn get_opt(&self, key: &str) -> Result<Option<&Value>> {
        match self {
            Value::Map(entries) => Ok(entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)),
            _ => Err(AuthError::Cbor("expected map".into())),
        }
    }
}

/// Build a map `Value` from `(key, value)` pairs.
pub fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

// MissingField wants &'static str; protocol field names are all string literals, so we
// only ever pass literals here. Fall back to a generic label otherwise.
fn leak(key: &str) -> &'static str {
    match key {
        "v" => "v",
        "aud" => "aud",
        "nonce" => "nonce",
        "iat" => "iat",
        "exp" => "exp",
        "chal" => "chal",
        "pub" => "pub",
        "sig" => "sig",
        "pqpub" => "pqpub",
        "pqsig" => "pqsig",
        "alg" => "alg",
        "key" => "key",
        _ => "field",
    }
}

/// Encode a CBOR head: major type (high 3 bits) + argument in smallest form.
fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    let mt = major << 5;
    if n < 24 {
        out.push(mt | n as u8);
    } else if n <= u8::MAX as u64 {
        out.push(mt | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(mt | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(mt | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| AuthError::Cbor("length overflow".into()))?;
        if end > self.data.len() {
            return Err(AuthError::Cbor("unexpected end of input".into()));
        }
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Read a head, returning (major, argument). Enforces smallest-form encoding.
    fn read_head(&mut self) -> Result<(u8, u64)> {
        let first = self.take(1)?[0];
        let major = first >> 5;
        let info = first & 0x1f;
        let arg = match info {
            0..=23 => info as u64,
            24 => {
                let b = self.take(1)?[0] as u64;
                if b < 24 {
                    return Err(AuthError::Cbor("non-minimal integer (1-byte)".into()));
                }
                b
            }
            25 => {
                let b = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if b <= u8::MAX as u64 {
                    return Err(AuthError::Cbor("non-minimal integer (2-byte)".into()));
                }
                b
            }
            26 => {
                let b = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if b <= u16::MAX as u64 {
                    return Err(AuthError::Cbor("non-minimal integer (4-byte)".into()));
                }
                b
            }
            27 => {
                let b = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if b <= u32::MAX as u64 {
                    return Err(AuthError::Cbor("non-minimal integer (8-byte)".into()));
                }
                b
            }
            _ => return Err(AuthError::Cbor("indefinite-length or reserved encoding".into())),
        };
        Ok((major, arg))
    }

    fn read_value(&mut self) -> Result<Value> {
        let (major, arg) = self.read_head()?;
        match major {
            0 => Ok(Value::Uint(arg)),
            2 => {
                let b = self.take(arg as usize)?;
                Ok(Value::Bytes(b.to_vec()))
            }
            3 => {
                let b = self.take(arg as usize)?;
                let s = std::str::from_utf8(b)
                    .map_err(|_| AuthError::Cbor("invalid utf-8 in text string".into()))?;
                Ok(Value::Text(s.to_string()))
            }
            4 => {
                let mut items = Vec::with_capacity(arg.min(1024) as usize);
                for _ in 0..arg {
                    items.push(self.read_value()?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let mut entries: Vec<(String, Value)> = Vec::with_capacity(arg.min(1024) as usize);
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..arg {
                    // Keys must be text strings in this profile.
                    let (km, ka) = self.read_head()?;
                    if km != 3 {
                        return Err(AuthError::Cbor("map key must be a text string".into()));
                    }
                    let kbytes = self.take(ka as usize)?;
                    let key = std::str::from_utf8(kbytes)
                        .map_err(|_| AuthError::Cbor("invalid utf-8 in map key".into()))?
                        .to_string();
                    // Enforce canonical key order (strictly increasing encoded bytes).
                    let mut enc_key = Vec::new();
                    encode_head(3, key.len() as u64, &mut enc_key);
                    enc_key.extend_from_slice(key.as_bytes());
                    if let Some(prev) = &prev_key {
                        if enc_key <= *prev {
                            return Err(AuthError::Cbor(
                                "map keys not in canonical order or duplicated".into(),
                            ));
                        }
                    }
                    prev_key = Some(enc_key);
                    let value = self.read_value()?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            _ => Err(AuthError::Cbor("unsupported major type".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_primitives() {
        for v in [
            Value::Uint(0),
            Value::Uint(23),
            Value::Uint(24),
            Value::Uint(255),
            Value::Uint(256),
            Value::Uint(65535),
            Value::Uint(65536),
            Value::Uint(u32::MAX as u64),
            Value::Uint(u32::MAX as u64 + 1),
            Value::Uint(u64::MAX),
            Value::Bytes(vec![]),
            Value::Bytes(vec![0, 255, 7]),
            Value::Text("".into()),
            Value::Text("identikey-auth/v1".into()),
        ] {
            let bytes = v.to_bytes();
            assert_eq!(Value::from_bytes(&bytes).unwrap(), v, "roundtrip {v:?}");
        }
    }

    #[test]
    fn map_is_canonically_sorted() {
        // Insert out of order; encoded form must be sorted by encoded key bytes.
        let m = map(vec![
            ("nonce", Value::Bytes(vec![1, 2, 3])),
            ("v", Value::Uint(1)),
            ("aud", Value::Text("papyrus".into())),
            ("exp", Value::Uint(200)),
            ("iat", Value::Uint(100)),
        ]);
        let bytes = m.to_bytes();
        let decoded = Value::from_bytes(&bytes).unwrap();
        // Round-trips to a value equal as a map (entry order in Vec follows canonical).
        assert_eq!(decoded.get("v").unwrap().as_uint().unwrap(), 1);
        assert_eq!(decoded.get("aud").unwrap().as_text().unwrap(), "papyrus");
        // Re-encoding the decoded form is byte-identical (determinism).
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn rejects_noncanonical_integer() {
        // 0x18 0x05 = uint 5 encoded in 1-byte form (non-minimal; should be 0x05).
        assert!(Value::from_bytes(&[0x18, 0x05]).is_err());
    }

    #[test]
    fn rejects_unsorted_map_keys() {
        // Map with keys "b" then "a" (out of canonical order). Major 5, len 2.
        let bytes = [0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert!(Value::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_duplicate_map_keys() {
        // Map {"a":1,"a":2}
        let bytes = [0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02];
        assert!(Value::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = Value::Uint(1).to_bytes();
        bytes.push(0x00);
        assert!(Value::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_input() {
        // byte string claiming length 4 with only 1 byte present
        assert!(Value::from_bytes(&[0x44, 0x00]).is_err());
    }
}
