//! Self-describing public keys, signatures, and fingerprints (§3.2, §5).

use std::fmt;

use crate::algorithm::{ClassicalAlg, PqAlg};
use crate::cbor::{map, Value};
use crate::error::{AuthError, Result};

/// A classical public key carrying its algorithm tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassicalPublicKey {
    pub alg: ClassicalAlg,
    pub bytes: Vec<u8>,
}

/// A classical signature carrying its algorithm tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassicalSignature {
    pub alg: ClassicalAlg,
    pub bytes: Vec<u8>,
}

/// A post-quantum public key carrying its algorithm tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqPublicKey {
    pub alg: PqAlg,
    pub bytes: Vec<u8>,
}

/// A post-quantum signature carrying its algorithm tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqSignature {
    pub alg: PqAlg,
    pub bytes: Vec<u8>,
}

impl ClassicalPublicKey {
    /// Canonical `{ "alg": tstr, "key": bstr }` map value.
    pub fn to_value(&self) -> Value {
        map(vec![
            ("alg", Value::Text(self.alg.tag().to_string())),
            ("key", Value::Bytes(self.bytes.clone())),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self> {
        let alg = ClassicalAlg::from_tag(v.get("alg")?.as_text()?)?;
        let bytes = v.get("key")?.as_bytes()?.to_vec();
        Ok(Self { alg, bytes })
    }
    /// The identity fingerprint: `Blake3(dcbor(PublicKey))` (algorithm-committing).
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(*blake3::hash(&self.to_value().to_bytes()).as_bytes())
    }
}

impl ClassicalSignature {
    pub fn to_value(&self) -> Value {
        map(vec![
            ("alg", Value::Text(self.alg.tag().to_string())),
            ("sig", Value::Bytes(self.bytes.clone())),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self> {
        let alg = ClassicalAlg::from_tag(v.get("alg")?.as_text()?)?;
        let bytes = v.get("sig")?.as_bytes()?.to_vec();
        Ok(Self { alg, bytes })
    }
}

impl PqPublicKey {
    pub fn to_value(&self) -> Value {
        map(vec![
            ("alg", Value::Text(self.alg.tag().to_string())),
            ("key", Value::Bytes(self.bytes.clone())),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self> {
        let alg = PqAlg::from_tag(v.get("alg")?.as_text()?)?;
        let bytes = v.get("key")?.as_bytes()?.to_vec();
        Ok(Self { alg, bytes })
    }
}

impl PqSignature {
    pub fn to_value(&self) -> Value {
        map(vec![
            ("alg", Value::Text(self.alg.tag().to_string())),
            ("sig", Value::Bytes(self.bytes.clone())),
        ])
    }
    pub fn from_value(v: &Value) -> Result<Self> {
        let alg = PqAlg::from_tag(v.get("alg")?.as_text()?)?;
        let bytes = v.get("sig")?.as_bytes()?.to_vec();
        Ok(Self { alg, bytes })
    }
}

/// A 32-byte Blake3 fingerprint of a self-describing public key (§5).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
    pub fn from_base58(s: &str) -> Result<Self> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|_| AuthError::InvalidKey("fingerprint base58"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| AuthError::InvalidKey("fingerprint length"))?;
        Ok(Self(arr))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", &self.to_base58()[..8.min(self.to_base58().len())])
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base58())
    }
}
