//! Public key fingerprint type
//!
//! Uses Blake3 hash of public key bytes for compact, collision-resistant identification.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A fingerprint uniquely identifying a public key
///
/// Blake3 hash provides 256-bit collision resistance, Base58 encoding for readability.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKeyFingerprint([u8; 32]);

impl PublicKeyFingerprint {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from a public key (Blake3 hash)
    pub fn from_public_key(pubkey_bytes: &[u8]) -> Self {
        let hash = blake3::hash(pubkey_bytes);
        Self(*hash.as_bytes())
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as base58 (compact, readable)
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Decode from base58
    pub fn from_base58(s: &str) -> Option<Self> {
        let bytes = bs58::decode(s).into_vec().ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let arr: [u8; 32] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

impl fmt::Debug for PublicKeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", &self.to_base58()[..8])
    }
}

impl fmt::Display for PublicKeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl From<[u8; 32]> for PublicKeyFingerprint {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKeyFingerprint {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_roundtrip() {
        let bytes = [42u8; 32];
        let fp = PublicKeyFingerprint::from_bytes(bytes);

        let b58 = fp.to_base58();
        let recovered = PublicKeyFingerprint::from_base58(&b58).unwrap();

        assert_eq!(fp, recovered);
    }

    #[test]
    fn test_from_public_key() {
        let pubkey = b"test public key bytes";
        let fp = PublicKeyFingerprint::from_public_key(pubkey);

        // Same input should produce same fingerprint
        let fp2 = PublicKeyFingerprint::from_public_key(pubkey);
        assert_eq!(fp, fp2);

        // Different input should produce different fingerprint
        let fp3 = PublicKeyFingerprint::from_public_key(b"different key");
        assert_ne!(fp, fp3);
    }
}
