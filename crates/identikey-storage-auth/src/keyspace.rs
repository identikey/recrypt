//! Keyspace types for group key management
//!
//! A keyspace is a named, versioned group of members sharing access to encrypted
//! content. Each version is captured in a `KeyspaceDoc` whose hash forms a
//! content-addressed chain.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::fingerprint::PublicKeyFingerprint;

// ---------------------------------------------------------------------------
// KeyspaceId
// ---------------------------------------------------------------------------

/// Unique random identifier for a keyspace (256-bit, displayed as base58).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyspaceId([u8; 32]);

impl KeyspaceId {
    /// Generate a random keyspace id.
    pub fn random() -> Self {
        Self(rand::random::<[u8; 32]>())
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl fmt::Display for KeyspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::Debug for KeyspaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyspaceId({})", &self.to_base58()[..8])
    }
}

impl FromStr for KeyspaceId {
    type Err = crate::error::AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(|e| {
            crate::error::AuthError::InvalidEncoding(format!("KeyspaceId base58: {e}"))
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            crate::error::AuthError::InvalidEncoding(format!(
                "KeyspaceId expected 32 bytes, got {}",
                v.len()
            ))
        })?;
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// KeyspaceDocHash
// ---------------------------------------------------------------------------

/// Blake3 hash of a `KeyspaceDoc`'s canonical bytes (displayed as base58).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyspaceDocHash([u8; 32]);

impl KeyspaceDocHash {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl fmt::Display for KeyspaceDocHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::Debug for KeyspaceDocHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DocHash({})", &self.to_base58()[..8])
    }
}

impl FromStr for KeyspaceDocHash {
    type Err = crate::error::AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec().map_err(|e| {
            crate::error::AuthError::InvalidEncoding(format!("KeyspaceDocHash base58: {e}"))
        })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            crate::error::AuthError::InvalidEncoding(format!(
                "KeyspaceDocHash expected 32 bytes, got {}",
                v.len()
            ))
        })?;
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// RotationMode
// ---------------------------------------------------------------------------

/// Describes the purpose of a keyspace document version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationMode {
    /// Initial creation of the keyspace.
    Create,
    /// Add members without rekeying.
    Additive,
    /// Routine key rotation (no membership change).
    Hygiene,
    /// Remove members and re-key.
    Revoke { removed: Vec<PublicKeyFingerprint> },
    /// Remove members and destroy old epoch keys.
    Burn { removed: Vec<PublicKeyFingerprint> },
    /// Fork into a new keyspace (new id generated).
    Fork { new_id: KeyspaceId },
    /// Permanently seal the keyspace.
    Tombstone,
}

// ---------------------------------------------------------------------------
// MemberCapability / DecryptionPolicy
// ---------------------------------------------------------------------------

/// Capability granted to a keyspace member.
///
/// Named `MemberCapability` to avoid collision with the existing per-file
/// `Capability` type in `capability.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MemberCapability {
    Read,
    Write,
    Delegate,
    Admin,
    SignRotation,
}

impl MemberCapability {
    /// String tag used in canonical byte encodings and serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberCapability::Read => "read",
            MemberCapability::Write => "write",
            MemberCapability::Delegate => "delegate",
            MemberCapability::Admin => "admin",
            MemberCapability::SignRotation => "sign_rotation",
        }
    }

    /// Parse from a case-insensitive string tag.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "read" => Some(MemberCapability::Read),
            "write" => Some(MemberCapability::Write),
            "delegate" => Some(MemberCapability::Delegate),
            "admin" => Some(MemberCapability::Admin),
            "sign_rotation" => Some(MemberCapability::SignRotation),
            _ => None,
        }
    }
}

/// How a member's decryption key is delivered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecryptionPolicy {
    /// Member holds the full decryption key.
    Standalone,
    /// Member holds a threshold share.
    ThresholdShare {
        threshold: u8,
        total: u8,
        /// Content hash referencing the threshold policy document.
        policy_ref: [u8; 32],
    },
}

// ---------------------------------------------------------------------------
// Member
// ---------------------------------------------------------------------------

/// A participant in a keyspace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub fingerprint: PublicKeyFingerprint,
    pub capabilities: BTreeSet<MemberCapability>,
    pub decryption_policy: DecryptionPolicy,
    pub added_at: u64,
    pub added_by: PublicKeyFingerprint,
}

// ---------------------------------------------------------------------------
// Canonical encoding helpers
// ---------------------------------------------------------------------------

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_le_bytes());
    out.extend(bytes);
}

fn encode_rotation_mode(out: &mut Vec<u8>, mode: &RotationMode) {
    match mode {
        RotationMode::Create => out.push(1),
        RotationMode::Additive => out.push(2),
        RotationMode::Hygiene => out.push(3),
        RotationMode::Revoke { removed } => {
            out.push(4);
            out.extend((removed.len() as u32).to_le_bytes());
            for fp in removed {
                out.extend(fp.as_bytes());
            }
        }
        RotationMode::Burn { removed } => {
            out.push(5);
            out.extend((removed.len() as u32).to_le_bytes());
            for fp in removed {
                out.extend(fp.as_bytes());
            }
        }
        RotationMode::Fork { new_id } => {
            out.push(6);
            out.extend(new_id.as_bytes());
        }
        RotationMode::Tombstone => out.push(7),
    }
}

fn encode_decryption_policy(out: &mut Vec<u8>, policy: &DecryptionPolicy) {
    match policy {
        DecryptionPolicy::Standalone => out.push(1),
        DecryptionPolicy::ThresholdShare {
            threshold,
            total,
            policy_ref,
        } => {
            out.push(2);
            out.push(*threshold);
            out.push(*total);
            out.extend(policy_ref);
        }
    }
}

// ---------------------------------------------------------------------------
// KeyspaceDoc
// ---------------------------------------------------------------------------

/// A versioned, signed keyspace document.
///
/// Each version forms a hash-linked chain via `parent`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyspaceDoc {
    pub id: KeyspaceId,
    pub version: u64,
    pub parent: Option<KeyspaceDocHash>,
    pub mode: RotationMode,
    pub name: String,
    /// Placeholder for `HdRootPubkey` (Phase C).
    pub root_pk: Vec<u8>,
    /// Placeholder for `PrePubkeyRef` — content hash of the epoch PRE public key (Phase C).
    pub epoch_pre_pk: [u8; 32],
    pub epoch: u64,
    pub members: Vec<Member>,
    pub quorum: u8,
    /// Placeholder for real `Signature` type (Phase C).
    pub signatures: Vec<Vec<u8>>,
    pub created_at: u64,
}

impl KeyspaceDoc {
    /// Domain-separation tag for `KeyspaceDoc` canonical bytes.
    pub(crate) const DOMAIN_TAG: &'static [u8] = b"IdentikeyKeyspaceDoc\x01";
    /// On-disk / on-wire format version for the canonical encoding.
    pub const FORMAT_VERSION: u32 = 1;

    /// Deterministic canonical byte representation.
    ///
    /// Explicit length-prefixed binary layout; every variable-width field
    /// is framed by a `u32` length so independent of serde / serde_json
    /// versioning. The chain hash is `Blake3(canonical_bytes)` so any
    /// silent change here invalidates every stored chain — intentionally.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend(Self::DOMAIN_TAG);
        out.extend(Self::FORMAT_VERSION.to_le_bytes());
        out.extend(self.id.as_bytes());
        out.extend(self.version.to_le_bytes());
        match &self.parent {
            Some(p) => {
                out.push(1);
                out.extend(p.as_bytes());
            }
            None => out.push(0),
        }
        encode_rotation_mode(&mut out, &self.mode);
        write_len_prefixed(&mut out, self.name.as_bytes());
        write_len_prefixed(&mut out, &self.root_pk);
        out.extend(&self.epoch_pre_pk);
        out.extend(self.epoch.to_le_bytes());
        out.extend((self.members.len() as u32).to_le_bytes());
        for m in &self.members {
            out.extend(m.fingerprint.as_bytes());
            crate::grant::write_capabilities(&mut out, &m.capabilities);
            encode_decryption_policy(&mut out, &m.decryption_policy);
            out.extend(m.added_at.to_le_bytes());
            out.extend(m.added_by.as_bytes());
        }
        out.push(self.quorum);
        out.extend((self.signatures.len() as u32).to_le_bytes());
        for sig in &self.signatures {
            write_len_prefixed(&mut out, sig);
        }
        out.extend(self.created_at.to_le_bytes());
        out
    }

    /// Blake3 hash of the canonical bytes.
    pub fn doc_hash(&self) -> KeyspaceDocHash {
        let hash = blake3::hash(&self.canonical_bytes());
        KeyspaceDocHash(*hash.as_bytes())
    }

    /// Members that hold the `SignRotation` capability.
    pub fn signers(&self) -> Vec<&Member> {
        self.members
            .iter()
            .filter(|m| m.capabilities.contains(&MemberCapability::SignRotation))
            .collect()
    }

    /// Fingerprints of all current members.
    pub fn member_fingerprints(&self) -> Vec<&PublicKeyFingerprint> {
        self.members.iter().map(|m| &m.fingerprint).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_member(seed: u8, caps: &[MemberCapability], added_by_seed: u8) -> Member {
        Member {
            fingerprint: PublicKeyFingerprint::from_bytes([seed; 32]),
            capabilities: caps.iter().cloned().collect(),
            decryption_policy: DecryptionPolicy::Standalone,
            added_at: 1000,
            added_by: PublicKeyFingerprint::from_bytes([added_by_seed; 32]),
        }
    }

    fn make_doc() -> KeyspaceDoc {
        KeyspaceDoc {
            id: KeyspaceId::from_bytes([1u8; 32]),
            version: 0,
            parent: None,
            mode: RotationMode::Create,
            name: "test-keyspace".to_string(),
            root_pk: vec![0u8; 32],
            epoch_pre_pk: [2u8; 32],
            epoch: 0,
            members: vec![
                make_member(
                    10,
                    &[MemberCapability::Read, MemberCapability::SignRotation],
                    10,
                ),
                make_member(20, &[MemberCapability::Read, MemberCapability::Write], 10),
                make_member(
                    30,
                    &[MemberCapability::Admin, MemberCapability::SignRotation],
                    10,
                ),
            ],
            quorum: 2,
            signatures: vec![],
            created_at: 1700000000,
        }
    }

    #[test]
    fn doc_hash_is_deterministic() {
        let doc = make_doc();
        let h1 = doc.doc_hash();
        let h2 = doc.doc_hash();
        assert_eq!(h1, h2, "doc_hash must be deterministic across calls");
    }

    #[test]
    fn canonical_bytes_deterministic_across_constructions() {
        let doc_a = make_doc();
        let doc_b = make_doc();
        assert_eq!(
            doc_a.canonical_bytes(),
            doc_b.canonical_bytes(),
            "canonical_bytes must be identical for independently constructed docs with same data"
        );
    }

    #[test]
    fn signers_returns_only_sign_rotation_members() {
        let doc = make_doc();
        let signers = doc.signers();

        // Members with seed 10 and 30 have SignRotation
        assert_eq!(signers.len(), 2);
        assert_eq!(
            signers[0].fingerprint,
            PublicKeyFingerprint::from_bytes([10; 32])
        );
        assert_eq!(
            signers[1].fingerprint,
            PublicKeyFingerprint::from_bytes([30; 32])
        );
    }

    #[test]
    fn keyspace_id_display_roundtrip() {
        let id = KeyspaceId::from_bytes([42u8; 32]);
        let s = id.to_string();
        let recovered: KeyspaceId = s.parse().unwrap();
        assert_eq!(id, recovered);
    }

    #[test]
    fn doc_hash_display_roundtrip() {
        let doc = make_doc();
        let hash = doc.doc_hash();
        let s = hash.to_string();
        let recovered: KeyspaceDocHash = s.parse().unwrap();
        assert_eq!(hash, recovered);
    }
}
