//! Capability: signed bearer token for authorizing access to recrypt resources.
//!
//! # Intent (target shape)
//!
//! `Capability` is the project's UCAN/JWT-style bearer token: an
//! issuer-signed, optionally time-limited credential that a holder can
//! present across any recrypt surface (proxy, storage, peer-to-peer)
//! to prove they were granted some set of permissions on some
//! resource. It is intentionally *generic*: the subject can identify
//! a file, a keyspace, an account fingerprint, or any future resource
//! type — Capability is the container, not the policy.
//!
//! Container: Gordian Envelope (dCBOR). Subject fields (which
//! resource, who issued, who is granted) are non-elidable; assertions
//! (permissions, expiry, notes) are salted and elidable. Spec lives
//! in [`docs/wire-protocol.md`](../../../docs/wire-protocol.md) §3.7.
//!
//! Optional delegation chain: a `parent` field will let a holder mint
//! sub-capabilities that downstream verifiers can walk back to the
//! root issuer. Chain verification logic is future work — gestured at
//! in the type but not implemented in this pass.
//!
//! # Status (current implementation is interim)
//!
//! Today's `Capability` is bound to a keyspace, signed via a hand-rolled
//! domain-tagged TLV (`signature_payload`), and has no HTTP surface. It
//! is **not on the critical path**: proxy authorization currently flows
//! through per-request multisig + `AccessGrant` lookups, not bearer
//! tokens. This struct exists so the type and the spec slot stay
//! reserved while the rebuild lands.
//!
//! Rebuild tracked under recrypt-91h (child of epic recrypt-nj1):
//! - Replace TLV with envelope canonical encoding.
//! - Generalize subject beyond keyspace.
//! - Add issue/verify HTTP endpoints via the codegen pipeline.
//! - Add (but do not yet enforce) the delegation `parent` field.
//!
//! Naming note: `MemberCapability` (in `keyspace.rs`) is a permission
//! tag — read/write/admin/etc. — *not* a bearer token. It is being
//! renamed to `Permission` under recrypt-r1l so that "Capability"
//! unambiguously refers to the token type described above.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::keyspace::MemberCapability;
use recrypt_core::sign::{
    MultiSig, SigningKeys, VerifyPolicy, VerifyingKeys, sign_message, verify_message,
};

/// A signed capability token bound to a keyspace.
///
/// Replaces the old file-hash-bound Capability. Capabilities are signed by the
/// issuer and can be verified by anyone with the issuer's public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    /// Format version
    pub version: u32,
    /// KeyspaceId bytes
    pub keyspace_id: [u8; 32],
    /// Version of the keyspace document this capability was issued against
    pub keyspace_version: u64,
    /// Who this capability is granted to
    pub granted_to: PublicKeyFingerprint,
    /// Permitted capabilities within the keyspace
    pub capabilities: BTreeSet<MemberCapability>,
    /// Expiration timestamp (Unix seconds, None = no expiry)
    pub expires_at: Option<u64>,
    /// Who issued this capability
    pub issuer: PublicKeyFingerprint,
    /// Signature over capability fields (None if unsigned)
    pub signature: Option<MultiSig>,
}

impl Capability {
    /// Current capability format version
    pub const VERSION: u32 = 2;

    /// Create a new unsigned capability
    pub fn new(
        keyspace_id: [u8; 32],
        keyspace_version: u64,
        granted_to: PublicKeyFingerprint,
        capabilities: BTreeSet<MemberCapability>,
        expires_at: Option<u64>,
        issuer: PublicKeyFingerprint,
    ) -> Self {
        Self {
            version: Self::VERSION,
            keyspace_id,
            keyspace_version,
            granted_to,
            capabilities,
            expires_at,
            issuer,
            signature: None,
        }
    }

    /// Domain-separation tag for `Capability` signature payloads.
    const DOMAIN_TAG: &'static [u8] = b"IdentikeyCap\x01";

    /// Compute the bytes to be signed.
    ///
    /// Layout is length-prefixed with a domain tag so that distinct
    /// field contents cannot alias under hashing, and so that a
    /// `Capability` payload can never be confused with an `AccessGrant`
    /// canonical encoding.
    fn signature_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(256);
        payload.extend(Self::DOMAIN_TAG);
        payload.extend(self.version.to_le_bytes());
        payload.extend(&self.keyspace_id);
        payload.extend(self.keyspace_version.to_le_bytes());
        payload.extend(self.granted_to.as_bytes());
        crate::grant::write_capabilities(&mut payload, &self.capabilities);
        payload.extend(self.expires_at.unwrap_or(0).to_le_bytes());
        payload.extend(self.issuer.as_bytes());
        payload
    }

    /// Sign the capability
    pub fn sign(&mut self, keys: &SigningKeys) -> AuthResult<()> {
        let payload = self.signature_payload();
        self.signature = Some(sign_message(&payload, keys)?);
        Ok(())
    }

    /// Create a signed capability in one step
    pub fn new_signed(
        keyspace_id: [u8; 32],
        keyspace_version: u64,
        granted_to: PublicKeyFingerprint,
        capabilities: BTreeSet<MemberCapability>,
        expires_at: Option<u64>,
        issuer: PublicKeyFingerprint,
        keys: &SigningKeys,
    ) -> AuthResult<Self> {
        let mut cap = Self::new(
            keyspace_id,
            keyspace_version,
            granted_to,
            capabilities,
            expires_at,
            issuer,
        );
        cap.sign(keys)?;
        Ok(cap)
    }

    /// Verify the capability signature under `policy`.
    pub fn verify_signature(
        &self,
        issuer_keys: &VerifyingKeys,
        policy: VerifyPolicy,
    ) -> AuthResult<()> {
        let sig = self.signature.as_ref().ok_or(AuthError::InvalidSignature)?;

        let payload = self.signature_payload();
        verify_message(&payload, sig, issuer_keys, policy)?;
        Ok(())
    }

    /// Check if capability has expired
    pub fn is_expired(&self) -> bool {
        let expires = match self.expires_at {
            Some(ts) => ts,
            None => return false,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now > expires
    }

    /// Check if a specific member capability is permitted
    pub fn permits(&self, cap: MemberCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Full verification: signature + expiry + capability check
    pub fn verify(
        &self,
        issuer_keys: &VerifyingKeys,
        policy: VerifyPolicy,
        required_cap: MemberCapability,
    ) -> AuthResult<()> {
        // Check signature
        self.verify_signature(issuer_keys, policy)?;

        // Check expiry
        if self.is_expired() {
            return Err(AuthError::CapabilityExpired);
        }

        // Check capability
        if !self.permits(required_cap) {
            return Err(AuthError::OperationNotPermitted(
                required_cap.as_str().into(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recrypt_ffi::ed25519::ed25519_keygen;
    use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

    fn test_keys() -> (SigningKeys, VerifyingKeys) {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: Some(pq_kp.secret_key.clone()),
        };

        let verifying = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: Some(pq_kp.public_key.clone()),
        };

        (signing, verifying)
    }

    #[test]
    fn test_capability_sign_verify() {
        let (signing, verifying) = test_keys();

        let keyspace_id = [1u8; 32];
        let grantee = PublicKeyFingerprint::from_bytes([2u8; 32]);
        let issuer = PublicKeyFingerprint::from_bytes([3u8; 32]);

        let cap = Capability::new_signed(
            keyspace_id,
            0,
            grantee,
            BTreeSet::from([MemberCapability::Read]),
            None,
            issuer,
            &signing,
        )
        .unwrap();

        assert!(
            cap.verify_signature(&verifying, VerifyPolicy::PqRequired)
                .is_ok()
        );
    }

    #[test]
    fn test_capability_expiry() {
        let keyspace_id = [0u8; 32];
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);

        // No expiry
        let cap = Capability::new(
            keyspace_id,
            0,
            fp,
            BTreeSet::from([MemberCapability::Read]),
            None,
            fp,
        );
        assert!(!cap.is_expired());

        // Expired
        let cap = Capability::new(
            keyspace_id,
            0,
            fp,
            BTreeSet::from([MemberCapability::Read]),
            Some(1),
            fp,
        );
        assert!(cap.is_expired());

        // Future expiry
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let cap = Capability::new(
            keyspace_id,
            0,
            fp,
            BTreeSet::from([MemberCapability::Read]),
            Some(future),
            fp,
        );
        assert!(!cap.is_expired());
    }

    #[test]
    fn test_capability_permissions() {
        let keyspace_id = [0u8; 32];
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);

        let cap = Capability::new(
            keyspace_id,
            0,
            fp,
            BTreeSet::from([MemberCapability::Read, MemberCapability::Write]),
            None,
            fp,
        );

        assert!(cap.permits(MemberCapability::Read));
        assert!(cap.permits(MemberCapability::Write));
        assert!(!cap.permits(MemberCapability::Delegate));
        assert!(!cap.permits(MemberCapability::Admin));
        assert!(!cap.permits(MemberCapability::SignRotation));
    }
}
