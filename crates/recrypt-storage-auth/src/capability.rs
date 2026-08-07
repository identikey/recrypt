//! Capability: signed bearer token for authorizing access to recrypt resources.
//!
//! # Intent
//!
//! `Capability` is the project's UCAN/JWT-style bearer token: an
//! issuer-signed, optionally time-limited credential that a holder can
//! present across any recrypt surface (proxy, storage, peer-to-peer)
//! to prove they were granted some set of permissions on some
//! resource. The subject is intentionally generic — `subject` (32-byte
//! content addr) plus `subject_kind` ("file" | "keyspace" | "account")
//! lets the same type talk about any resource the system understands.
//!
//! # Wire format
//!
//! Gordian Envelope (dCBOR). Subject identity triple (resource, issuer,
//! grantee) is non-elidable; assertions (`permissions`, `expires-at`,
//! `note`) are salted and elidable. Signed via wrap-then-sign: an outer
//! wrapper holds the inner envelope plus signature assertions, so the
//! signature commits to the entire payload. Spec lives in
//! [`docs/wire-protocol.md`](../../../docs/wire-protocol.md) §3.7.
//!
//! Signatures are emitted as **sibling raw-bytes assertions** rather
//! than bc-envelope's native `'signed'` form: `ed25519-signature`
//! (64 B) + optional `mldsa-signature` (~4.6 KB). This keeps the
//! ML-DSA half symmetric with ed25519 (bc-envelope cannot model
//! ML-DSA in `Signature`) and matches the hybrid pattern used by
//! `Identity::sign_self_hybrid`. A future migration to native
//! `'signed'` for the ed25519 half is straightforward.
//!
//! # Delegation (future work)
//!
//! `parent` is reserved for signature chains — a holder mints a
//! sub-capability whose `parent` is the digest of the parent capability's
//! wrapped envelope, and a downstream verifier can walk back to the
//! root issuer. **Chain verification is not implemented in this
//! pass**; verifying a capability with `parent` set checks only the
//! immediate signature, not the chain. Tracked as a follow-up.
//!
//! # Status
//!
//! Not on the critical path. Proxy authorization today flows through
//! per-request multisig + server-side `AccessGrant` lookups, not
//! bearer tokens. `Capability` exists for offline-verifiable
//! authorization (sharing access without the proxy) and as plumbing
//! for the future delegation story.

use std::collections::BTreeSet;

use bc_envelope::prelude::*;
use ed25519_dalek::Signature as Ed25519Signature;
use serde::{Deserialize, Serialize};

use recrypt_core::sign::{
    MultiSig, SigningKeys, VerifyPolicy, VerifyingKeys, sign_message, verify_message,
};
use recrypt_wire::armor::{ArmorType, armor_decode, armor_encode};
use recrypt_wire::error::{WireError, WireResult};
use recrypt_wire::format::MultiFormat;

use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::keyspace::Permission;

/// Kind of resource a `Capability` references.
///
/// The wire form is the lowercase tag string emitted by `as_str()`. New
/// kinds are non-breaking: unknown values fail to parse with a clear
/// error rather than silently coercing to a known kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubjectKind {
    File,
    Keyspace,
    Account,
}

impl SubjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Keyspace => "keyspace",
            Self::Account => "account",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "file" => Some(Self::File),
            "keyspace" => Some(Self::Keyspace),
            "account" => Some(Self::Account),
            _ => None,
        }
    }
}

/// A signed, optionally time-limited authorization token.
///
/// Issuer signs an envelope binding `subject` (resource ref + kind) and
/// `granted_to` (recipient fingerprint) with a set of `permissions`.
/// Verifiers parse, check the signature against the issuer's public
/// keys, and consult `permissions` / `expires_at` to authorize an
/// operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub format_version: u32,
    /// 32-byte resource address (e.g., file BLAKE3 hash, keyspace id,
    /// or account fingerprint, depending on `subject_kind`).
    pub subject: [u8; 32],
    pub subject_kind: SubjectKind,
    /// Recipient (Blake3 fingerprint of their Ed25519 public key).
    pub granted_to: PublicKeyFingerprint,
    /// Issuer (Blake3 fingerprint of the signer's Ed25519 public key).
    pub issuer: PublicKeyFingerprint,
    /// Permissions granted on the subject. Salted on the wire — a
    /// 4-value enum is trivially brute-forceable unsalted.
    pub permissions: BTreeSet<Permission>,
    /// Unix-seconds expiry. `None` means no expiry. Salted on the wire.
    pub expires_at: Option<u64>,
    /// Free-form human-readable note. Salted on the wire because
    /// templated comments are often guessable.
    pub note: Option<String>,
    /// Digest of the parent capability's wrapped envelope, when this
    /// capability was minted as a delegated sub-capability. Reserved
    /// for future chain verification — present-but-not-walked today.
    pub parent: Option<[u8; 32]>,
}

impl Capability {
    pub const FORMAT_VERSION: u32 = 1;

    pub fn new(
        subject: [u8; 32],
        subject_kind: SubjectKind,
        granted_to: PublicKeyFingerprint,
        issuer: PublicKeyFingerprint,
        permissions: BTreeSet<Permission>,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            format_version: Self::FORMAT_VERSION,
            subject,
            subject_kind,
            granted_to,
            issuer,
            permissions,
            expires_at,
            note: None,
            parent: None,
        }
    }

    pub fn with_note(mut self, note: String) -> Self {
        self.note = Some(note);
        self
    }

    pub fn with_parent(mut self, parent: [u8; 32]) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Whether `perm` is in the `permissions` set.
    pub fn permits(&self, perm: Permission) -> bool {
        self.permissions.contains(&perm)
    }

    /// Whether `expires_at` is in the past relative to system time.
    pub fn is_expired(&self) -> bool {
        let Some(expires) = self.expires_at else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > expires
    }

    /// Sign this capability and emit the signed envelope as CBOR bytes.
    ///
    /// Wraps the inner envelope, computes a `MultiSig` over the
    /// wrapper's subject digest (which transitively covers every
    /// non-elided assertion), then attaches `ed25519-signature` and
    /// optionally `mldsa-signature` raw-bytes assertions.
    pub fn sign(&self, signing_keys: &SigningKeys) -> AuthResult<Vec<u8>> {
        let inner = self
            .to_envelope_inner()
            .map_err(|e| AuthError::InvalidEncoding(format!("encode: {e}")))?;
        let wrapped = inner.wrap();
        let payload = wrapped.subject().digest().data().to_vec();

        let sig = sign_message(&payload, signing_keys)?;

        let mut signed = wrapped.add_assertion(
            "ed25519-signature",
            ByteString::from(sig.ed25519_sig.to_bytes().to_vec()),
        );
        if let Some(ref ml) = sig.ml_dsa_sig {
            signed = signed.add_assertion("mldsa-signature", ByteString::from(ml.clone()));
        }

        Ok(signed.to_cbor_data())
    }

    /// Parse a signed capability envelope, verify its signature against
    /// `issuer_keys` under `policy`, and return the parsed `Capability`.
    ///
    /// Returns [`AuthError::InvalidSignature`] for any signature failure
    /// or malformed wrapper. Does **not** check expiry or permissions
    /// — see [`Self::verify_full`] for the full check.
    pub fn verify(
        envelope_bytes: &[u8],
        issuer_keys: &VerifyingKeys,
        policy: VerifyPolicy,
    ) -> AuthResult<Self> {
        let outer = Envelope::try_from_cbor_data(envelope_bytes.to_vec())
            .map_err(|_| AuthError::InvalidSignature)?;

        let inner = outer.try_unwrap().map_err(|_| AuthError::InvalidSignature)?;

        let cap = Self::from_envelope_inner(&inner)
            .map_err(|e| AuthError::InvalidEncoding(format!("decode: {e}")))?;

        let ed_sig: ByteString = outer
            .extract_object_for_predicate("ed25519-signature")
            .map_err(|_| AuthError::InvalidSignature)?;
        let ed_arr: [u8; 64] = ed_sig
            .to_vec()
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;

        let ml_dsa_sig: Option<Vec<u8>> = outer
            .extract_optional_object_for_predicate::<ByteString>("mldsa-signature")
            .ok()
            .flatten()
            .map(|b| b.to_vec());

        let multisig = MultiSig {
            ed25519_sig: Ed25519Signature::from_bytes(&ed_arr),
            ml_dsa_sig,
        };

        let payload = outer.subject().digest().data().to_vec();
        verify_message(&payload, &multisig, issuer_keys, policy)
            .map_err(|_| AuthError::InvalidSignature)?;

        Ok(cap)
    }

    /// Parse the issuer fingerprint from a signed capability envelope
    /// **without** verifying the signature. Used by chain verification
    /// to look up the issuer's public keys before calling [`Self::verify`].
    ///
    /// A signed envelope passed here that signature-verifies via
    /// [`Self::verify`] also produces the correct issuer here, so the
    /// "peek" is safe in practice: the issuer is part of the inner
    /// envelope's subject map, which the wrap-then-sign covers.
    pub fn peek_issuer(envelope_bytes: &[u8]) -> AuthResult<PublicKeyFingerprint> {
        let outer = Envelope::try_from_cbor_data(envelope_bytes.to_vec())
            .map_err(|_| AuthError::InvalidSignature)?;
        let inner = outer.try_unwrap().map_err(|_| AuthError::InvalidSignature)?;
        let cap = Self::from_envelope_inner(&inner)
            .map_err(|e| AuthError::InvalidEncoding(format!("decode: {e}")))?;
        Ok(cap.issuer)
    }

    /// Compute the digest of a signed capability envelope's wrapped
    /// subject — the value a *child* capability would store in its
    /// `parent` field when delegating from this one.
    ///
    /// Used by chain verification to confirm a resolved parent's
    /// envelope bytes hash to the digest the child committed to.
    pub fn wrapped_subject_digest(envelope_bytes: &[u8]) -> AuthResult<[u8; 32]> {
        let outer = Envelope::try_from_cbor_data(envelope_bytes.to_vec())
            .map_err(|_| AuthError::InvalidSignature)?;
        let bytes = outer.subject().digest().data().to_vec();
        bytes
            .try_into()
            .map_err(|_| AuthError::InvalidEncoding("envelope digest must be 32 bytes".into()))
    }

    /// Verify signature, expiry, and that `required_perm` is granted.
    pub fn verify_full(
        envelope_bytes: &[u8],
        issuer_keys: &VerifyingKeys,
        policy: VerifyPolicy,
        required_perm: Permission,
    ) -> AuthResult<Self> {
        let cap = Self::verify(envelope_bytes, issuer_keys, policy)?;
        if cap.is_expired() {
            return Err(AuthError::CapabilityExpired);
        }
        if !cap.permits(required_perm) {
            return Err(AuthError::OperationNotPermitted(
                required_perm.as_str().into(),
            ));
        }
        Ok(cap)
    }

    fn to_envelope_inner(&self) -> WireResult<Envelope> {
        let mut subject = Map::new();
        subject.insert("type", "recrypt.capability");
        subject.insert("format-version", self.format_version);
        subject.insert("subject", ByteString::from(self.subject.to_vec()));
        subject.insert("subject-kind", self.subject_kind.as_str());
        subject.insert(
            "granted-to",
            ByteString::from(self.granted_to.as_bytes().to_vec()),
        );
        subject.insert("issuer", ByteString::from(self.issuer.as_bytes().to_vec()));

        let mut env = Envelope::new(CBOR::from(subject));

        // permissions: salted (closed enum is brute-forceable unsalted)
        let perm_strs: Vec<String> =
            self.permissions.iter().map(|p| p.as_str().to_string()).collect();
        env = env.add_assertion_salted("permissions", perm_strs, true);

        if let Some(exp) = self.expires_at {
            let tagged = CBOR::to_tagged_value(Tag::with_value(1), exp);
            env = env.add_assertion_salted("expires-at", tagged, true);
        }

        if let Some(ref n) = self.note {
            env = env.add_assertion_salted("note", n.as_str(), true);
        }

        // parent: NOT salted — verifiers walking the chain need the link
        // visible.
        if let Some(ref p) = self.parent {
            env = env.add_assertion("parent", ByteString::from(p.to_vec()));
        }

        Ok(env)
    }

    fn from_envelope_inner(env: &Envelope) -> WireResult<Self> {
        let subject_cbor = env
            .subject()
            .try_leaf()
            .map_err(|e| WireError::Envelope(format!("subject leaf: {e}")))?;
        let subject_map = match subject_cbor.into_case() {
            CBORCase::Map(m) => m,
            other => {
                return Err(WireError::Envelope(format!(
                    "subject is not a map: {:?}",
                    CBOR::from(other)
                )));
            }
        };

        let ty: String = subject_map
            .get("type")
            .ok_or_else(|| WireError::MissingField("type".into()))?;
        if ty != "recrypt.capability" {
            return Err(WireError::WrongType {
                expected: "recrypt.capability".into(),
                actual: ty,
            });
        }

        let version: u32 = subject_map
            .get("format-version")
            .ok_or_else(|| WireError::MissingField("format-version".into()))?;
        if version != Self::FORMAT_VERSION {
            return Err(WireError::VersionMismatch {
                expected: Self::FORMAT_VERSION,
                actual: version,
            });
        }

        let subject_bs: ByteString = subject_map
            .get("subject")
            .ok_or_else(|| WireError::MissingField("subject".into()))?;
        let subject: [u8; 32] = subject_bs
            .to_vec()
            .try_into()
            .map_err(|_| WireError::InvalidFormat("subject must be 32 bytes".into()))?;

        let kind_str: String = subject_map
            .get("subject-kind")
            .ok_or_else(|| WireError::MissingField("subject-kind".into()))?;
        let subject_kind = SubjectKind::parse(&kind_str)
            .ok_or_else(|| WireError::InvalidFormat(format!("unknown subject-kind: {kind_str}")))?;

        let granted_to_bs: ByteString = subject_map
            .get("granted-to")
            .ok_or_else(|| WireError::MissingField("granted-to".into()))?;
        let granted_to_arr: [u8; 32] = granted_to_bs
            .to_vec()
            .try_into()
            .map_err(|_| WireError::InvalidFormat("granted-to must be 32 bytes".into()))?;

        let issuer_bs: ByteString = subject_map
            .get("issuer")
            .ok_or_else(|| WireError::MissingField("issuer".into()))?;
        let issuer_arr: [u8; 32] = issuer_bs
            .to_vec()
            .try_into()
            .map_err(|_| WireError::InvalidFormat("issuer must be 32 bytes".into()))?;

        // permissions assertion may be elided. Treat absence as empty;
        // callers checking `permits()` will see it as no-grant rather
        // than panic.
        let permissions: BTreeSet<Permission> =
            match env.extract_object_for_predicate::<Vec<String>>("permissions") {
                Ok(strs) => strs.into_iter().filter_map(|s| Permission::parse(&s)).collect(),
                Err(_) => BTreeSet::new(),
            };

        let expires_at: Option<u64> = match env.optional_object_for_predicate("expires-at") {
            Ok(Some(obj)) => {
                let cbor = obj
                    .try_leaf()
                    .map_err(|e| WireError::Envelope(format!("expires-at: {e}")))?;
                match cbor.into_case() {
                    CBORCase::Tagged(tag, inner) if tag.value() == 1 => match inner.into_case() {
                        CBORCase::Unsigned(v) => Some(v),
                        other => {
                            return Err(WireError::InvalidFormat(format!(
                                "expires-at tag 1 inner is not unsigned: {:?}",
                                CBOR::from(other)
                            )));
                        }
                    },
                    other => {
                        return Err(WireError::InvalidFormat(format!(
                            "expires-at is not CBOR tag 1: {:?}",
                            CBOR::from(other)
                        )));
                    }
                }
            }
            _ => None,
        };

        let note: Option<String> = env
            .extract_optional_object_for_predicate::<String>("note")
            .ok()
            .flatten();

        let parent: Option<[u8; 32]> =
            match env.extract_optional_object_for_predicate::<ByteString>("parent") {
                Ok(Some(bs)) => Some(bs.to_vec().try_into().map_err(|_| {
                    WireError::InvalidFormat("parent must be 32 bytes".into())
                })?),
                _ => None,
            };

        Ok(Capability {
            format_version: version,
            subject,
            subject_kind,
            granted_to: PublicKeyFingerprint::from_bytes(granted_to_arr),
            issuer: PublicKeyFingerprint::from_bytes(issuer_arr),
            permissions,
            expires_at,
            note,
            parent,
        })
    }
}

impl MultiFormat for Capability {
    fn envelope_type() -> &'static str {
        "recrypt.capability"
    }

    fn to_envelope(&self) -> WireResult<Vec<u8>> {
        let env = self.to_envelope_inner()?;
        Ok(env.to_cbor_data())
    }

    fn from_envelope(bytes: &[u8]) -> WireResult<Self> {
        let env = Envelope::try_from_cbor_data(bytes.to_vec())
            .map_err(|e| WireError::Envelope(format!("parse envelope: {e}")))?;
        Self::from_envelope_inner(&env)
    }

    fn to_armor(&self) -> WireResult<String> {
        let bytes = self.to_envelope()?;
        let headers = [("Version", "1"), ("Format", "envelope+cbor")];
        Ok(armor_encode(ArmorType::Capability, &headers, &bytes))
    }

    fn from_armor(s: &str) -> WireResult<Self> {
        let block = armor_decode(s)?;
        if block.armor_type != ArmorType::Capability {
            return Err(WireError::InvalidFormat(format!(
                "expected CAPABILITY, got {:?}",
                block.armor_type
            )));
        }
        Self::from_envelope(&block.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use recrypt_ffi::ed25519::ed25519_keygen;
    use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

    fn test_keys() -> (SigningKeys, VerifyingKeys, PublicKeyFingerprint) {
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
        let fp = PublicKeyFingerprint::from_public_key(ed_kp.verifying_key.as_bytes());
        (signing, verifying, fp)
    }

    fn make_cap(issuer: PublicKeyFingerprint, granted_to: PublicKeyFingerprint) -> Capability {
        Capability::new(
            [7u8; 32],
            SubjectKind::File,
            granted_to,
            issuer,
            BTreeSet::from([Permission::Read]),
            None,
        )
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (signing, verifying, issuer_fp) = test_keys();
        let grantee_fp = PublicKeyFingerprint::from_bytes([2u8; 32]);

        let cap = make_cap(issuer_fp, grantee_fp);
        let bytes = cap.sign(&signing).unwrap();

        let parsed = Capability::verify(&bytes, &verifying, VerifyPolicy::PqRequired).unwrap();
        assert_eq!(parsed.subject, cap.subject);
        assert_eq!(parsed.subject_kind, SubjectKind::File);
        assert_eq!(parsed.granted_to, grantee_fp);
        assert_eq!(parsed.issuer, issuer_fp);
        assert!(parsed.permits(Permission::Read));
        assert!(!parsed.permits(Permission::Write));
    }

    #[test]
    fn verify_rejects_tampered_subject() {
        let (signing, verifying, issuer_fp) = test_keys();
        let grantee_fp = PublicKeyFingerprint::from_bytes([2u8; 32]);
        let cap = make_cap(issuer_fp, grantee_fp);
        let bytes = cap.sign(&signing).unwrap();

        // Flip a byte in the middle (within the wrapped subject digest's
        // input area) and verify rejection.
        let mut tampered = bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] = tampered[mid].wrapping_add(1);

        // Either parse fails (corrupt CBOR) or signature fails — both
        // are valid rejections.
        let result = Capability::verify(&tampered, &verifying, VerifyPolicy::PqRequired);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_issuer_keys() {
        let (signing, _, issuer_fp) = test_keys();
        let (_, other_verifying, _) = test_keys();
        let grantee_fp = PublicKeyFingerprint::from_bytes([2u8; 32]);

        let cap = make_cap(issuer_fp, grantee_fp);
        let bytes = cap.sign(&signing).unwrap();

        assert!(matches!(
            Capability::verify(&bytes, &other_verifying, VerifyPolicy::PqRequired),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn verify_full_checks_expiry_and_permission() {
        let (signing, verifying, issuer_fp) = test_keys();
        let grantee_fp = PublicKeyFingerprint::from_bytes([2u8; 32]);

        let mut cap = make_cap(issuer_fp, grantee_fp);
        cap.expires_at = Some(1); // long-expired
        let bytes = cap.sign(&signing).unwrap();

        assert!(matches!(
            Capability::verify_full(&bytes, &verifying, VerifyPolicy::PqRequired, Permission::Read),
            Err(AuthError::CapabilityExpired)
        ));

        // Same payload without expiry, wrong permission requested → permission error.
        let cap2 = make_cap(issuer_fp, grantee_fp);
        let bytes2 = cap2.sign(&signing).unwrap();
        assert!(matches!(
            Capability::verify_full(&bytes2, &verifying, VerifyPolicy::PqRequired, Permission::Write),
            Err(AuthError::OperationNotPermitted(_))
        ));
    }

    #[test]
    fn permits_and_is_expired() {
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);
        let mut cap = Capability::new(
            [0u8; 32],
            SubjectKind::Keyspace,
            fp,
            fp,
            BTreeSet::from([Permission::Read, Permission::Write]),
            None,
        );
        assert!(cap.permits(Permission::Read));
        assert!(cap.permits(Permission::Write));
        assert!(!cap.permits(Permission::Delegate));
        assert!(!cap.is_expired());

        cap.expires_at = Some(1);
        assert!(cap.is_expired());
    }

    #[test]
    fn unsigned_envelope_roundtrip_via_multiformat() {
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);
        let cap = Capability::new(
            [9u8; 32],
            SubjectKind::Account,
            fp,
            fp,
            BTreeSet::from([Permission::Admin]),
            Some(1_700_000_000),
        )
        .with_note("test".into());

        let bytes = cap.to_envelope().unwrap();
        let parsed = Capability::from_envelope(&bytes).unwrap();
        assert_eq!(parsed, cap);
    }

    #[test]
    fn parent_field_round_trips() {
        let fp = PublicKeyFingerprint::from_bytes([0u8; 32]);
        let cap = Capability::new(
            [1u8; 32],
            SubjectKind::File,
            fp,
            fp,
            BTreeSet::from([Permission::Read]),
            None,
        )
        .with_parent([42u8; 32]);

        let bytes = cap.to_envelope().unwrap();
        let parsed = Capability::from_envelope(&bytes).unwrap();
        assert_eq!(parsed.parent, Some([42u8; 32]));
    }
}
