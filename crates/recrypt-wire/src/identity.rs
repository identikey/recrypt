//! Wire-format Identity type with Gordian Envelope serialization.

use bc_components::{Ed25519PrivateKey, Ed25519PublicKey, SigningPrivateKey, SigningPublicKey};
use bc_envelope::prelude::*;
use std::sync::OnceLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::armor::{ArmorType, armor_decode, armor_encode};
use crate::error::{WireError, WireResult};
use crate::format::MultiFormat;

const KNOWN_PREDICATES: &[&str] = &[
    "created",
    "ed25519-public",
    "ed25519-secret",
    "ml-dsa-public",
    "ml-dsa-secret",
    "name",
    "pre-backend",
    "pre-public",
    "pre-secret",
];

fn known_predicate_digests() -> &'static [Digest] {
    static CELL: OnceLock<Vec<Digest>> = OnceLock::new();
    CELL.get_or_init(|| {
        KNOWN_PREDICATES
            .iter()
            .map(|p| Envelope::new(*p).digest())
            .collect()
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PreKeyMaterial {
    #[zeroize(skip)]
    pub backend: String,
    #[zeroize(skip)]
    pub public: Vec<u8>,
    pub secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    pub fingerprint: [u8; 32],
    #[zeroize(skip)]
    pub ed25519_public: [u8; 32],
    pub ed25519_secret: Option<[u8; 32]>,
    #[zeroize(skip)]
    pub name: Option<String>,
    #[zeroize(skip)]
    pub created: Option<u64>,
    pub ml_dsa: Option<MlDsaKeyPair>,
    pub pre: Option<PreKeyMaterial>,
    #[zeroize(skip)]
    pub unknown_assertions: Vec<(Envelope, Envelope)>,
}

impl Identity {
    pub fn to_envelope_bytes(&self) -> WireResult<Vec<u8>> {
        let envelope = self.to_envelope_inner()?;
        Ok(envelope.to_cbor_data())
    }

    pub fn from_envelope_bytes(bytes: &[u8]) -> WireResult<Self> {
        let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
            .map_err(|e| WireError::Envelope(format!("parse envelope: {e}")))?;
        Self::from_envelope_inner(&envelope)
    }

    /// Signs the identity envelope using a wrap-then-sign pattern.
    ///
    /// The identity envelope is first wrapped (so the wrapper's subject digest
    /// covers the entire inner envelope — subject **and** all assertions), then
    /// the wrapper is signed with the identity's ed25519 secret key. This
    /// ensures the signature commits to all key material (ml-dsa-public,
    /// pre-public, etc.) and not just the subject's fingerprint.
    ///
    /// Wire shape: `wrap(identity-envelope) + 'signed': Signature(ed25519, ...)`.
    /// See `docs/standards/identity-self-signature.md` for the full spec.
    ///
    /// Requires `self.ed25519_secret.is_some()`.
    pub fn sign_self_ed25519(&self) -> WireResult<Vec<u8>> {
        let secret_bytes = self.ed25519_secret.ok_or_else(|| {
            WireError::InvalidFormat("ed25519 secret key required for signing".into())
        })?;

        let inner = self.to_envelope_inner()?;
        let wrapped = inner.wrap();

        let private_key =
            SigningPrivateKey::new_ed25519(Ed25519PrivateKey::from_data(secret_bytes));

        let signed_envelope = wrapped.add_signature(&private_key);
        Ok(signed_envelope.to_cbor_data())
    }

    /// Sign with ed25519 AND ML-DSA-87 in a hybrid wrap-then-sign pattern.
    ///
    /// Wire shape: `wrap(inner) + 'signed': Signature(ed25519, ...) +
    /// "mldsa-signature": h'<raw ML-DSA-87 signature bytes>'`. Both
    /// signatures commit to the same payload (the wrapped envelope's
    /// subject digest, i.e. the inner envelope's digest). The ed25519
    /// half uses bc-envelope's native `'signed'` machinery; the ML-DSA
    /// half is a sibling raw-bytes assertion because bc-envelope's
    /// `Signature` type does not yet model ML-DSA.
    ///
    /// Requires both `self.ed25519_secret` and the supplied
    /// `ml_dsa_secret` to be present.
    ///
    /// See `docs/standards/identity-self-signature.md`.
    #[cfg(feature = "pq-self-sign")]
    pub fn sign_self_hybrid(&self, ml_dsa_secret: &[u8]) -> WireResult<Vec<u8>> {
        use recrypt_ffi::liboqs::{PqAlgorithm, pq_sign};

        let ed25519_sk = self.ed25519_secret.ok_or_else(|| {
            WireError::InvalidFormat("ed25519 secret key required for hybrid signing".into())
        })?;

        let inner = self.to_envelope_inner()?;
        let wrapped = inner.wrap();

        // ed25519 via bc-envelope (canonical 'signed' assertion).
        let priv_ed = SigningPrivateKey::new_ed25519(Ed25519PrivateKey::from_data(ed25519_sk));
        let ed_signed = wrapped.add_signature(&priv_ed);

        // ML-DSA over the wrapped envelope's subject digest — the same
        // bytes ed25519 commits to. (bc-envelope's signature mechanism
        // signs over the wrapper's subject digest internally.)
        let payload = wrapped.subject().digest().data().to_vec();
        let ml_dsa_sig = pq_sign(ml_dsa_secret, PqAlgorithm::MlDsa87, &payload)
            .map_err(|e| WireError::Envelope(format!("ML-DSA-87 self-signature failed: {e}")))?;

        let final_envelope =
            ed_signed.add_assertion("mldsa-signature", ByteString::from(ml_dsa_sig));
        Ok(final_envelope.to_cbor_data())
    }

    /// Verify a hybrid (ed25519 + ML-DSA-87) self-signature.
    ///
    /// Both signatures must verify against the same payload. Returns
    /// `Err` for any failure mode (missing ML-DSA pubkey on the inner
    /// identity, fingerprint mismatch, ed25519 invalid, ML-DSA invalid,
    /// or `mldsa-signature` assertion absent).
    #[cfg(feature = "pq-self-sign")]
    pub fn verify_self_signature_hybrid(envelope_bytes: &[u8]) -> WireResult<()> {
        use recrypt_ffi::liboqs::{PqAlgorithm, pq_verify};

        let outer = Envelope::try_from_cbor_data(envelope_bytes.to_vec())
            .map_err(|e| WireError::Envelope(format!("parse envelope: {e}")))?;

        let inner = outer.try_unwrap().map_err(|e| {
            tracing::debug!(error = %e, "expected wrapped (signed) identity envelope");
            WireError::SignatureVerification("signature verification failed".into())
        })?;

        let identity = Self::from_envelope_inner(&inner)?;

        // ed25519 first (cheaper; fail fast).
        let public_key =
            SigningPublicKey::from_ed25519(Ed25519PublicKey::from_data(identity.ed25519_public));
        let ed_ok = outer.has_signature_from(&public_key).map_err(|e| {
            tracing::debug!(
                fingerprint = hex::encode(identity.fingerprint),
                error = %e,
                "ed25519 signature check returned error"
            );
            WireError::SignatureVerification("signature verification failed".into())
        })?;
        if !ed_ok {
            tracing::debug!(
                fingerprint = hex::encode(identity.fingerprint),
                "no valid 'signed' assertion found on wrapped envelope"
            );
            return Err(WireError::SignatureVerification(
                "signature verification failed".into(),
            ));
        }

        // ML-DSA: pubkey from the inner identity, signature from the
        // outer envelope's "mldsa-signature" assertion, payload is the
        // wrapped subject digest (same bytes ed25519 just verified).
        let ml_dsa_public = identity
            .ml_dsa
            .as_ref()
            .map(|kp| kp.public.as_slice())
            .ok_or_else(|| {
                WireError::SignatureVerification("inner identity has no ml-dsa public key".into())
            })?;

        let ml_dsa_sig: ByteString = outer
            .extract_object_for_predicate("mldsa-signature")
            .map_err(|_| {
                WireError::SignatureVerification(
                    "missing 'mldsa-signature' assertion on hybrid envelope".into(),
                )
            })?;

        // Reconstruct the payload: wrap(inner)'s subject digest. We have
        // `inner` from the unwrap; the wrap's subject digest is computed
        // from the inner envelope.
        let wrapped = inner.wrap();
        let payload = wrapped.subject().digest().data().to_vec();

        let pq_ok = pq_verify(
            ml_dsa_public,
            PqAlgorithm::MlDsa87,
            &payload,
            &ml_dsa_sig.to_vec(),
        )
        .map_err(|e| {
            tracing::debug!(error = %e, "ML-DSA verification call failed");
            WireError::SignatureVerification("signature verification failed".into())
        })?;
        if !pq_ok {
            return Err(WireError::SignatureVerification(
                "signature verification failed".into(),
            ));
        }

        Ok(())
    }

    /// Verifies the `'signed'` ed25519 self-signature on a wrap-then-signed
    /// identity envelope.
    ///
    /// Steps:
    /// 1. Parse outer envelope, unwrap to obtain the inner identity envelope.
    /// 2. Parse inner identity (validates `fingerprint == Blake3(ed25519_public)`).
    /// 3. Verify the `'signed'` assertion on the outer envelope using the
    ///    public key extracted from the (now-validated) inner identity.
    ///
    /// Returns `Err` if: outer is not a wrapped envelope, fingerprint mismatch,
    /// no `'signed'` assertion, or signature invalid. The caller-facing error
    /// message is intentionally generic; details are emitted via
    /// `tracing::debug!`. This verifies ED25519 ONLY — see
    /// [`Self::verify_self_signature_hybrid`] when the file was signed with
    /// `sign_self_hybrid`.
    pub fn verify_self_signature_ed25519(envelope_bytes: &[u8]) -> WireResult<()> {
        let outer = Envelope::try_from_cbor_data(envelope_bytes.to_vec())
            .map_err(|e| WireError::Envelope(format!("parse envelope: {e}")))?;

        let inner = outer.try_unwrap().map_err(|e| {
            tracing::debug!(error = %e, "expected wrapped (signed) identity envelope");
            WireError::SignatureVerification("signature verification failed".into())
        })?;

        let identity = Self::from_envelope_inner(&inner)?;

        let public_key =
            SigningPublicKey::from_ed25519(Ed25519PublicKey::from_data(identity.ed25519_public));

        let has_sig = outer.has_signature_from(&public_key).map_err(|e| {
            tracing::debug!(
                fingerprint = hex::encode(identity.fingerprint),
                error = %e,
                "signature check returned error"
            );
            WireError::SignatureVerification("signature verification failed".into())
        })?;

        if !has_sig {
            tracing::debug!(
                fingerprint = hex::encode(identity.fingerprint),
                "no valid 'signed' assertion found on wrapped envelope"
            );
            return Err(WireError::SignatureVerification(
                "signature verification failed".into(),
            ));
        }

        Ok(())
    }

    fn to_envelope_inner(&self) -> WireResult<Envelope> {
        // Encoder-side fingerprint check: catches construction errors before
        // they hit the wire. Decoder enforces the same invariant on parse
        // (see `from_envelope_inner`).
        let expected_fp = blake3::hash(&self.ed25519_public);
        if self.fingerprint != *expected_fp.as_bytes() {
            return Err(WireError::InvalidFormat(
                "fingerprint does not match Blake3(ed25519-public)".into(),
            ));
        }

        let mut subject = Map::new();
        subject.insert("type", "recrypt.identity");
        subject.insert("format-version", 1_u32);
        subject.insert("fingerprint", ByteString::from(self.fingerprint.to_vec()));

        let mut envelope = Envelope::new(CBOR::from(subject));

        // Emit assertions in predicate-alphabetical order for determinism.

        if let Some(created) = self.created {
            let tagged = CBOR::to_tagged_value(Tag::with_value(1), created);
            envelope = envelope.add_assertion("created", tagged);
        }

        envelope = envelope.add_assertion(
            "ed25519-public",
            ByteString::from(self.ed25519_public.to_vec()),
        );

        if let Some(ref secret) = self.ed25519_secret {
            envelope = envelope.add_assertion("ed25519-secret", ByteString::from(secret.to_vec()));
        }

        if let Some(ref ml_dsa) = self.ml_dsa {
            envelope =
                envelope.add_assertion("ml-dsa-public", ByteString::from(ml_dsa.public.clone()));
            if let Some(ref secret) = ml_dsa.secret {
                envelope =
                    envelope.add_assertion("ml-dsa-secret", ByteString::from(secret.clone()));
            }
        }

        if let Some(ref name) = self.name {
            envelope = envelope.add_assertion("name", name.as_str());
        }

        if let Some(ref pre) = self.pre {
            envelope = envelope.add_assertion("pre-backend", pre.backend.as_str());
            envelope = envelope.add_assertion("pre-public", ByteString::from(pre.public.clone()));
            if let Some(ref secret) = pre.secret {
                envelope = envelope.add_assertion("pre-secret", ByteString::from(secret.clone()));
            }
        }

        // Re-emit unknown assertions in their original order.
        for (pred, obj) in &self.unknown_assertions {
            let assertion = Envelope::new_assertion(pred.clone(), obj.clone());
            envelope = envelope
                .add_assertion_envelope(assertion)
                .map_err(|e| WireError::Envelope(format!("add unknown assertion: {e}")))?;
        }

        Ok(envelope)
    }

    fn from_envelope_inner(envelope: &Envelope) -> WireResult<Self> {
        let subject_cbor = envelope
            .subject()
            .try_leaf()
            .map_err(|e| WireError::Envelope(format!("extract subject leaf: {e}")))?;

        let subject = match subject_cbor.into_case() {
            CBORCase::Map(m) => m,
            other => {
                return Err(WireError::Envelope(format!(
                    "subject is not a map: {:?}",
                    CBOR::from(other)
                )));
            }
        };

        let ty: String = subject
            .get("type")
            .ok_or_else(|| WireError::MissingField("type".into()))?;
        if ty != "recrypt.identity" {
            return Err(WireError::WrongType {
                expected: "recrypt.identity".into(),
                actual: ty,
            });
        }

        let version: u32 = subject
            .get("format-version")
            .ok_or_else(|| WireError::MissingField("format-version".into()))?;
        if version != 1 {
            return Err(WireError::VersionMismatch {
                expected: 1,
                actual: version,
            });
        }

        let fp_bs: ByteString = subject
            .get("fingerprint")
            .ok_or_else(|| WireError::MissingField("fingerprint".into()))?;
        let fingerprint: [u8; 32] = fp_bs
            .to_vec()
            .try_into()
            .map_err(|_| WireError::InvalidFormat("fingerprint must be 32 bytes".into()))?;

        // ed25519-public (mandatory)
        let ed25519_public_bs: ByteString = envelope
            .extract_object_for_predicate("ed25519-public")
            .map_err(|_| WireError::MissingField("ed25519-public".into()))?;
        let ed25519_public: [u8; 32] = ed25519_public_bs
            .to_vec()
            .try_into()
            .map_err(|_| WireError::InvalidFormat("ed25519-public must be 32 bytes".into()))?;

        // Validate fingerprint
        let expected_fp = blake3::hash(&ed25519_public);
        if fingerprint != *expected_fp.as_bytes() {
            return Err(WireError::InvalidFormat(
                "fingerprint does not match Blake3(ed25519-public)".into(),
            ));
        }

        // ed25519-secret (optional)
        let ed25519_secret: Option<[u8; 32]> =
            match envelope.extract_optional_object_for_predicate::<ByteString>("ed25519-secret") {
                Ok(Some(bs)) => Some(bs.to_vec().try_into().map_err(|_| {
                    WireError::InvalidFormat("ed25519-secret must be 32 bytes".into())
                })?),
                _ => None,
            };

        // name (optional)
        let name: Option<String> = envelope
            .extract_optional_object_for_predicate::<String>("name")
            .unwrap_or(None);

        // created (optional) — CBOR tag 1 epoch seconds
        let created: Option<u64> = match envelope.optional_object_for_predicate("created") {
            Ok(Some(obj_envelope)) => {
                let cbor = obj_envelope
                    .try_leaf()
                    .map_err(|e| WireError::Envelope(format!("created leaf: {e}")))?;
                match cbor.into_case() {
                    CBORCase::Tagged(tag, inner) if tag.value() == 1 => match inner.into_case() {
                        CBORCase::Unsigned(v) => Some(v),
                        other => {
                            return Err(WireError::InvalidFormat(format!(
                                "created tag 1 inner is not unsigned: {:?}",
                                CBOR::from(other)
                            )));
                        }
                    },
                    other => {
                        return Err(WireError::InvalidFormat(format!(
                            "created is not tag 1: {:?}",
                            CBOR::from(other)
                        )));
                    }
                }
            }
            _ => None,
        };

        // ml-dsa (optional). Absent assertion → None; present-but-malformed
        // → InvalidFormat (don't silently treat malformed bytes as absent).
        let ml_dsa =
            match envelope.extract_optional_object_for_predicate::<ByteString>("ml-dsa-public") {
                Ok(Some(pub_bs)) => {
                    let secret = match envelope
                        .extract_optional_object_for_predicate::<ByteString>("ml-dsa-secret")
                    {
                        Ok(Some(bs)) => Some(bs.to_vec()),
                        Ok(None) => None,
                        Err(e) => {
                            return Err(WireError::InvalidFormat(format!(
                                "ml-dsa-secret present but malformed: {e}"
                            )));
                        }
                    };
                    Some(MlDsaKeyPair {
                        public: pub_bs.to_vec(),
                        secret,
                    })
                }
                Ok(None) => None,
                Err(e) => {
                    return Err(WireError::InvalidFormat(format!(
                        "ml-dsa-public present but malformed: {e}"
                    )));
                }
            };

        // pre (optional). Same absent-vs-malformed discipline as ml-dsa.
        let pre = match envelope.extract_optional_object_for_predicate::<String>("pre-backend") {
            Ok(Some(backend)) => {
                let pub_bs: ByteString = envelope
                    .extract_object_for_predicate("pre-public")
                    .map_err(|_| {
                        WireError::MissingField("pre-public (pre-backend present)".into())
                    })?;
                let secret = match envelope
                    .extract_optional_object_for_predicate::<ByteString>("pre-secret")
                {
                    Ok(Some(bs)) => Some(bs.to_vec()),
                    Ok(None) => None,
                    Err(e) => {
                        return Err(WireError::InvalidFormat(format!(
                            "pre-secret present but malformed: {e}"
                        )));
                    }
                };
                Some(PreKeyMaterial {
                    backend,
                    public: pub_bs.to_vec(),
                    secret,
                })
            }
            Ok(None) => None,
            Err(e) => {
                return Err(WireError::InvalidFormat(format!(
                    "pre-backend present but malformed: {e}"
                )));
            }
        };

        // Collect unknown assertions
        let known = known_predicate_digests();
        let mut unknown_assertions = Vec::new();
        for assertion in envelope.assertions() {
            if let (Some(pred), Some(obj)) = (assertion.as_predicate(), assertion.as_object()) {
                let pred_digest = pred.digest();
                if !known.contains(&pred_digest) {
                    unknown_assertions.push((pred, obj));
                }
            }
        }

        Ok(Identity {
            fingerprint,
            ed25519_public,
            ed25519_secret,
            name,
            created,
            ml_dsa,
            pre,
            unknown_assertions,
        })
    }
}

impl MultiFormat for Identity {
    fn envelope_type() -> &'static str {
        "recrypt.identity"
    }

    fn to_envelope(&self) -> WireResult<Vec<u8>> {
        self.to_envelope_bytes()
    }

    fn from_envelope(bytes: &[u8]) -> WireResult<Self> {
        Self::from_envelope_bytes(bytes)
    }

    fn to_armor(&self) -> WireResult<String> {
        let envelope_bytes = self.to_envelope()?;
        let headers = [("Version", "1"), ("Format", "envelope+cbor")];
        Ok(armor_encode(ArmorType::Identity, &headers, &envelope_bytes))
    }

    fn from_armor(s: &str) -> WireResult<Self> {
        let block = armor_decode(s)?;
        if block.armor_type != ArmorType::Identity {
            return Err(WireError::InvalidFormat(format!(
                "Expected IDENTITY, got {:?}",
                block.armor_type
            )));
        }
        Self::from_envelope(&block.payload)
    }
}
