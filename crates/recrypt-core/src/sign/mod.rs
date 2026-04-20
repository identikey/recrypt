//! Multi-signature system (ED25519 required, ML-DSA-87 optional).
//!
//! The signing protocol pairs a fast classical signature (ED25519) with an
//! optional post-quantum signature (ML-DSA-87). The invariant is
//! *ML-DSA implies ED25519*: a signature can be ED25519-only, or hybrid
//! (ED25519 + ML-DSA), but never ML-DSA-only. That keeps fingerprint-based
//! identity (derived from the ED25519 key) universally applicable and lets
//! verifiers fall back to the classical check when PQ material is absent.
//!
//! Verifiers choose the security ceiling via [`VerifyPolicy`]: a local CLI
//! decrypt may accept classical-only, while a server-side capability check
//! guarding long-lived data insists on [`VerifyPolicy::PqRequired`].

use crate::error::{CoreError, CoreResult};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey};
use recrypt_ffi::ed25519::{ed25519_sign, ed25519_verify};
use recrypt_ffi::liboqs::{PqAlgorithm, pq_sign, pq_verify};

/// A signature combining a mandatory ED25519 signature with an optional
/// ML-DSA-87 post-quantum signature.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MultiSig {
    /// ED25519 signature (always present; 64 bytes).
    pub ed25519_sig: Ed25519Signature,
    /// ML-DSA-87 signature bytes (post-quantum, ~4.6 KiB), present when the
    /// signer held a PQ key and chose to produce a hybrid signature.
    pub ml_dsa_sig: Option<Vec<u8>>,
}

/// Signing keys. ED25519 is required; when `ml_dsa` is `Some`,
/// [`sign_message`] additionally produces an ML-DSA-87 signature.
pub struct SigningKeys {
    pub ed25519: SigningKey,
    /// ML-DSA-87 secret key bytes. `None` produces a classical-only signature.
    pub ml_dsa: Option<Vec<u8>>,
}

/// Verifying keys. ED25519 is required; `ml_dsa` is required only when the
/// signature carries an ML-DSA component or the verifier's policy demands it.
pub struct VerifyingKeys {
    pub ed25519: VerifyingKey,
    /// ML-DSA-87 public key bytes. `None` means this verifier cannot check PQ
    /// signatures; pairing such keys with a PQ-bearing signature is an error.
    pub ml_dsa: Option<Vec<u8>>,
}

/// How much post-quantum assurance the verifier demands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyPolicy {
    /// Accept ED25519-only signatures. If the signature also carries an
    /// ML-DSA-87 component it is still verified (a bad PQ signature is
    /// rejected), but its absence is not an error.
    PqOptional,
    /// Reject the signature unless the ML-DSA-87 component is present and
    /// valid. Use for contexts where post-quantum robustness is mandatory
    /// (long-lived grants, keyspace roots, sensitive capabilities).
    PqRequired,
}

/// Sign a message. Always produces an ED25519 signature; additionally
/// produces ML-DSA-87 iff `keys.ml_dsa` is set.
pub fn sign_message(msg: &[u8], keys: &SigningKeys) -> CoreResult<MultiSig> {
    let ed25519_sig = ed25519_sign(&keys.ed25519, msg);

    let ml_dsa_sig = match &keys.ml_dsa {
        Some(sk) => Some(
            pq_sign(sk, PqAlgorithm::MlDsa87, msg)
                .map_err(|e| CoreError::Signature(format!("ML-DSA signing failed: {e}")))?,
        ),
        None => None,
    };

    Ok(MultiSig {
        ed25519_sig,
        ml_dsa_sig,
    })
}

/// Verify a signature under `policy`.
///
/// Rules:
/// 1. ED25519 is always verified; failure is fatal.
/// 2. If `policy == PqRequired`, `sig.ml_dsa_sig` must be `Some`.
/// 3. If `sig.ml_dsa_sig` is `Some`, `pks.ml_dsa` must also be `Some` and the
///    ML-DSA-87 signature must verify. A PQ signature without a PQ verifying
///    key is treated as an error, not silently skipped, to prevent downgrade.
pub fn verify_message(
    msg: &[u8],
    sig: &MultiSig,
    pks: &VerifyingKeys,
    policy: VerifyPolicy,
) -> CoreResult<bool> {
    // 1. ED25519 is mandatory.
    ed25519_verify(&pks.ed25519, msg, &sig.ed25519_sig)
        .map_err(|_| CoreError::Signature("ED25519 verification failed".into()))?;

    // 2. Policy gate on PQ presence.
    let Some(ml_dsa_bytes) = sig.ml_dsa_sig.as_ref() else {
        return match policy {
            VerifyPolicy::PqRequired => Err(CoreError::Signature(
                "ML-DSA-87 signature required by policy but absent".into(),
            )),
            VerifyPolicy::PqOptional => Ok(true),
        };
    };

    // 3. PQ signature present — verify it. Downgrade-proof: a missing PQ
    //    verifying key is an error, not a silent skip.
    let pq_pk = pks.ml_dsa.as_ref().ok_or_else(|| {
        CoreError::Signature("ML-DSA-87 signature present but no PQ verifying key".into())
    })?;

    let valid = pq_verify(pq_pk, PqAlgorithm::MlDsa87, msg, ml_dsa_bytes)
        .map_err(|e| CoreError::Signature(format!("ML-DSA verification failed: {e}")))?;

    if !valid {
        return Err(CoreError::Signature("ML-DSA signature invalid".into()));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use recrypt_ffi::ed25519::ed25519_keygen;
    use recrypt_ffi::liboqs::pq_keygen;

    fn hybrid_keys() -> (SigningKeys, VerifyingKeys) {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        (
            SigningKeys {
                ed25519: ed_kp.signing_key,
                ml_dsa: Some(pq_kp.secret_key.clone()),
            },
            VerifyingKeys {
                ed25519: ed_kp.verifying_key,
                ml_dsa: Some(pq_kp.public_key),
            },
        )
    }

    fn classical_keys() -> (SigningKeys, VerifyingKeys) {
        let ed_kp = ed25519_keygen();
        (
            SigningKeys {
                ed25519: ed_kp.signing_key,
                ml_dsa: None,
            },
            VerifyingKeys {
                ed25519: ed_kp.verifying_key,
                ml_dsa: None,
            },
        )
    }

    #[test]
    fn hybrid_roundtrip_with_either_policy() {
        let (signing, verifying) = hybrid_keys();
        let msg = b"Test multi-signature";
        let sig = sign_message(msg, &signing).unwrap();
        assert!(sig.ml_dsa_sig.is_some());

        assert!(verify_message(msg, &sig, &verifying, VerifyPolicy::PqOptional).unwrap());
        assert!(verify_message(msg, &sig, &verifying, VerifyPolicy::PqRequired).unwrap());
    }

    #[test]
    fn classical_only_roundtrip_under_pq_optional() {
        let (signing, verifying) = classical_keys();
        let msg = b"ED25519-only signature";
        let sig = sign_message(msg, &signing).unwrap();
        assert!(sig.ml_dsa_sig.is_none());

        assert!(verify_message(msg, &sig, &verifying, VerifyPolicy::PqOptional).unwrap());
    }

    #[test]
    fn classical_only_rejected_under_pq_required() {
        let (signing, verifying) = classical_keys();
        let sig = sign_message(b"msg", &signing).unwrap();
        let err =
            verify_message(b"msg", &sig, &verifying, VerifyPolicy::PqRequired).unwrap_err();
        assert!(format!("{err}").contains("ML-DSA-87 signature required"));
    }

    #[test]
    fn tampered_message_fails() {
        let (signing, verifying) = hybrid_keys();
        let sig = sign_message(b"Original", &signing).unwrap();
        let result = verify_message(b"Tampered", &sig, &verifying, VerifyPolicy::PqOptional);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_ed25519_key_fails() {
        let (signing, _) = hybrid_keys();
        let (_, wrong) = hybrid_keys();
        let sig = sign_message(b"msg", &signing).unwrap();
        let result = verify_message(b"msg", &sig, &wrong, VerifyPolicy::PqOptional);
        assert!(result.is_err());
    }

    #[test]
    fn pq_signature_present_but_verifier_has_no_pq_key_fails() {
        // Signer produces hybrid sig; verifier holds only ED25519 key.
        let (signing, hybrid_verifying) = hybrid_keys();
        let verifying = VerifyingKeys {
            ed25519: hybrid_verifying.ed25519,
            ml_dsa: None,
        };

        let sig = sign_message(b"msg", &signing).unwrap();
        let err = verify_message(b"msg", &sig, &verifying, VerifyPolicy::PqOptional).unwrap_err();
        assert!(format!("{err}").contains("no PQ verifying key"));
    }

    #[test]
    fn tampered_pq_signature_detected_under_pq_optional() {
        let (signing, verifying) = hybrid_keys();
        let mut sig = sign_message(b"msg", &signing).unwrap();
        // Corrupt the ML-DSA signature.
        if let Some(bytes) = sig.ml_dsa_sig.as_mut() {
            bytes[0] ^= 0xff;
        }
        let result = verify_message(b"msg", &sig, &verifying, VerifyPolicy::PqOptional);
        assert!(result.is_err());
    }
}
