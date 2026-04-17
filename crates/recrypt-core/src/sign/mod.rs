//! Multi-signature system (ED25519 + ML-DSA)

use crate::error::{CoreError, CoreResult};
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey};
use recrypt_ffi::ed25519::{ed25519_sign, ed25519_verify};
use recrypt_ffi::liboqs::{PqAlgorithm, pq_sign, pq_verify};

/// A multi-signature combining classical and post-quantum signatures
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MultiSig {
    /// ED25519 signature (fast, small)
    pub ed25519_sig: Ed25519Signature,
    /// ML-DSA-87 signature (post-quantum, large)
    pub ml_dsa_sig: Vec<u8>,
}

/// Signing keys for multi-signature
pub struct SigningKeys {
    pub ed25519: SigningKey,
    pub ml_dsa: Vec<u8>, // Secret key bytes
}

/// Verifying keys for multi-signature
pub struct VerifyingKeys {
    pub ed25519: VerifyingKey,
    pub ml_dsa: Vec<u8>, // Public key bytes
}

/// Sign a message with both classical and post-quantum keys
pub fn sign_message(msg: &[u8], keys: &SigningKeys) -> CoreResult<MultiSig> {
    let ed25519_sig = ed25519_sign(&keys.ed25519, msg);

    let ml_dsa_sig = pq_sign(&keys.ml_dsa, PqAlgorithm::MlDsa87, msg)
        .map_err(|e| CoreError::Signature(format!("ML-DSA signing failed: {e}")))?;

    Ok(MultiSig {
        ed25519_sig,
        ml_dsa_sig,
    })
}

/// Verify a multi-signature
///
/// Both signatures must be valid for verification to succeed.
pub fn verify_message(msg: &[u8], sig: &MultiSig, pks: &VerifyingKeys) -> CoreResult<bool> {
    // Verify ED25519 (fast check first)
    ed25519_verify(&pks.ed25519, msg, &sig.ed25519_sig)
        .map_err(|_| CoreError::Signature("ED25519 verification failed".into()))?;

    // Verify ML-DSA
    let ml_dsa_valid = pq_verify(&pks.ml_dsa, PqAlgorithm::MlDsa87, msg, &sig.ml_dsa_sig)
        .map_err(|e| CoreError::Signature(format!("ML-DSA verification failed: {e}")))?;

    if !ml_dsa_valid {
        return Err(CoreError::Signature("ML-DSA signature invalid".into()));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use recrypt_ffi::ed25519::ed25519_keygen;
    use recrypt_ffi::liboqs::pq_keygen;

    #[test]
    fn test_multisig_roundtrip() {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing_keys = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: pq_kp.secret_key.clone(),
        };

        let verifying_keys = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: pq_kp.public_key.clone(),
        };

        let message = b"Test multi-signature";
        let sig = sign_message(message, &signing_keys).unwrap();
        let valid = verify_message(message, &sig, &verifying_keys).unwrap();

        assert!(valid);
    }

    #[test]
    fn test_multisig_tampered_message() {
        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let signing_keys = SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: pq_kp.secret_key.clone(),
        };

        let verifying_keys = VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: pq_kp.public_key.clone(),
        };

        let message = b"Original message";
        let sig = sign_message(message, &signing_keys).unwrap();

        let tampered = b"Tampered message";
        let result = verify_message(tampered, &sig, &verifying_keys);

        assert!(result.is_err());
    }

    #[test]
    fn test_multisig_wrong_key() {
        let ed_kp1 = ed25519_keygen();
        let pq_kp1 = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let ed_kp2 = ed25519_keygen();

        let signing_keys = SigningKeys {
            ed25519: ed_kp1.signing_key,
            ml_dsa: pq_kp1.secret_key.clone(),
        };

        let wrong_verifying_keys = VerifyingKeys {
            ed25519: ed_kp2.verifying_key, // Wrong key!
            ml_dsa: pq_kp1.public_key.clone(),
        };

        let message = b"Test message";
        let sig = sign_message(message, &signing_keys).unwrap();

        let result = verify_message(message, &sig, &wrong_verifying_keys);
        assert!(result.is_err());
    }
}
