//! # identikey-auth
//!
//! Hardware-enclave-backed **challenge/response authentication** for IdentiKey.
//!
//! A verifier issues a short-lived, audience-bound, nonce-carrying [`Challenge`]; a
//! claimant answers with a [`Response`] signed by a hardware-protected key; the verifier
//! checks the signature directly — no Relying-Party server, no hosted domain. This suits
//! server-less / P2P apps (the design rationale is in the companion Papyrus SP-02 spike).
//!
//! It is **cipher-agile**: keys and signatures are self-describing (Ed25519 or P-256
//! classical, optional ML-DSA / FIPS 204 post-quantum), with downgrade-proof
//! verification via [`VerifyPolicy`]. The wire format is canonical (deterministic) CBOR.
//!
//! See `docs/standards/identikey-auth-challenge-v1.md` for the full protocol spec.
//!
//! ## Quick start
//!
//! ```
//! use identikey_auth::{
//!     ChallengeIssuer, InMemoryNonceStore, SoftwareSigner, Signer, VerifyPolicy,
//!     verify_response,
//! };
//!
//! // Verifier issues a challenge.
//! let mut nonces = InMemoryNonceStore::new();
//! let issuer = ChallengeIssuer::new("papyrus", 120);
//! let now = 1_000_000;
//! let challenge = issuer.issue(&mut nonces, now);
//!
//! // Claimant signs it with a (software, here) P-256 identity.
//! let signer = SoftwareSigner::generate_p256();
//! let response = signer.respond(&challenge).unwrap();
//!
//! // Verifier checks it.
//! let verified = verify_response(
//!     &response, "papyrus", now, 30, VerifyPolicy::PqOptional, &mut nonces,
//! ).unwrap();
//! assert_eq!(verified.public_key, signer.classical_public_key());
//! ```

mod cbor;

pub mod algorithm;
pub mod attestation;
pub mod challenge;
pub mod enclave;
pub mod error;
pub mod key;
pub mod nonce;
pub mod signer;
pub mod verify;

pub use algorithm::{ClassicalAlg, PqAlg};
pub use attestation::{attest_node_id, verify_node_attestation, NodeAttestation};
pub use challenge::{signing_payload, Challenge, Response, VERSION};
pub use error::{AuthError, Result};
pub use key::{
    ClassicalPublicKey, ClassicalSignature, Fingerprint, PqPublicKey, PqSignature,
};
pub use nonce::{ChallengeIssuer, InMemoryNonceStore, NonceStore};
pub use signer::{verify_classical, verify_pq, Signer, SoftwareSigner};
pub use verify::{verify_response, Verified, VerifyPolicy};

#[cfg(target_os = "macos")]
pub use enclave::{SecureEnclaveEd25519Signer, SecureEnclaveSigner};
#[cfg(any(target_os = "windows", target_os = "linux"))]
pub use enclave::TpmSigner;

#[cfg(test)]
mod tests {
    use super::*;

    const AUD: &str = "papyrus";
    const NOW: u64 = 1_000_000;

    fn setup() -> (InMemoryNonceStore, Challenge) {
        let mut nonces = InMemoryNonceStore::new();
        let challenge = ChallengeIssuer::new(AUD, 120).issue(&mut nonces, NOW);
        (nonces, challenge)
    }

    #[test]
    fn ed25519_happy_path() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519();
        let resp = signer.respond(&challenge).unwrap();
        let v = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces).unwrap();
        assert_eq!(v.public_key.alg, ClassicalAlg::Ed25519);
        assert_eq!(v.fingerprint, signer.classical_public_key().fingerprint());
        assert!(v.pq_public_key.is_none());
    }

    #[test]
    fn p256_happy_path() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_p256();
        let resp = signer.respond(&challenge).unwrap();
        let v = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces).unwrap();
        assert_eq!(v.public_key.alg, ClassicalAlg::P256);
    }

    #[test]
    fn hybrid_pq_happy_path_and_required_policy() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519().with_ml_dsa_65().unwrap();
        let resp = signer.respond(&challenge).unwrap();
        assert!(resp.pq.is_some());
        let v = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqRequired, &mut nonces).unwrap();
        assert_eq!(v.pq_public_key.as_ref().unwrap().alg, PqAlg::MlDsa65);
    }

    #[test]
    fn classical_only_rejected_when_pq_required() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_p256();
        let resp = signer.respond(&challenge).unwrap();
        let err = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqRequired, &mut nonces)
            .unwrap_err();
        assert!(matches!(err, AuthError::PqRequired));
    }

    #[test]
    fn wire_roundtrip() {
        let (_n, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519().with_ml_dsa_65().unwrap();
        let resp = signer.respond(&challenge).unwrap();
        let bytes = resp.to_bytes();
        let decoded = Response::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, resp);
        // Deterministic: re-encoding is byte-identical.
        assert_eq!(decoded.to_bytes(), bytes);
    }

    #[test]
    fn tampered_challenge_fails() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519();
        let mut resp = signer.respond(&challenge).unwrap();
        // Flip a byte in the embedded challenge — signature no longer matches.
        let last = resp.challenge_bytes.len() - 1;
        resp.challenge_bytes[last] ^= 0xFF;
        assert!(verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces).is_err());
    }

    #[test]
    fn tampered_pq_signature_fails() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519().with_ml_dsa_65().unwrap();
        let mut resp = signer.respond(&challenge).unwrap();
        if let Some((_, pqsig)) = resp.pq.as_mut() {
            pqsig.bytes[0] ^= 0xFF;
        }
        let err = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces)
            .unwrap_err();
        assert!(matches!(err, AuthError::BadSignature));
    }

    #[test]
    fn wrong_audience_rejected() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519();
        let resp = signer.respond(&challenge).unwrap();
        let err = verify_response(&resp, "not-papyrus", NOW, 30, VerifyPolicy::PqOptional, &mut nonces)
            .unwrap_err();
        assert!(matches!(err, AuthError::Audience));
    }

    #[test]
    fn expired_challenge_rejected() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519();
        let resp = signer.respond(&challenge).unwrap();
        // Far past the 120s ttl + 30s skew.
        let err = verify_response(&resp, AUD, NOW + 1000, 30, VerifyPolicy::PqOptional, &mut nonces)
            .unwrap_err();
        assert!(matches!(err, AuthError::TimeWindow));
    }

    #[test]
    fn replay_rejected() {
        let (mut nonces, challenge) = setup();
        let signer = SoftwareSigner::generate_ed25519();
        let resp = signer.respond(&challenge).unwrap();
        // First use succeeds.
        verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces).unwrap();
        // Replay of the same valid response is rejected.
        let err = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces)
            .unwrap_err();
        assert!(matches!(err, AuthError::NonceReplay));
    }

    #[test]
    fn unknown_nonce_rejected() {
        // A response whose challenge was never issued by this verifier's store.
        let mut nonces = InMemoryNonceStore::new();
        let foreign = Challenge {
            version: VERSION,
            audience: AUD.to_string(),
            nonce: vec![9u8; 16],
            issued_at: NOW,
            expires_at: NOW + 120,
        };
        let signer = SoftwareSigner::generate_ed25519();
        let resp = signer.respond(&foreign).unwrap();
        let err = verify_response(&resp, AUD, NOW, 30, VerifyPolicy::PqOptional, &mut nonces)
            .unwrap_err();
        assert!(matches!(err, AuthError::NonceReplay));
    }

    #[test]
    fn fingerprint_commits_to_algorithm() {
        // Same 32 bytes interpreted under different algs must not collide.
        let ed = ClassicalPublicKey { alg: ClassicalAlg::Ed25519, bytes: vec![7u8; 32] };
        let p2 = ClassicalPublicKey { alg: ClassicalAlg::P256, bytes: vec![7u8; 32] };
        assert_ne!(ed.fingerprint(), p2.fingerprint());
    }
}
