//! Signing + verification backends.
//!
//! [`Signer`] is the abstraction the platform enclave backends (Apple Secure Enclave,
//! Windows TPM, …) will implement; [`SoftwareSigner`] is the working in-process
//! reference used for dev, CI, and the wrapped-seed fallback. Low-level
//! [`verify_classical`] / [`verify_pq`] are pure functions usable by any verifier.

use crate::algorithm::{ClassicalAlg, PqAlg};
use crate::challenge::{signing_payload, Challenge, Response};
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature, PqPublicKey, PqSignature};

/// Something that can answer an authentication challenge by signing.
///
/// Implementors provide the classical key + signing operation (and optionally a PQ
/// key); [`Signer::respond`] assembles the full [`Response`] with correct
/// domain-separation, so backends never touch the wire format.
pub trait Signer: Send + Sync {
    fn classical_public_key(&self) -> ClassicalPublicKey;
    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature>;

    fn pq_public_key(&self) -> Option<PqPublicKey> {
        None
    }
    fn sign_pq(&self, _payload: &[u8]) -> Result<Option<PqSignature>> {
        Ok(None)
    }

    /// Produce a [`Response`] to `challenge`, signing the domain-separated payload.
    fn respond(&self, challenge: &Challenge) -> Result<Response> {
        let chal = challenge.to_bytes();
        let payload = signing_payload(&chal);
        let signature = self.sign_classical(&payload)?;
        let pq = match (self.pq_public_key(), self.sign_pq(&payload)?) {
            (Some(pk), Some(sig)) => Some((pk, sig)),
            _ => None,
        };
        Ok(Response {
            challenge_bytes: chal,
            public_key: self.classical_public_key(),
            signature,
            pq,
        })
    }
}

// ----------------------------------------------------------------------------
// Software reference signer
// ----------------------------------------------------------------------------

enum ClassicalSecret {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

/// In-process software signer. NOT hardware-backed and performs no biometric check —
/// for dev/CI and as the building block of the enclave wrapped-seed fallback.
pub struct SoftwareSigner {
    classical: ClassicalSecret,
    /// Optional ML-DSA-65 key: (secret, public-key bytes).
    pq: Option<(fips204::ml_dsa_65::PrivateKey, Vec<u8>)>,
}

impl SoftwareSigner {
    /// Generate a fresh Ed25519 software identity.
    pub fn generate_ed25519() -> Self {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        Self {
            classical: ClassicalSecret::Ed25519(sk),
            pq: None,
        }
    }

    /// Generate a fresh P-256 software identity.
    pub fn generate_p256() -> Self {
        let sk = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        Self {
            classical: ClassicalSecret::P256(sk),
            pq: None,
        }
    }

    /// Rebuild an Ed25519 signer from a 32-byte seed (used by the enclave wrapped-seed
    /// fallback, where the seed is unwrapped from hardware into memory for a signature).
    pub fn from_ed25519_seed(seed: [u8; 32]) -> Self {
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        Self {
            classical: ClassicalSecret::Ed25519(sk),
            pq: None,
        }
    }

    /// Attach a freshly generated ML-DSA-65 post-quantum key to this identity.
    pub fn with_ml_dsa_65(mut self) -> Result<Self> {
        use fips204::traits::SerDes;
        let (pk, sk) = fips204::ml_dsa_65::try_keygen()
            .map_err(|e| AuthError::Backend(format!("ml-dsa-65 keygen: {e}")))?;
        self.pq = Some((sk, pk.into_bytes().to_vec()));
        Ok(self)
    }
}

impl Signer for SoftwareSigner {
    fn classical_public_key(&self) -> ClassicalPublicKey {
        match &self.classical {
            ClassicalSecret::Ed25519(sk) => ClassicalPublicKey {
                alg: ClassicalAlg::Ed25519,
                bytes: sk.verifying_key().to_bytes().to_vec(),
            },
            ClassicalSecret::P256(sk) => {
                let vk = sk.verifying_key();
                ClassicalPublicKey {
                    alg: ClassicalAlg::P256,
                    bytes: vk.to_encoded_point(true).as_bytes().to_vec(),
                }
            }
        }
    }

    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature> {
        match &self.classical {
            ClassicalSecret::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                let sig = sk.sign(payload);
                Ok(ClassicalSignature {
                    alg: ClassicalAlg::Ed25519,
                    bytes: sig.to_bytes().to_vec(),
                })
            }
            ClassicalSecret::P256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = sk.sign(payload);
                Ok(ClassicalSignature {
                    alg: ClassicalAlg::P256,
                    bytes: sig.to_bytes().to_vec(),
                })
            }
        }
    }

    fn pq_public_key(&self) -> Option<PqPublicKey> {
        self.pq.as_ref().map(|(_, pk_bytes)| PqPublicKey {
            alg: PqAlg::MlDsa65,
            bytes: pk_bytes.clone(),
        })
    }

    fn sign_pq(&self, payload: &[u8]) -> Result<Option<PqSignature>> {
        match &self.pq {
            None => Ok(None),
            Some((sk, _)) => {
                use fips204::traits::Signer as _;
                let sig = sk
                    .try_sign(payload, &[])
                    .map_err(|e| AuthError::Backend(format!("ml-dsa-65 sign: {e}")))?;
                Ok(Some(PqSignature {
                    alg: PqAlg::MlDsa65,
                    bytes: sig.to_vec(),
                }))
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Low-level verification (pure functions)
// ----------------------------------------------------------------------------

/// Verify a classical signature over `payload`. Returns `Ok(())` on success.
pub fn verify_classical(
    pk: &ClassicalPublicKey,
    payload: &[u8],
    sig: &ClassicalSignature,
) -> Result<()> {
    if pk.alg != sig.alg {
        return Err(AuthError::BadSignature);
    }
    match pk.alg {
        ClassicalAlg::Ed25519 => {
            let kb: [u8; 32] = pk
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::InvalidKey("ed25519"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&kb)
                .map_err(|_| AuthError::InvalidKey("ed25519"))?;
            let sb: [u8; 64] = sig
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::InvalidSig("ed25519"))?;
            let s = ed25519_dalek::Signature::from_bytes(&sb);
            vk.verify_strict(payload, &s)
                .map_err(|_| AuthError::BadSignature)
        }
        ClassicalAlg::P256 => {
            use p256::ecdsa::signature::Verifier as _;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk.bytes)
                .map_err(|_| AuthError::InvalidKey("p256"))?;
            let s = p256::ecdsa::Signature::from_slice(&sig.bytes)
                .map_err(|_| AuthError::InvalidSig("p256"))?;
            vk.verify(payload, &s).map_err(|_| AuthError::BadSignature)
        }
    }
}

/// Verify a post-quantum signature over `payload`.
pub fn verify_pq(pk: &PqPublicKey, payload: &[u8], sig: &PqSignature) -> Result<()> {
    if pk.alg != sig.alg {
        return Err(AuthError::BadSignature);
    }
    use fips204::traits::{SerDes as _, Verifier as _};
    macro_rules! verify_with {
        ($m:path, $name:literal) => {{
            use $m as m;
            let kb: [u8; m::PK_LEN] = pk
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::InvalidKey($name))?;
            let pubk =
                m::PublicKey::try_from_bytes(kb).map_err(|e| AuthError::Backend(format!("{e}")))?;
            let sb: [u8; m::SIG_LEN] = sig
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| AuthError::InvalidSig($name))?;
            if pubk.verify(payload, &sb, &[]) {
                Ok(())
            } else {
                Err(AuthError::BadSignature)
            }
        }};
    }
    match pk.alg {
        PqAlg::MlDsa44 => verify_with!(fips204::ml_dsa_44, "ml-dsa-44"),
        PqAlg::MlDsa65 => verify_with!(fips204::ml_dsa_65, "ml-dsa-65"),
        PqAlg::MlDsa87 => verify_with!(fips204::ml_dsa_87, "ml-dsa-87"),
    }
}
