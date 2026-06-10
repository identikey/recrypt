//! OpenFHE Proxy Recryption bindings
//!
//! Provides lattice-based PRE via the BFV scheme with INDCPA security.

mod pre;

pub use pre::{bytes_to_coefficients, coefficients_to_bytes};

use crate::error::FfiError;

#[cfg(feature = "openfhe")]
use recrypt_openfhe_sys::ffi as openfhe;

/// A public key for encryption
pub struct PublicKey {
    #[cfg(feature = "openfhe")]
    pub(crate) inner: cxx::UniquePtr<openfhe::PublicKey>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

#[cfg(feature = "openfhe")]
impl PublicKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, FfiError> {
        Ok(openfhe::serialize_public_key(&self.inner)?)
    }
}

/// A secret key for decryption
pub struct SecretKey {
    #[cfg(feature = "openfhe")]
    pub(crate) inner: cxx::UniquePtr<openfhe::PrivateKey>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

#[cfg(feature = "openfhe")]
impl SecretKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, FfiError> {
        Ok(openfhe::serialize_private_key(&self.inner)?)
    }
}

/// A keypair containing both public and secret keys
pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

/// A ciphertext encrypted under a public key
pub struct Ciphertext {
    #[cfg(feature = "openfhe")]
    pub(crate) inner: cxx::UniquePtr<openfhe::Ciphertext>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

#[cfg(feature = "openfhe")]
impl Ciphertext {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, FfiError> {
        Ok(openfhe::serialize_ciphertext(&self.inner)?)
    }
}

/// A recryption key for transforming ciphertexts
pub struct RecryptKey {
    #[cfg(feature = "openfhe")]
    pub(crate) inner: cxx::UniquePtr<openfhe::RecryptKey>,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

#[cfg(feature = "openfhe")]
impl RecryptKey {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, FfiError> {
        Ok(openfhe::serialize_recrypt_key(&self.inner)?)
    }
}

/// PRE-enabled crypto context using BFV scheme
pub struct PreContext {
    #[cfg(feature = "openfhe")]
    inner: cxx::UniquePtr<openfhe::CryptoContext>,
    #[cfg(feature = "openfhe")]
    ring_dimension: u32,
    #[cfg(not(feature = "openfhe"))]
    _private: (),
}

// SAFETY: OpenFHE CryptoContext is thread-safe after initialization.
// The context uses internal locking for concurrent operations.
// Key operations (encrypt/decrypt/recrypt) can run in parallel on different data.
// See: docs/openfhe-threading-model.md
#[cfg(feature = "openfhe")]
unsafe impl Send for PreContext {}
#[cfg(feature = "openfhe")]
unsafe impl Sync for PreContext {}

#[cfg(feature = "openfhe")]
impl PreContext {
    /// Create a new PRE context with default parameters
    ///
    /// Uses BFVrns with plaintext_modulus = 65537
    pub fn new() -> Result<Self, FfiError> {
        let ctx = openfhe::create_bfv_context(65537, 60)?;
        if ctx.is_null() {
            return Err(FfiError::OpenFhe("Failed to create BFV context".into()));
        }

        openfhe::enable_pke(&ctx)?;
        openfhe::enable_keyswitch(&ctx)?;
        openfhe::enable_leveledshe(&ctx)?;
        openfhe::enable_pre(&ctx)?;

        let ring_dimension = openfhe::get_ring_dimension(&ctx)?;

        Ok(Self {
            inner: ctx,
            ring_dimension,
        })
    }

    /// Get the number of slots available for packing data
    pub fn slot_count(&self) -> u32 {
        self.ring_dimension
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> Result<KeyPair, FfiError> {
        let kp = openfhe::keygen(&self.inner)?;
        if kp.is_null() {
            return Err(FfiError::OpenFhe("Failed to generate keypair".into()));
        }

        let pk = openfhe::get_public_key(&kp)?;
        let sk = openfhe::get_private_key(&kp)?;

        Ok(KeyPair {
            public: PublicKey { inner: pk },
            secret: SecretKey { inner: sk },
        })
    }

    /// Encrypt raw bytes for a recipient
    ///
    /// Data is converted to coefficients and may be split across multiple ciphertexts
    /// if it exceeds the slot capacity.
    pub fn encrypt(&self, pk: &PublicKey, data: &[u8]) -> Result<Vec<Ciphertext>, FfiError> {
        let coeffs = bytes_to_coefficients(data);
        let slot_count = self.slot_count() as usize;

        let mut ciphertexts = Vec::new();
        for chunk in coeffs.chunks(slot_count) {
            // Pad to full slot count
            let mut padded = chunk.to_vec();
            padded.resize(slot_count, 0);

            let pt = openfhe::make_packed_plaintext(&self.inner, &padded)?;
            let ct = openfhe::encrypt(&self.inner, &pk.inner, &pt)?;

            if ct.is_null() {
                return Err(FfiError::OpenFhe("Encryption failed".into()));
            }

            ciphertexts.push(Ciphertext { inner: ct });
        }

        Ok(ciphertexts)
    }

    /// Decrypt ciphertexts and return raw bytes
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        ciphertexts: &[Ciphertext],
        original_len: usize,
    ) -> Result<Vec<u8>, FfiError> {
        let mut all_coeffs = Vec::new();

        for ct in ciphertexts {
            let pt = openfhe::decrypt(&self.inner, &sk.inner, &ct.inner)?;
            if pt.is_null() {
                return Err(FfiError::OpenFhe("Decryption failed".into()));
            }

            let coeffs = openfhe::get_packed_value(&pt)?;
            all_coeffs.extend(coeffs);
        }

        // Convert back to bytes
        let coeff_count = original_len.div_ceil(2);
        let bytes = coefficients_to_bytes(
            &all_coeffs[..coeff_count.min(all_coeffs.len())],
            original_len,
        );

        Ok(bytes)
    }

    /// Generate a recryption key from one user to another
    pub fn generate_recrypt_key(
        &self,
        from_sk: &SecretKey,
        to_pk: &PublicKey,
    ) -> Result<RecryptKey, FfiError> {
        let rk = openfhe::generate_recrypt_key(&self.inner, &from_sk.inner, &to_pk.inner)?;
        if rk.is_null() {
            return Err(FfiError::OpenFhe(
                "Failed to generate recryption key".into(),
            ));
        }

        Ok(RecryptKey { inner: rk })
    }

    /// Transform ciphertexts from one recipient to another
    pub fn recrypt(
        &self,
        rk: &RecryptKey,
        ciphertexts: &[Ciphertext],
    ) -> Result<Vec<Ciphertext>, FfiError> {
        let mut result = Vec::with_capacity(ciphertexts.len());

        for ct in ciphertexts {
            let new_ct = openfhe::recrypt(&self.inner, &rk.inner, &ct.inner)?;
            if new_ct.is_null() {
                return Err(FfiError::OpenFhe("Recryption failed".into()));
            }
            result.push(Ciphertext { inner: new_ct });
        }

        Ok(result)
    }

    // --- Deserialization methods for byte-based operations ---

    /// Deserialize a public key from bytes
    pub fn deserialize_public_key(&self, data: &[u8]) -> Result<PublicKey, FfiError> {
        let pk = openfhe::deserialize_public_key(&self.inner, data)?;
        if pk.is_null() {
            return Err(FfiError::OpenFhe("Failed to deserialize public key".into()));
        }
        Ok(PublicKey { inner: pk })
    }

    /// Deserialize a secret key from bytes
    pub fn deserialize_secret_key(&self, data: &[u8]) -> Result<SecretKey, FfiError> {
        let sk = openfhe::deserialize_private_key(&self.inner, data)?;
        if sk.is_null() {
            return Err(FfiError::OpenFhe("Failed to deserialize secret key".into()));
        }
        Ok(SecretKey { inner: sk })
    }

    /// Deserialize a ciphertext from bytes
    pub fn deserialize_ciphertext(&self, data: &[u8]) -> Result<Ciphertext, FfiError> {
        let ct = openfhe::deserialize_ciphertext(&self.inner, data)?;
        if ct.is_null() {
            return Err(FfiError::OpenFhe("Failed to deserialize ciphertext".into()));
        }
        Ok(Ciphertext { inner: ct })
    }

    /// Deserialize a recrypt key from bytes
    pub fn deserialize_recrypt_key(&self, data: &[u8]) -> Result<RecryptKey, FfiError> {
        let rk = openfhe::deserialize_recrypt_key(&self.inner, data)?;
        if rk.is_null() {
            return Err(FfiError::OpenFhe(
                "Failed to deserialize recrypt key".into(),
            ));
        }
        Ok(RecryptKey { inner: rk })
    }

    // --- High-level byte-based operations for LatticeBackend ---

    /// Generate keypair and return serialized bytes
    pub fn generate_keypair_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), FfiError> {
        let kp = self.generate_keypair()?;
        Ok((kp.public.to_bytes()?, kp.secret.to_bytes()?))
    }

    /// Encrypt data using serialized public key, return serialized ciphertext
    pub fn encrypt_bytes(&self, pk_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>, FfiError> {
        let pk = self.deserialize_public_key(pk_bytes)?;
        let ciphertexts = self.encrypt(&pk, data)?;

        // For single-ciphertext case (data <= 96 bytes), just serialize that
        if ciphertexts.len() != 1 {
            return Err(FfiError::OpenFhe(format!(
                "Expected 1 ciphertext, got {}",
                ciphertexts.len()
            )));
        }

        ciphertexts[0].to_bytes()
    }

    /// Decrypt using serialized secret key
    pub fn decrypt_bytes(
        &self,
        sk_bytes: &[u8],
        ct_bytes: &[u8],
        original_len: usize,
    ) -> Result<Vec<u8>, FfiError> {
        let sk = self.deserialize_secret_key(sk_bytes)?;
        let ct = self.deserialize_ciphertext(ct_bytes)?;
        self.decrypt(&sk, &[ct], original_len)
    }

    /// Generate recrypt key from serialized keys, return serialized recrypt key
    pub fn generate_recrypt_key_bytes(
        &self,
        from_sk_bytes: &[u8],
        to_pk_bytes: &[u8],
    ) -> Result<Vec<u8>, FfiError> {
        let from_sk = self.deserialize_secret_key(from_sk_bytes)?;
        let to_pk = self.deserialize_public_key(to_pk_bytes)?;
        let rk = self.generate_recrypt_key(&from_sk, &to_pk)?;
        rk.to_bytes()
    }

    /// Recrypt using serialized recrypt key, return serialized ciphertext
    pub fn recrypt_bytes(&self, rk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>, FfiError> {
        let rk = self.deserialize_recrypt_key(rk_bytes)?;
        let ct = self.deserialize_ciphertext(ct_bytes)?;
        let result = self.recrypt(&rk, &[ct])?;

        if result.len() != 1 {
            return Err(FfiError::OpenFhe(format!(
                "Expected 1 ciphertext, got {}",
                result.len()
            )));
        }

        result[0].to_bytes()
    }
}

// Stub implementation when openfhe feature is disabled
#[cfg(not(feature = "openfhe"))]
impl PreContext {
    pub fn new() -> Result<Self, FfiError> {
        Err(FfiError::OpenFhe(
            "OpenFHE feature not enabled. Build with --features openfhe".into(),
        ))
    }

    pub fn slot_count(&self) -> u32 {
        0
    }

    pub fn generate_keypair(&self) -> Result<KeyPair, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn encrypt(&self, _pk: &PublicKey, _data: &[u8]) -> Result<Vec<Ciphertext>, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn decrypt(
        &self,
        _sk: &SecretKey,
        _ciphertexts: &[Ciphertext],
        _original_len: usize,
    ) -> Result<Vec<u8>, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn generate_recrypt_key(
        &self,
        _from_sk: &SecretKey,
        _to_pk: &PublicKey,
    ) -> Result<RecryptKey, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }

    pub fn recrypt(
        &self,
        _rk: &RecryptKey,
        _ciphertexts: &[Ciphertext],
    ) -> Result<Vec<Ciphertext>, FfiError> {
        Err(FfiError::OpenFhe("OpenFHE feature not enabled".into()))
    }
}

#[cfg(all(test, feature = "openfhe"))]
mod tests {
    use super::*;

    #[test]
    fn test_pre_context_creation() {
        let ctx = PreContext::new().unwrap();
        assert!(ctx.slot_count() > 0);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx = PreContext::new().unwrap();
        let kp = ctx.generate_keypair().unwrap();

        let data = b"Hello, PRE!";
        let ciphertexts = ctx.encrypt(&kp.public, data).unwrap();
        let decrypted = ctx.decrypt(&kp.secret, &ciphertexts, data.len()).unwrap();

        assert_eq!(&decrypted[..], data);
    }

    #[test]
    fn test_pre_recryption_flow() {
        let ctx = PreContext::new().unwrap();

        // Alice and Bob
        let alice = ctx.generate_keypair().unwrap();
        let bob = ctx.generate_keypair().unwrap();

        // Alice encrypts
        let data = b"Secret message for recryption";
        let ct_alice = ctx.encrypt(&alice.public, data).unwrap();

        // Generate recryption key Alice → Bob
        let rk = ctx
            .generate_recrypt_key(&alice.secret, &bob.public)
            .unwrap();

        // Proxy transforms
        let ct_bob = ctx.recrypt(&rk, &ct_alice).unwrap();

        // Bob decrypts
        let decrypted = ctx.decrypt(&bob.secret, &ct_bob, data.len()).unwrap();

        assert_eq!(&decrypted[..], data);
    }
}
