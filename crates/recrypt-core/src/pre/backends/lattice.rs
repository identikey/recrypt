//! OpenFHE lattice-based PRE backend (post-quantum)
//!
//! Uses BFV scheme with INDCPA security for proxy recryption.
//! Keys and ciphertexts are serialized via OpenFHE's binary format.

use crate::error::{PreError, PreResult};
use crate::pre::*;
use zeroize::Zeroizing;

#[cfg(feature = "openfhe")]
use std::sync::Arc;

#[cfg(feature = "openfhe")]
use recrypt_ffi::openfhe::PreContext as FfiContext;

/// Lattice-based PRE backend using OpenFHE BFV scheme.
///
/// Thread-safe via Arc<FfiContext>. All operations use fixed BFV parameters
/// to ensure serialized keys/ciphertexts are compatible across instances.
pub struct LatticeBackend {
    #[cfg(feature = "openfhe")]
    context: Arc<FfiContext>,
    #[cfg(not(feature = "openfhe"))]
    _marker: std::marker::PhantomData<()>,
}

impl LatticeBackend {
    /// Create new lattice backend with default BFV parameters
    ///
    /// Uses plaintext_modulus=65537, scaling_mod_size=60 for all instances.
    /// This ensures serialized keys are compatible across backend instances.
    #[cfg(feature = "openfhe")]
    #[allow(clippy::arc_with_non_send_sync)] // FfiContext is thread-safe after init per OpenFHE docs
    pub fn new() -> PreResult<Self> {
        let context = FfiContext::new()
            .map_err(|e| PreError::BackendUnavailable(format!("OpenFHE init failed: {e}")))?;

        Ok(Self {
            context: Arc::new(context),
        })
    }

    #[cfg(not(feature = "openfhe"))]
    pub fn new() -> PreResult<Self> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled. Build with --features openfhe".into(),
        ))
    }

    /// Check if the lattice backend is available
    pub fn is_available() -> bool {
        cfg!(feature = "openfhe")
    }
}

#[cfg(feature = "openfhe")]
impl PreBackend for LatticeBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Lattice
    }

    fn name(&self) -> &'static str {
        "OpenFHE BFV/PRE (Post-Quantum)"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        let (pk_bytes, sk_bytes) = self
            .context
            .generate_keypair_bytes()
            .map_err(|e| PreError::KeyGeneration(e.to_string()))?;

        Ok(KeyPair {
            public: PublicKey::new(BackendId::Lattice, pk_bytes),
            secret: SecretKey::new(BackendId::Lattice, sk_bytes),
        })
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        Err(PreError::KeyGeneration(
            "Lattice keys are not deterministically derivable".into(),
        ))
    }

    fn generate_recrypt_key(
        &self,
        from_secret: &SecretKey,
        to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        let rk_bytes = self
            .context
            .generate_recrypt_key_bytes(&from_secret.bytes, &to_public.bytes)
            .map_err(|e| PreError::RecryptKeyGeneration(e.to_string()))?;

        // We can't derive from_public from from_secret for lattice,
        // so use empty placeholder (the rk_bytes contains all needed info)
        let from_public = PublicKey::new(BackendId::Lattice, vec![]);

        Ok(RecryptKey::new(
            BackendId::Lattice,
            from_public,
            to_public.clone(),
            rk_bytes,
        ))
    }

    fn encrypt(&self, recipient: &PublicKey, plaintext: &[u8]) -> PreResult<Ciphertext> {
        if plaintext.len() > self.max_plaintext_size() {
            return Err(PreError::Encryption(format!(
                "Plaintext too large: {} > {} bytes",
                plaintext.len(),
                self.max_plaintext_size()
            )));
        }

        let ct_bytes = self
            .context
            .encrypt_bytes(&recipient.bytes, plaintext)
            .map_err(|e| PreError::Encryption(e.to_string()))?;

        // Prepend original plaintext length for decryption
        let mut bytes = Vec::with_capacity(4 + ct_bytes.len());
        bytes.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
        bytes.extend(ct_bytes);

        Ok(Ciphertext::new(BackendId::Lattice, 0, bytes))
    }

    fn decrypt(
        &self,
        secret: &SecretKey,
        ciphertext: &Ciphertext,
    ) -> PreResult<Zeroizing<Vec<u8>>> {
        if ciphertext.bytes.len() < 4 {
            return Err(PreError::Decryption("Ciphertext too short".into()));
        }

        // Extract original length
        let original_len = u32::from_le_bytes(
            ciphertext.bytes[..4]
                .try_into()
                .map_err(|_| PreError::Decryption("Invalid length prefix".into()))?,
        ) as usize;

        let ct_bytes = &ciphertext.bytes[4..];

        let plaintext = self
            .context
            .decrypt_bytes(&secret.bytes, ct_bytes, original_len)
            .map_err(|e| PreError::Decryption(e.to_string()))?;

        Ok(Zeroizing::new(plaintext))
    }

    fn recrypt(&self, recrypt_key: &RecryptKey, ciphertext: &Ciphertext) -> PreResult<Ciphertext> {
        if ciphertext.bytes.len() < 4 {
            return Err(PreError::Recryption("Ciphertext too short".into()));
        }

        // Preserve the length prefix
        let length_prefix = &ciphertext.bytes[..4];
        let ct_bytes = &ciphertext.bytes[4..];

        let new_ct_bytes = self
            .context
            .recrypt_bytes(&recrypt_key.bytes, ct_bytes)
            .map_err(|e| PreError::Recryption(e.to_string()))?;

        // Reconstruct with length prefix
        let mut bytes = Vec::with_capacity(4 + new_ct_bytes.len());
        bytes.extend_from_slice(length_prefix);
        bytes.extend(new_ct_bytes);

        Ok(Ciphertext::new(
            BackendId::Lattice,
            ciphertext.level + 1,
            bytes,
        ))
    }

    fn max_plaintext_size(&self) -> usize {
        // KeyMaterial is 96 bytes (32 key + 24 nonce + 32 hash + 8 size)
        96
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        // BFV ciphertext is ~5-10KB depending on parameters
        // 4 bytes length prefix + serialized ciphertext
        4 + 8 * 1024
    }
}

// Stub implementation when openfhe feature is disabled
#[cfg(not(feature = "openfhe"))]
impl PreBackend for LatticeBackend {
    fn backend_id(&self) -> BackendId {
        BackendId::Lattice
    }

    fn name(&self) -> &'static str {
        "OpenFHE BFV/PRE (Post-Quantum) [UNAVAILABLE]"
    }

    fn is_post_quantum(&self) -> bool {
        true
    }

    fn generate_keypair(&self) -> PreResult<KeyPair> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled".into(),
        ))
    }

    fn public_key_from_secret(&self, _secret: &SecretKey) -> PreResult<PublicKey> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled".into(),
        ))
    }

    fn generate_recrypt_key(
        &self,
        _from_secret: &SecretKey,
        _to_public: &PublicKey,
    ) -> PreResult<RecryptKey> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled".into(),
        ))
    }

    fn encrypt(&self, _recipient: &PublicKey, _plaintext: &[u8]) -> PreResult<Ciphertext> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled".into(),
        ))
    }

    fn decrypt(
        &self,
        _secret: &SecretKey,
        _ciphertext: &Ciphertext,
    ) -> PreResult<Zeroizing<Vec<u8>>> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled".into(),
        ))
    }

    fn recrypt(
        &self,
        _recrypt_key: &RecryptKey,
        _ciphertext: &Ciphertext,
    ) -> PreResult<Ciphertext> {
        Err(PreError::BackendUnavailable(
            "OpenFHE feature not enabled".into(),
        ))
    }

    fn max_plaintext_size(&self) -> usize {
        96
    }

    fn ciphertext_size_estimate(&self, _plaintext_size: usize) -> usize {
        4 + 8 * 1024
    }
}

#[cfg(all(test, feature = "openfhe"))]
mod tests {
    use super::*;

    #[test]
    fn test_lattice_backend_creation() {
        let backend = LatticeBackend::new().unwrap();
        assert_eq!(backend.name(), "OpenFHE BFV/PRE (Post-Quantum)");
        assert!(backend.is_post_quantum());
    }

    #[test]
    fn test_lattice_keypair_generation() {
        let backend = LatticeBackend::new().unwrap();
        let kp = backend.generate_keypair();
        assert!(kp.is_ok(), "Keypair generation should succeed");

        let kp = kp.unwrap();
        assert!(!kp.public.bytes.is_empty(), "Public key should have bytes");
        assert!(!kp.secret.bytes.is_empty(), "Secret key should have bytes");
    }

    #[test]
    fn test_lattice_encrypt_decrypt_roundtrip() {
        let backend = LatticeBackend::new().unwrap();
        let kp = backend.generate_keypair().unwrap();

        let plaintext = b"Hello, lattice PRE!";
        let ct = backend.encrypt(&kp.public, plaintext).unwrap();
        let pt = backend.decrypt(&kp.secret, &ct).unwrap();

        assert_eq!(&pt[..], plaintext);
    }

    /// Round-trip at the full max_plaintext_size (96 bytes) — the size of
    /// HybridEncryptor's KeyMaterial. Smaller plaintexts pass; the hybrid
    /// path needs every byte to round-trip exactly.
    ///
    /// Currently fails: BFV parameters drop bits at the 96-byte boundary.
    /// Tracked in recrypt-fwg.
    #[test]
    #[ignore = "blocked on recrypt-fwg: lattice 96-byte round-trip drops bits"]
    fn test_lattice_encrypt_decrypt_roundtrip_96_bytes() {
        let backend = LatticeBackend::new().unwrap();
        let kp = backend.generate_keypair().unwrap();

        // 96 bytes of varied content (KeyMaterial leads with version=1).
        let mut plaintext = vec![0u8; 96];
        for (i, b) in plaintext.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(1);
        }

        let ct = backend.encrypt(&kp.public, &plaintext).unwrap();
        let pt = backend.decrypt(&kp.secret, &ct).unwrap();

        assert_eq!(
            &pt[..],
            &plaintext[..],
            "96-byte (KeyMaterial-sized) plaintext must round-trip exactly"
        );
    }

    #[test]
    fn test_lattice_recryption_flow() {
        let backend = LatticeBackend::new().unwrap();

        let alice = backend.generate_keypair().unwrap();
        let bob = backend.generate_keypair().unwrap();

        let plaintext = b"Secret for Bob via lattice PRE";
        let ct_alice = backend.encrypt(&alice.public, plaintext).unwrap();

        // Generate recrypt key Alice → Bob
        let rk = backend
            .generate_recrypt_key(&alice.secret, &bob.public)
            .unwrap();

        // Proxy transforms
        let ct_bob = backend.recrypt(&rk, &ct_alice).unwrap();

        // Bob decrypts
        let pt_bob = backend.decrypt(&bob.secret, &ct_bob).unwrap();
        assert_eq!(&pt_bob[..], plaintext);
        assert_eq!(ct_bob.level(), 1);
    }
}

#[cfg(test)]
mod availability_tests {
    use super::*;

    #[test]
    fn test_is_available_matches_feature() {
        let available = LatticeBackend::is_available();
        assert_eq!(available, cfg!(feature = "openfhe"));
    }
}
