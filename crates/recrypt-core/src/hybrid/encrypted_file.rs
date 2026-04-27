//! Encrypted file structure (implementation in Phase 2.4)

use crate::error::CoreResult;
use crate::pre::Ciphertext;
use crate::sign::{MultiSig, SigningKeys, VerifyPolicy, VerifyingKeys};

/// An encrypted file with streaming-verifiable integrity
#[derive(Clone, Debug)]
pub struct EncryptedFile {
    /// PRE-encrypted key bundle (contains: key, nonce, plaintext_hash, size)
    pub wrapped_key: Ciphertext,

    /// Bao root hash of ciphertext (for streaming verification)
    pub bao_hash: [u8; 32],

    /// XChaCha20-encrypted data (no auth tag—Bao provides integrity)
    pub ciphertext: Vec<u8>,

    /// Signature over (wrapped_key || bao_hash) - optional for unsigned files
    pub signature: Option<MultiSig>,
}

impl EncryptedFile {
    /// Compute the signature payload
    pub fn signature_payload(&self) -> Vec<u8> {
        let mut payload = self.wrapped_key.to_bytes();
        payload.extend(&self.bao_hash);
        payload
    }

    /// Sign the file with the given keys
    pub fn sign(&mut self, keys: &SigningKeys) -> CoreResult<()> {
        let payload = self.signature_payload();
        self.signature = Some(crate::sign::sign_message(&payload, keys)?);
        Ok(())
    }

    /// Verify the signature under `policy`.
    pub fn verify_signature(&self, pks: &VerifyingKeys, policy: VerifyPolicy) -> CoreResult<bool> {
        match &self.signature {
            Some(sig) => {
                let payload = self.signature_payload();
                crate::sign::verify_message(&payload, sig, pks, policy)
            }
            None => Err(crate::error::CoreError::Verification(
                "No signature present".into(),
            )),
        }
    }
}
