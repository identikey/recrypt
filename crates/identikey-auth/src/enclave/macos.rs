//! macOS **Secure Enclave** P-256 signer with **Touch ID** gating.
//!
//! The private key is generated inside the Secure Enclave and never leaves it; signing
//! happens in-hardware and the OS presents the Touch ID sheet automatically (the key's
//! `SecAccessControl` carries the biometry-current-set + private-key-usage flags).
//!
//! Design: the struct holds only the keychain **label** and the cached compressed
//! public key — both `Send + Sync` — and re-loads the (`!Send`) `SecKey` from the
//! keychain on each signature. That keeps [`SecureEnclaveSigner`] `Send + Sync` (required
//! by [`Signer`]) and means the durable key lives in the keychain, referenced by label.
//!
//! ## Requirements (verify on a signed build)
//! Creating Secure-Enclave keys requires the binary to be **code-signed** with a
//! `keychain-access-groups` entitlement (Papyrus's `entitlements.plist` adds one).
//! Unsigned `cargo test` binaries cannot create SEP keys — use the [software
//! signer](crate::SoftwareSigner) for headless CI and this backend on the signed app.
//!
//! ## Scope
//! This implements the **P-256-in-enclave** mode (§8, the preferred mode). The Ed25519
//! "wrap the seed under an enclave P-256 key" fallback (§8) is a tracked follow-on.

use core_foundation::base::CFOptionFlags;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};

use crate::algorithm::ClassicalAlg;
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature};
use crate::signer::Signer;

/// A Secure-Enclave-backed P-256 signer (Touch ID gated).
pub struct SecureEnclaveSigner {
    label: String,
    public_key: ClassicalPublicKey,
}

impl SecureEnclaveSigner {
    /// Load the Secure Enclave key stored under `label`, or generate a new one if none
    /// exists. The label is the keychain item label identifying this device identity.
    pub fn load_or_create(label: &str) -> Result<Self> {
        let key = match load_seckey(label)? {
            Some(k) => k,
            None => generate_sep_key(label)?,
        };
        let public_key = pubkey_from_seckey(&key)?;
        Ok(Self {
            label: label.to_string(),
            public_key,
        })
    }

    /// Whether a Secure Enclave key already exists for `label`.
    pub fn exists(label: &str) -> Result<bool> {
        Ok(load_seckey(label)?.is_some())
    }
}

impl Signer for SecureEnclaveSigner {
    fn classical_public_key(&self) -> ClassicalPublicKey {
        self.public_key.clone()
    }

    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature> {
        let key = load_seckey(&self.label)?
            .ok_or_else(|| AuthError::Backend("Secure Enclave key not found".into()))?;
        // Touch ID is presented here. `…MessageX962SHA256` hashes `payload` with SHA-256
        // and returns an X9.62/DER ECDSA signature.
        let der = key
            .create_signature(Algorithm::ECDSASignatureMessageX962SHA256, payload)
            .map_err(|e| AuthError::Backend(format!("Secure Enclave sign: {e}")))?;
        // Convert DER → fixed 64-byte r‖s to match the protocol's P-256 signature form.
        let sig = p256::ecdsa::Signature::from_der(&der)
            .map_err(|_| AuthError::Backend("malformed ECDSA DER from Secure Enclave".into()))?;
        Ok(ClassicalSignature {
            alg: ClassicalAlg::P256,
            bytes: sig.to_bytes().to_vec(),
        })
    }
}

/// Generate a new P-256 key inside the Secure Enclave, biometric-gated, stored under `label`.
fn generate_sep_key(label: &str) -> Result<SecKey> {
    // Require biometric (current enrolled set) AND mark the key for private-key signing use.
    let flags: CFOptionFlags =
        kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet;
    let access = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        flags,
    )
    .map_err(|e| AuthError::Backend(format!("access control: {e}")))?;

    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(access)
        .set_label(label);

    SecKey::new(&opts).map_err(|e| AuthError::Backend(format!("Secure Enclave keygen: {e}")))
}

/// Find a key in the keychain by label; `None` if absent.
fn load_seckey(label: &str) -> Result<Option<SecKey>> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .label(label)
        .load_refs(true)
        .limit(1)
        .search();
    match results {
        Ok(items) => {
            for item in items {
                if let SearchResult::Ref(Reference::Key(k)) = item {
                    return Ok(Some(k));
                }
            }
            Ok(None)
        }
        // A "not found" error is expected when no key exists yet.
        Err(_) => Ok(None),
    }
}

/// Extract a compressed P-256 public key from a `SecKey`.
fn pubkey_from_seckey(key: &SecKey) -> Result<ClassicalPublicKey> {
    let pubk = key
        .public_key()
        .ok_or_else(|| AuthError::Backend("no public key on Secure Enclave key".into()))?;
    let data = pubk
        .external_representation()
        .ok_or_else(|| AuthError::Backend("cannot export public key".into()))?;
    // EC external representation is the uncompressed point 0x04‖X‖Y; compress it.
    let point = p256::PublicKey::from_sec1_bytes(data.bytes())
        .map_err(|_| AuthError::Backend("invalid EC public point".into()))?;
    Ok(ClassicalPublicKey {
        alg: ClassicalAlg::P256,
        bytes: point.to_encoded_point(true).as_bytes().to_vec(),
    })
}
