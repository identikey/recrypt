//! macOS **Secure Enclave** P-256 signer with **Touch ID** gating.
//!
//! The private key is generated inside the Secure Enclave and never leaves it; signing
//! happens in-hardware and the OS presents the Touch ID sheet automatically (the key's
//! `SecAccessControl` carries the biometry-current-set + private-key-usage flags).
//!
//! Two constructors:
//! - [`SecureEnclaveSigner::create_ephemeral`] — a session-only SEP key, NOT written to
//!   the keychain. Needs no entitlement; used by tooling/CI and the `enclave_demo`
//!   example to exercise the full Touch-ID-sign-and-verify path.
//! - [`SecureEnclaveSigner::load_or_create`] — a persistent device key stored in the
//!   file keychain. Persisting a SEP key requires the `keychain-access-groups`
//!   entitlement (errSecMissingEntitlement / -34018 otherwise). This works in the
//!   code-signed Papyrus `.app` (whose identity matches the access group) — see
//!   `Papyrus/src-tauri/entitlements.plist`.
//!
//! Either way this implements the **P-256-in-enclave** mode (§8). The Ed25519
//! "wrap the seed under an enclave P-256 key" fallback (§8) is a tracked follow-on.

use core_foundation::base::CFOptionFlags;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::item::{
    ItemClass, ItemSearchOptions, KeyClass, Location, Reference, SearchResult,
};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};

use crate::algorithm::ClassicalAlg;
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature};
use crate::signer::Signer;

/// `SecKey` wrapper asserting thread-safety.
///
/// SAFETY: Apple's Security framework is documented thread-safe, and a `SecKeyRef` is a
/// reference-counted CoreFoundation object whose operations (`SecKeyCreateSignature`,
/// `SecKeyCopyPublicKey`) may be invoked from any thread. Holding and using it across
/// threads is sound; only the default `!Send` of the raw CF pointer type requires this.
struct SendKey(SecKey);
unsafe impl Send for SendKey {}
unsafe impl Sync for SendKey {}

/// A Secure-Enclave-backed P-256 signer (Touch ID gated).
pub struct SecureEnclaveSigner {
    key: SendKey,
    public_key: ClassicalPublicKey,
}

impl SecureEnclaveSigner {
    /// Generate a **session-only** Secure Enclave key (not persisted to the keychain).
    /// Requires no entitlement. The key is usable only for the lifetime of this value.
    pub fn create_ephemeral(label: &str) -> Result<Self> {
        let key = generate_sep_key(label, false)?;
        Self::from_seckey(key)
    }

    /// Load the persistent Secure Enclave device key stored under `label`, or create and
    /// persist a new one. Persisting requires the `keychain-access-groups` entitlement
    /// (see module docs); use [`create_ephemeral`](Self::create_ephemeral) for unsigned
    /// tooling.
    pub fn load_or_create(label: &str) -> Result<Self> {
        let key = match load_seckey(label)? {
            Some(k) => k,
            None => generate_sep_key(label, true)?,
        };
        Self::from_seckey(key)
    }

    /// Whether a persistent Secure Enclave key already exists for `label`.
    pub fn exists(label: &str) -> Result<bool> {
        Ok(load_seckey(label)?.is_some())
    }

    fn from_seckey(key: SecKey) -> Result<Self> {
        let public_key = pubkey_from_seckey(&key)?;
        Ok(Self {
            key: SendKey(key),
            public_key,
        })
    }
}

impl Signer for SecureEnclaveSigner {
    fn classical_public_key(&self) -> ClassicalPublicKey {
        self.public_key.clone()
    }

    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature> {
        // Touch ID is presented here. `…MessageX962SHA256` hashes `payload` with SHA-256
        // and returns an X9.62/DER ECDSA signature.
        let der = self
            .key
            .0
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

/// Generate a P-256 key inside the Secure Enclave, biometric-gated. When `persist` is
/// true the key is written to the file keychain (needs the keychain entitlement);
/// otherwise it is session-only.
fn generate_sep_key(label: &str, persist: bool) -> Result<SecKey> {
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
    if persist {
        // security-framework only sets kSecAttrIsPermanent when a location is present.
        // DefaultFileKeychain avoids the data-protection keychain (which would also need
        // the entitlement); persisting still requires keychain-access-groups.
        opts.set_location(Location::DefaultFileKeychain);
    }

    SecKey::new(&opts).map_err(|e| AuthError::Backend(format!("Secure Enclave keygen: {e}")))
}

/// Find a persistent private key in the keychain by label; `None` if absent.
fn load_seckey(label: &str) -> Result<Option<SecKey>> {
    let results = ItemSearchOptions::new()
        .class(ItemClass::key())
        .key_class(KeyClass::private())
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
