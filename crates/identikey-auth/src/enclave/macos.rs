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

use ed25519_dalek::{Signer as _, SigningKey};
use rand_core::RngCore;
use zeroize::Zeroize;

use crate::algorithm::ClassicalAlg;
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature};
use crate::signer::Signer;

/// ECIES profile used to wrap the Ed25519 seed under the Secure Enclave P-256 key:
/// cofactor ECDH + X9.63-SHA256 KDF + AES-GCM, with a per-message ephemeral key.
const ECIES: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

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

// ===========================================================================
// Ed25519 identity, wrapped at rest under a Secure Enclave P-256 key (§8).
// ===========================================================================

/// An **Ed25519** identity whose seed is encrypted at rest under a Touch-ID-gated
/// Secure Enclave P-256 key (the SE cannot hold an Ed25519 key directly).
///
/// Wrapping uses the SE key's public half via ECIES (no prompt); each signature unwraps
/// the seed with the SE private key (Touch ID), Ed25519-signs in memory, then zeroizes.
/// The wrapped seed is opaque at rest — only this device's Secure Enclave can decrypt it.
///
/// The seed is briefly present in process memory during a signature — the deliberate,
/// documented compromise of the wrapped-key mode (vs P-256-in-enclave, which never
/// exposes key material). Prefer [`SecureEnclaveSigner`] (P-256) unless an Ed25519
/// identity is specifically required.
pub struct SecureEnclaveEd25519Signer {
    wrapping_key: SendKey,
    wrapped_seed: Vec<u8>,
    public_key: ClassicalPublicKey,
}

impl SecureEnclaveEd25519Signer {
    /// Create an ephemeral Ed25519 identity wrapped under a session-only Secure Enclave
    /// key (no keychain persistence; no entitlement required). For tooling/CI.
    pub fn create_ephemeral(label: &str) -> Result<Self> {
        let key = generate_sep_key(label, false)?;
        let (ed_public, wrapped_seed) = wrap_fresh_ed25519(&key)?;
        Ok(Self {
            wrapping_key: SendKey(key),
            wrapped_seed,
            public_key: ClassicalPublicKey {
                alg: ClassicalAlg::Ed25519,
                bytes: ed_public.to_vec(),
            },
        })
    }

    /// Load a persistent wrapped Ed25519 identity (SE wrapping key in the keychain under
    /// `label`, wrapped seed at `<storage_dir>/device_identity.ed25519.ecies`), or create
    /// and persist one. Persisting the SE key needs the `keychain-access-groups`
    /// entitlement (works in the signed app).
    pub fn load_or_create(label: &str, storage_dir: &std::path::Path) -> Result<Self> {
        let path = storage_dir.join("device_identity.ed25519.ecies");
        let (key, ed_public, wrapped_seed) = match load_seckey(label)? {
            Some(key) => {
                // File layout: ed25519 public key (32 bytes) || ECIES-wrapped seed.
                let blob = std::fs::read(&path)
                    .map_err(|e| AuthError::Backend(format!("read wrapped seed: {e}")))?;
                if blob.len() < 32 {
                    return Err(AuthError::Backend("wrapped seed file too short".into()));
                }
                (key, blob[..32].to_vec(), blob[32..].to_vec())
            }
            None => {
                let key = generate_sep_key(label, true)?;
                let (ed_public, wrapped_seed) = wrap_fresh_ed25519(&key)?;
                std::fs::create_dir_all(storage_dir)
                    .map_err(|e| AuthError::Backend(format!("create storage dir: {e}")))?;
                let mut blob = ed_public.to_vec();
                blob.extend_from_slice(&wrapped_seed);
                std::fs::write(&path, &blob)
                    .map_err(|e| AuthError::Backend(format!("write wrapped seed: {e}")))?;
                (key, ed_public.to_vec(), wrapped_seed)
            }
        };
        Ok(Self {
            wrapping_key: SendKey(key),
            wrapped_seed,
            public_key: ClassicalPublicKey {
                alg: ClassicalAlg::Ed25519,
                bytes: ed_public,
            },
        })
    }
}

impl Signer for SecureEnclaveEd25519Signer {
    fn classical_public_key(&self) -> ClassicalPublicKey {
        self.public_key.clone()
    }

    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature> {
        // Unwrap the seed via the SE private key — Touch ID is presented here.
        let mut seed_bytes = self
            .wrapping_key
            .0
            .decrypt_data(ECIES, &self.wrapped_seed)
            .map_err(|e| AuthError::Backend(format!("Secure Enclave unwrap (Touch ID): {e}")))?;
        let mut seed: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::Backend("unwrapped seed has wrong length".into()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(payload);
        // Scrub the seed from memory (SigningKey zeroizes itself on drop).
        seed.zeroize();
        seed_bytes.zeroize();
        Ok(ClassicalSignature {
            alg: ClassicalAlg::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        })
    }
}

/// Generate a fresh Ed25519 seed, wrap it under the Secure Enclave key's public half
/// (ECIES), and return `(ed25519_public_key, wrapped_seed)`. The seed is zeroized.
fn wrap_fresh_ed25519(se_key: &SecKey) -> Result<([u8; 32], Vec<u8>)> {
    let se_public = se_key
        .public_key()
        .ok_or_else(|| AuthError::Backend("no public key on Secure Enclave key".into()))?;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let ed_public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let wrapped = se_public
        .encrypt_data(ECIES, &seed)
        .map_err(|e| AuthError::Backend(format!("Secure Enclave ECIES wrap: {e}")))?;
    seed.zeroize();
    Ok((ed_public, wrapped))
}
