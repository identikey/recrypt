//! Windows **TPM**-backed P-256 signer via CNG (Microsoft Platform Crypto Provider),
//! with optional **Windows Hello** user-presence gating.
//!
//! The private key is generated inside the TPM (`MS_PLATFORM_CRYPTO_PROVIDER`) and signs
//! in-hardware. Unlike macOS's `SecKey`, the CNG handles are plain `usize` newtypes
//! (`Send + Sync`), so we hold them directly and free them on `Drop`.
//!
//! Two constructors mirror the macOS backend:
//! - [`TpmSigner::create_ephemeral`] — an ephemeral TPM key (not persisted, no UI
//!   policy); proves keygen→sign→verify headlessly (e.g. in a VM with a vTPM).
//! - [`TpmSigner::load_or_create`] — a persistent named TPM key for the app. Pass
//!   `require_user_presence = true` to attach an `NCRYPT_UI_POLICY` (Windows Hello /
//!   consent prompt); that prompt is interactive and will fail in a headless context.
//!
//! Implements the **P-256-in-TPM** mode (spec §8). `NCryptSignHash` returns a raw
//! 64-byte `r‖s` signature (no DER), matching the protocol's P-256 form directly; we
//! SHA-256 the payload ourselves since NCrypt signs a digest.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::{Digest, Sha256};
use windows::core::PCWSTR;
use windows::Win32::Foundation::NTE_BAD_KEYSET;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash, BCRYPT_ECCPUBLIC_BLOB,
    BCRYPT_ECDSA_P256_ALGORITHM, CERT_KEY_SPEC, MS_PLATFORM_CRYPTO_PROVIDER, NCRYPT_FLAGS,
    NCRYPT_HANDLE, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_UI_POLICY,
    NCRYPT_UI_POLICY_PROPERTY, NCRYPT_UI_PROTECT_KEY_FLAG,
};

use crate::algorithm::ClassicalAlg;
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature};
use crate::signer::Signer;

/// A TPM-backed (CNG Platform Crypto Provider) P-256 signer.
pub struct TpmSigner {
    prov: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    public_key: ClassicalPublicKey,
}

// CNG handles are `usize` newtypes and the provider is thread-safe, so `TpmSigner` is
// `Send + Sync` by derivation — no wrapper needed (unlike macOS `SecKey`).

impl TpmSigner {
    /// Create an **ephemeral** TPM P-256 key (not persisted, no user-presence prompt).
    /// Suitable for tooling/CI and headless verification.
    pub fn create_ephemeral() -> Result<Self> {
        let prov = open_pcp()?;
        let key = create_key(prov, None, false)?;
        Self::finish(prov, key)
    }

    /// Load the persistent TPM key named `name`, or create it. When
    /// `require_user_presence` is true the key is created with an `NCRYPT_UI_POLICY`
    /// (Windows Hello / consent on each use) — interactive, not for headless use.
    pub fn load_or_create(name: &str, require_user_presence: bool) -> Result<Self> {
        let prov = open_pcp()?;
        let key = match open_key(prov, name)? {
            Some(k) => k,
            None => create_key(prov, Some(name), require_user_presence)?,
        };
        Self::finish(prov, key)
    }

    /// Whether a persistent TPM key named `name` exists.
    pub fn exists(name: &str) -> Result<bool> {
        let prov = open_pcp()?;
        let found = open_key(prov, name)?.is_some();
        unsafe {
            let _ = NCryptFreeObject(prov.into());
        }
        Ok(found)
    }

    fn finish(prov: NCRYPT_PROV_HANDLE, key: NCRYPT_KEY_HANDLE) -> Result<Self> {
        let public_key = export_pub(key)?;
        Ok(Self {
            prov,
            key,
            public_key,
        })
    }
}

impl Drop for TpmSigner {
    fn drop(&mut self) {
        unsafe {
            let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            let _ = NCryptFreeObject(self.prov.into());
        }
    }
}

impl Signer for TpmSigner {
    fn classical_public_key(&self) -> ClassicalPublicKey {
        self.public_key.clone()
    }

    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature> {
        // NCrypt signs a digest; the protocol's P-256 verify hashes the message with
        // SHA-256, so we hash here to match.
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let raw = sign_digest(self.key, &digest)?;
        // ECDSA via NCryptSignHash yields raw r‖s (64 bytes) — already the protocol form.
        Ok(ClassicalSignature {
            alg: ClassicalAlg::P256,
            bytes: raw,
        })
    }
}

// ---------------------------------------------------------------------------
// CNG helpers — each encapsulates its FFI calls in an `unsafe` block.
// ---------------------------------------------------------------------------

/// Build a NUL-terminated UTF-16 buffer; keep it alive while its PCWSTR is in use.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_pcp() -> Result<NCRYPT_PROV_HANDLE> {
    let mut prov = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) }
        .map_err(|e| AuthError::Backend(format!("open Platform Crypto Provider: {e}")))?;
    Ok(prov)
}

fn create_key(
    prov: NCRYPT_PROV_HANDLE,
    name: Option<&str>,
    require_user_presence: bool,
) -> Result<NCRYPT_KEY_HANDLE> {
    let name_w = name.map(wide);
    let name_pcwstr = match &name_w {
        Some(v) => PCWSTR::from_raw(v.as_ptr()),
        None => PCWSTR::null(),
    };
    let mut key = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            prov,
            &mut key,
            BCRYPT_ECDSA_P256_ALGORITHM,
            name_pcwstr,
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| AuthError::Backend(format!("create TPM key: {e}")))?;

    if require_user_presence {
        set_ui_policy(key)?;
    }

    unsafe { NCryptFinalizeKey(key, NCRYPT_FLAGS(0)) }
        .map_err(|e| AuthError::Backend(format!("finalize TPM key: {e}")))?;
    Ok(key)
}

fn open_key(prov: NCRYPT_PROV_HANDLE, name: &str) -> Result<Option<NCRYPT_KEY_HANDLE>> {
    let name_w = wide(name);
    let mut key = NCRYPT_KEY_HANDLE::default();
    let r = unsafe {
        NCryptOpenKey(
            prov,
            &mut key,
            PCWSTR::from_raw(name_w.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    };
    match r {
        Ok(()) => Ok(Some(key)),
        Err(e) if e.code() == NTE_BAD_KEYSET => Ok(None),
        Err(e) => Err(AuthError::Backend(format!("open TPM key: {e}"))),
    }
}

/// Set a user-presence UI policy (Windows Hello / consent) — must precede finalize.
fn set_ui_policy(key: NCRYPT_KEY_HANDLE) -> Result<()> {
    let title = wide("IdentiKey");
    let friendly = wide("IdentiKey device key");
    let desc = wide("Confirm sign-in");
    let policy = NCRYPT_UI_POLICY {
        dwVersion: 1,
        dwFlags: NCRYPT_UI_PROTECT_KEY_FLAG,
        pszCreationTitle: PCWSTR::from_raw(title.as_ptr()),
        pszFriendlyName: PCWSTR::from_raw(friendly.as_ptr()),
        pszDescription: PCWSTR::from_raw(desc.as_ptr()),
    };
    // SAFETY: view the POD struct as bytes; `policy` (and its backing strings) outlive
    // the call below.
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&policy as *const NCRYPT_UI_POLICY) as *const u8,
            std::mem::size_of::<NCRYPT_UI_POLICY>(),
        )
    };
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.0),
            NCRYPT_UI_POLICY_PROPERTY,
            bytes,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| AuthError::Backend(format!("set UI policy: {e}")))
}

/// Export the public key as a BCRYPT_ECCPUBLIC_BLOB and return it compressed (SEC1).
fn export_pub(key: NCRYPT_KEY_HANDLE) -> Result<ClassicalPublicKey> {
    let mut needed = 0u32;
    unsafe {
        NCryptExportKey(
            key,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            None,
            &mut needed,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| AuthError::Backend(format!("export size: {e}")))?;

    let mut blob = vec![0u8; needed as usize];
    let mut written = 0u32;
    unsafe {
        NCryptExportKey(
            key,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            Some(&mut blob),
            &mut written,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| AuthError::Backend(format!("export key: {e}")))?;
    blob.truncate(written as usize);

    // BCRYPT_ECCKEY_BLOB: [u32 dwMagic][u32 cbKey][X: cbKey][Y: cbKey] (little-endian).
    if blob.len() < 8 {
        return Err(AuthError::Backend("ECC blob too short".into()));
    }
    let cb_key = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as usize;
    if cb_key != 32 || blob.len() < 8 + 2 * cb_key {
        return Err(AuthError::Backend("unexpected ECC blob layout".into()));
    }
    // SEC1 uncompressed point: 0x04 || X || Y.
    let mut sec1 = Vec::with_capacity(1 + 2 * cb_key);
    sec1.push(0x04);
    sec1.extend_from_slice(&blob[8..8 + cb_key]);
    sec1.extend_from_slice(&blob[8 + cb_key..8 + 2 * cb_key]);

    let point = p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| AuthError::Backend("invalid EC public point".into()))?;
    Ok(ClassicalPublicKey {
        alg: ClassicalAlg::P256,
        bytes: point.to_encoded_point(true).as_bytes().to_vec(),
    })
}

/// Sign a 32-byte digest, returning the raw 64-byte r‖s ECDSA signature.
fn sign_digest(key: NCRYPT_KEY_HANDLE, digest: &[u8; 32]) -> Result<Vec<u8>> {
    let mut needed = 0u32;
    unsafe { NCryptSignHash(key, None, &digest[..], None, &mut needed, NCRYPT_FLAGS(0)) }
        .map_err(|e| AuthError::Backend(format!("sign size: {e}")))?;
    let mut sig = vec![0u8; needed as usize];
    let mut written = 0u32;
    unsafe {
        NCryptSignHash(
            key,
            None,
            &digest[..],
            Some(&mut sig),
            &mut written,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| AuthError::Backend(format!("sign: {e}")))?;
    sig.truncate(written as usize);
    Ok(sig)
}
