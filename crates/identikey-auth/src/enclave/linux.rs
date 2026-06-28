//! Linux **TPM 2.0**-backed P-256 signer via the tpm2-tss ESAPI (`tss-esapi`).
//!
//! The private key is created inside the TPM and signs in-hardware. Linux has no uniform
//! biometric prompt, so "user presence" is not modelled here (unlike Touch ID / Hello).
//!
//! TCTI selection: the `TPM2TOOLS_TCTI` (or `TCTI`) environment variable if set, else the
//! kernel resource-managed device `/dev/tpmrm0`. For testing against a software TPM, set
//! e.g. `TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321`.
//!
//! The `Context` is not `Send + Sync`, so — like the macOS backend's reload-per-sign —
//! this struct stores only the TCTI string + mode + cached public key (all `Send + Sync`)
//! and opens a fresh `Context` per operation.
//!
//! Two constructors mirror the other backends:
//! - [`TpmSigner::create_ephemeral`] — a key on the **null hierarchy**, recreated each
//!   call (deterministic per TPM power cycle). No persistent TPM state; ideal for
//!   tooling/CI and headless verification.
//! - [`TpmSigner::load_or_create`] — a key on the **owner hierarchy** persisted to a
//!   persistent TPM handle (`0x81xxxxxx`), read back across runs. This writes persistent
//!   state to the TPM.
//!
//! Implements the **P-256-in-TPM** mode (spec §8).

use std::convert::TryFrom;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK},
    handles::{KeyHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        ecc::EccCurve,
        resource_handles::{Hierarchy, Provision},
    },
    structures::{
        CreatePrimaryKeyResult, Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Public,
        PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme,
    },
    tcti_ldr::TctiNameConf,
    tss2_esys::TPMT_TK_HASHCHECK,
    Context,
};

use crate::algorithm::ClassicalAlg;
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature};
use crate::signer::Signer;

const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";
const COORD_LEN: usize = 32; // P-256 field element size

#[derive(Clone, Copy)]
enum Mode {
    /// Null-hierarchy primary, recreated per use (no persistence).
    Ephemeral,
    /// Owner-hierarchy key persisted at this persistent TPM handle.
    Persistent(u32),
}

/// A TPM 2.0-backed P-256 signer.
pub struct TpmSigner {
    tcti: String,
    mode: Mode,
    public_key: ClassicalPublicKey,
}

impl TpmSigner {
    /// Create an ephemeral (null-hierarchy) TPM P-256 key. No persistent TPM state.
    pub fn create_ephemeral() -> Result<Self> {
        let tcti = resolve_tcti();
        let mut ctx = open_context(&tcti)?;
        let public = ctx
            .execute_with_nullauth_session(|ctx| {
                let primary = create_primary(ctx, Hierarchy::Null)?;
                let publ = primary.out_public.clone();
                ctx.flush_context(primary.key_handle.into())?;
                Ok::<_, tss_esapi::Error>(publ)
            })
            .map_err(tpm_err)?;
        Ok(Self {
            tcti,
            mode: Mode::Ephemeral,
            public_key: pubkey_from_public(&public)?,
        })
    }

    /// Load the owner-hierarchy key persisted at `persistent_handle` (e.g. 0x81000001),
    /// or create and persist it. Writes persistent state to the TPM.
    pub fn load_or_create(persistent_handle: u32) -> Result<Self> {
        let tcti = resolve_tcti();
        let mut ctx = open_context(&tcti)?;
        let public = ctx
            .execute_with_nullauth_session(|ctx| {
                let ph = PersistentTpmHandle::new(persistent_handle)?;
                match ctx.tr_from_tpm_public(TpmHandle::Persistent(ph)) {
                    Ok(handle) => {
                        let (publ, _, _) = ctx.read_public(handle.into())?;
                        Ok::<_, tss_esapi::Error>(publ)
                    }
                    Err(_) => {
                        let primary = create_primary(ctx, Hierarchy::Owner)?;
                        let publ = primary.out_public.clone();
                        ctx.evict_control(
                            Provision::Owner,
                            primary.key_handle.into(),
                            Persistent::Persistent(ph),
                        )?;
                        ctx.flush_context(primary.key_handle.into())?;
                        Ok(publ)
                    }
                }
            })
            .map_err(tpm_err)?;
        Ok(Self {
            tcti,
            mode: Mode::Persistent(persistent_handle),
            public_key: pubkey_from_public(&public)?,
        })
    }
}

impl Signer for TpmSigner {
    fn classical_public_key(&self) -> ClassicalPublicKey {
        self.public_key.clone()
    }

    fn sign_classical(&self, payload: &[u8]) -> Result<ClassicalSignature> {
        // The TPM signs a digest; the protocol's P-256 verify hashes the message with
        // SHA-256, so hash here to match.
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let mode = self.mode;
        let mut ctx = open_context(&self.tcti)?;
        let sig = ctx
            .execute_with_nullauth_session(|ctx| {
                let (key, transient) = match mode {
                    Mode::Ephemeral => (create_primary(ctx, Hierarchy::Null)?.key_handle, true),
                    Mode::Persistent(h) => {
                        let ph = PersistentTpmHandle::new(h)?;
                        let handle = ctx.tr_from_tpm_public(TpmHandle::Persistent(ph))?;
                        (KeyHandle::from(handle), false)
                    }
                };
                let sig = ctx.sign(
                    key,
                    Digest::try_from(digest.to_vec())?,
                    SignatureScheme::Null,
                    null_hashcheck_ticket()?,
                )?;
                if transient {
                    ctx.flush_context(key.into())?;
                }
                Ok::<_, tss_esapi::Error>(sig)
            })
            .map_err(tpm_err)?;
        Ok(ClassicalSignature {
            alg: ClassicalAlg::P256,
            bytes: raw_rs_from_sig(&sig)?,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tpm_err(e: tss_esapi::Error) -> AuthError {
    AuthError::Backend(format!("tpm: {e}"))
}

fn resolve_tcti() -> String {
    std::env::var("TPM2TOOLS_TCTI")
        .or_else(|_| std::env::var("TCTI"))
        .unwrap_or_else(|_| DEFAULT_TCTI.to_string())
}

fn open_context(tcti: &str) -> Result<Context> {
    let conf = TctiNameConf::from_str(tcti)
        .map_err(|e| AuthError::Backend(format!("tcti '{tcti}': {e}")))?;
    Context::new(conf).map_err(tpm_err)
}

/// Template for an unrestricted ECDSA / P-256 signing key.
fn p256_signing_template() -> tss_esapi::Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(false)
        .build()?;
    // Convenience constructor sets all required fields for a signing key (symmetric Null,
    // KDF Null, restricted false) — a manual builder omits the KDF scheme and fails
    // validation with ParamsMissing.
    let ecc_params = PublicEccParametersBuilder::new_unrestricted_signing_key(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .build()?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

fn create_primary(
    ctx: &mut Context,
    hierarchy: Hierarchy,
) -> tss_esapi::Result<CreatePrimaryKeyResult> {
    let template = p256_signing_template()?;
    ctx.create_primary(hierarchy, template, None, None, None, None)
}

/// Null hashcheck ticket (TPM_RH_NULL) — required by `Context::sign` in tss-esapi 7.x for
/// an unrestricted key signing an externally-computed digest.
fn null_hashcheck_ticket() -> tss_esapi::Result<HashcheckTicket> {
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    })
}

/// Left-pad a big-endian field element to exactly `COORD_LEN` bytes. The TPM returns ECC
/// coordinates / signature components with leading zero bytes stripped.
fn left_pad32(src: &[u8]) -> [u8; COORD_LEN] {
    let mut out = [0u8; COORD_LEN];
    let n = src.len().min(COORD_LEN);
    out[COORD_LEN - n..].copy_from_slice(&src[src.len() - n..]);
    out
}

/// Convert a TPM ECC `Public` into our compressed P-256 public key.
fn pubkey_from_public(public: &Public) -> Result<ClassicalPublicKey> {
    let unique = match public {
        Public::Ecc { unique, .. } => unique,
        _ => return Err(AuthError::Backend("TPM key is not ECC".into())),
    };
    let x = left_pad32(unique.x().value());
    let y = left_pad32(unique.y().value());
    let mut sec1 = Vec::with_capacity(1 + 2 * COORD_LEN);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    let point = p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| AuthError::Backend("invalid EC public point".into()))?;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    Ok(ClassicalPublicKey {
        alg: ClassicalAlg::P256,
        bytes: point.to_encoded_point(true).as_bytes().to_vec(),
    })
}

/// Assemble a raw 64-byte r‖s signature from a TPM EcDsa signature.
fn raw_rs_from_sig(sig: &Signature) -> Result<Vec<u8>> {
    let ecc = match sig {
        Signature::EcDsa(ecc) => ecc,
        _ => return Err(AuthError::Backend("TPM signature is not ECDSA".into())),
    };
    let r = left_pad32(ecc.signature_r().value());
    let s = left_pad32(ecc.signature_s().value());
    let mut out = Vec::with_capacity(2 * COORD_LEN);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    Ok(out)
}
