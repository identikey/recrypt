//! HTTP routes for the `Capability` bearer token (epic recrypt-nj1, child recrypt-91h).
//!
//! Capabilities are constructed and signed client-side; this surface
//! lets a relying party verify a presented token without holding the
//! issuer's keys directly. The `issuer_*_pk` fields in the request
//! are the public keys to verify against — typically resolved via the
//! `/accounts/{fingerprint}` lookup before calling this endpoint.

use crate::error::{ServerError, ServerResult};
use crate::state::AppState;
use axum::{Json, extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::VerifyingKey;
use recrypt_storage_auth::Capability;
use recrypt_core::sign::{VerifyPolicy, VerifyingKeys};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request body for `POST /capabilities/verify`.
#[derive(Deserialize, ToSchema)]
pub struct VerifyCapabilityRequest {
    /// Base64-encoded Gordian Envelope (dCBOR) of a signed capability.
    /// The wire form produced by `Capability::sign`.
    pub envelope_b64: String,
    /// Base64-encoded 32-byte Ed25519 public key the capability was
    /// signed with. Lookup hint: derive from the issuer fingerprint
    /// via `GET /accounts/{fingerprint}`.
    pub issuer_ed25519_pk: String,
    /// Base64-encoded ML-DSA-87 public key (~2.6 KB), if the
    /// caller wants to require post-quantum signature verification.
    /// Omitted = classical-only check.
    #[serde(default)]
    pub issuer_ml_dsa_pk: Option<String>,
}

/// Response body for `POST /capabilities/verify`.
///
/// `valid: true` means the signature checked out and the capability
/// has not expired. Permission set, expiry, and parent-chain link are
/// returned for the caller to enforce against their own policy.
#[derive(Serialize, ToSchema)]
pub struct VerifyCapabilityResponse {
    pub valid: bool,
    pub expired: bool,
    /// `"file"`, `"keyspace"`, or `"account"`.
    pub subject_kind: String,
    /// Base58 of the 32-byte resource address.
    pub subject: String,
    /// Base58 fingerprint of the recipient.
    pub granted_to: String,
    /// Base58 fingerprint of the issuer.
    pub issuer: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<u64>,
    pub note: Option<String>,
    /// Base58 of the parent capability's wrapped envelope digest, when
    /// present. Chain verification is not performed by this endpoint
    /// (see recrypt-91h follow-up).
    pub parent: Option<String>,
}

/// Verify a presented capability token.
#[utoipa::path(
    post,
    path = "/capabilities/verify",
    tag = "capabilities",
    request_body = VerifyCapabilityRequest,
    responses(
        (status = 200, description = "Capability parsed and signature verified (check `expired`)", body = VerifyCapabilityResponse),
        (status = 400, description = "Malformed envelope or key encodings"),
        (status = 401, description = "Signature verification failed"),
    ),
)]
pub async fn verify_capability(
    State(_state): State<AppState>,
    Json(body): Json<VerifyCapabilityRequest>,
) -> ServerResult<(StatusCode, Json<VerifyCapabilityResponse>)> {
    let envelope_bytes = BASE64
        .decode(&body.envelope_b64)
        .map_err(|e| ServerError::BadRequest(format!("envelope_b64: {e}")))?;
    let ed25519_pk_bytes = BASE64
        .decode(&body.issuer_ed25519_pk)
        .map_err(|e| ServerError::BadRequest(format!("issuer_ed25519_pk: {e}")))?;
    let ed_arr: [u8; 32] = ed25519_pk_bytes
        .try_into()
        .map_err(|_| ServerError::BadRequest("issuer_ed25519_pk must be 32 bytes".into()))?;
    let ed25519 = VerifyingKey::from_bytes(&ed_arr)
        .map_err(|e| ServerError::BadRequest(format!("issuer_ed25519_pk: {e}")))?;

    let (ml_dsa, policy) = match body.issuer_ml_dsa_pk {
        Some(s) => {
            let bytes = BASE64
                .decode(&s)
                .map_err(|e| ServerError::BadRequest(format!("issuer_ml_dsa_pk: {e}")))?;
            (Some(bytes), VerifyPolicy::PqRequired)
        }
        None => (None, VerifyPolicy::PqOptional),
    };

    let issuer_keys = VerifyingKeys { ed25519, ml_dsa };

    let cap = Capability::verify(&envelope_bytes, &issuer_keys, policy)
        .map_err(|_| ServerError::Unauthorized("capability signature invalid".into()))?;

    Ok((
        StatusCode::OK,
        Json(VerifyCapabilityResponse {
            valid: true,
            expired: cap.is_expired(),
            subject_kind: cap.subject_kind.as_str().to_string(),
            subject: bs58::encode(cap.subject).into_string(),
            granted_to: bs58::encode(cap.granted_to.as_bytes()).into_string(),
            issuer: bs58::encode(cap.issuer.as_bytes()).into_string(),
            permissions: cap.permissions.iter().map(|p| p.as_str().to_string()).collect(),
            expires_at: cap.expires_at,
            note: cap.note,
            parent: cap.parent.map(|p| bs58::encode(p).into_string()),
        }),
    ))
}
