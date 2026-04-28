use crate::error::{ServerError, ServerResult};
use crate::middleware::{extract_signature_headers, verify_multisig};
use crate::state::AppState;
use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use identikey_storage_auth::{AccountRecord, PublicKeyFingerprint};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Request body for `POST /accounts`.
#[derive(Deserialize, ToSchema)]
pub struct CreateAccountRequest {
    /// Base64-encoded 32-byte Ed25519 public key. All body-bytes
    /// fields are base64; base58 is reserved for URL path segments
    /// (e.g. the derived `fingerprint`).
    #[schema(example = "MCowBQYDK2VwAyEA...base64...")]
    pub ed25519_pk: String,
    /// Base64-encoded ML-DSA-87 public key (~2.6 KB).
    #[schema(example = "MIIChw...base64...")]
    pub ml_dsa_pk: String,
}

/// Response body for `POST /accounts` and `GET /accounts/{fingerprint}`.
#[derive(Serialize, ToSchema)]
pub struct AccountResponse {
    /// Base58-encoded BLAKE3 fingerprint of the Ed25519 public key. Used
    /// as the account's stable identifier in URL path segments.
    pub fingerprint: String,
    /// Base64-encoded 32-byte Ed25519 public key (echoed from the request).
    pub ed25519_pk: String,
    /// Base64-encoded ML-DSA-87 public key (echoed from the request).
    pub ml_dsa_pk: String,
    /// Account creation time (Unix seconds).
    pub created_at: u64,
}

/// Create a new account.
///
/// Registers the caller's dual-stack public keys (Ed25519 + ML-DSA-87)
/// under the BLAKE3 fingerprint of their Ed25519 key. Subsequent
/// authenticated endpoints look up this account record to verify
/// per-request multisigs.
///
/// **Authorization**: dual-stack multisig over the canonical message
/// `CREATE:{ed25519_pk}:{ml_dsa_pk}:{nonce}` using the very keys being
/// registered. The `X-Public-Key` header MUST equal the fingerprint
/// derived from `ed25519_pk`; otherwise the request is rejected as
/// malformed.
#[utoipa::path(
    post,
    path = "/accounts",
    tag = "accounts",
    request_body = CreateAccountRequest,
    responses(
        (status = 201, description = "Account created", body = AccountResponse),
        (status = 400, description = "Malformed request or fingerprint mismatch"),
        (status = 409, description = "Account already exists"),
    ),
)]
pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateAccountRequest>,
) -> ServerResult<(StatusCode, Json<AccountResponse>)> {
    let sig_headers = extract_signature_headers(&headers)?;

    // Decode keys (all body bytes are base64 — see http-api-reference.md §1.3)
    let ed25519_pk = BASE64
        .decode(&body.ed25519_pk)
        .map_err(|_| ServerError::BadRequest("Invalid base64 in ed25519_pk".into()))?;
    let ml_dsa_pk = BASE64
        .decode(&body.ml_dsa_pk)
        .map_err(|_| ServerError::BadRequest("Invalid base64 in ml_dsa_pk".into()))?;

    // Compute fingerprint from ED25519 public key
    let fingerprint = compute_fingerprint(&ed25519_pk);

    // Verify fingerprint matches header
    if fingerprint != sig_headers.fingerprint {
        return Err(ServerError::BadRequest(
            "X-Public-Key fingerprint doesn't match ed25519_pk".into(),
        ));
    }

    // Build message to verify
    let message = format!(
        "CREATE:{}:{}:{}",
        body.ed25519_pk, body.ml_dsa_pk, sig_headers.nonce
    );

    // Verify signature
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &ed25519_pk,
        Some(&ml_dsa_pk),
        recrypt_core::sign::VerifyPolicy::PqRequired,
    )?;

    // Check for conflict
    let fp = PublicKeyFingerprint::from_public_key(&ed25519_pk);
    if state
        .accounts
        .exists(&fp)
        .await
        .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
    {
        return Err(ServerError::Conflict("Account already exists".into()));
    }

    // Create account
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = AccountRecord {
        fingerprint: fingerprint.clone(),
        ed25519_pk: ed25519_pk.clone(),
        ml_dsa_pk: ml_dsa_pk.clone(),
        created_at: now,
    };

    state
        .accounts
        .register(record)
        .await
        .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(AccountResponse {
            fingerprint,
            ed25519_pk: body.ed25519_pk,
            ml_dsa_pk: body.ml_dsa_pk,
            created_at: now,
        }),
    ))
}

/// GET /accounts/{fingerprint}
pub async fn get_account(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> ServerResult<Json<AccountResponse>> {
    let fp = PublicKeyFingerprint::from_base58(&fingerprint)
        .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))?;
    let account = state
        .accounts
        .get(&fp)
        .await
        .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
        .ok_or_else(|| ServerError::NotFound("Account not found".into()))?;

    Ok(Json(AccountResponse {
        fingerprint: account.fingerprint.clone(),
        ed25519_pk: BASE64.encode(&account.ed25519_pk),
        ml_dsa_pk: BASE64.encode(&account.ml_dsa_pk),
        created_at: account.created_at,
    }))
}

/// Compute fingerprint from public key bytes
fn compute_fingerprint(pk: &[u8]) -> String {
    let hash = blake3::hash(pk);
    bs58::encode(hash.as_bytes()).into_string()
}

/// GET /accounts/{fingerprint}/files
/// List all files owned by this account
pub async fn list_files(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
) -> ServerResult<Json<Vec<FileInfo>>> {
    use blake3::Hash;
    use identikey_storage_auth::PublicKeyFingerprint;

    let fp = PublicKeyFingerprint::from_base58(&fingerprint)
        .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))?;

    let file_hashes = state
        .ownership
        .list_owned(&fp)
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to list files: {e}")))?;

    let files: Vec<FileInfo> = file_hashes
        .into_iter()
        .map(|hash: Hash| FileInfo {
            hash: bs58::encode(hash.as_bytes()).into_string(),
        })
        .collect();

    Ok(Json(files))
}

#[derive(serde::Serialize)]
pub struct FileInfo {
    pub hash: String,
}
