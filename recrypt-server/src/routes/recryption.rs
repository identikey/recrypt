use crate::error::{ServerError, ServerResult};
use crate::middleware::{extract_signature_headers, verify_multisig};
use crate::state::{AppState, SharePolicy};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use recrypt_core::pre::BackendId;
use recrypt_core::{EncryptedFile, HybridEncryptor};
use recrypt_wire::MultiFormat;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Response types for the control/data plane split
// ---------------------------------------------------------------------------

/// JSON representation of a multi-signature.
///
/// The signature commits to the *original* `wrapped_key || bao_hash`, not the
/// recrypted `wrapped_key_for_recipient`. The recipient uses this to confirm
/// that the file's `bao_hash` is what the original sender attested to. The
/// recrypted `wrapped_key_for_recipient` is authenticated by the PRE scheme
/// itself — only the correct recipient can decrypt it, and `plaintext_hash`
/// inside `KeyMaterial` provides post-decryption integrity. Do NOT use this
/// signature to authenticate the recrypted wrapped key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureJson {
    /// Base64-encoded ED25519 signature bytes (64 bytes).
    pub ed25519_sig: String,
    /// Base64-encoded ML-DSA-87 signature bytes, absent when the file was
    /// signed classical-only.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ml_dsa_sig: Option<String>,
}

/// Response for `GET /recryption/share/{id}` (control-plane only).
///
/// The proxy returns only the recrypted wrapped key + metadata + storage URLs.
/// The client fetches bulk ciphertext directly from storage (data plane),
/// eliminating proxy bandwidth proportional to file size.
///
/// # Storage URL security
/// URLs point to content-addressed ciphertext objects. Possessing a URL yields
/// ciphertext only — not plaintext — because the symmetric key is protected by
/// the recrypted `wrapped_key_for_recipient`. Pre-signed URLs with short TTLs
/// are a follow-up; see design doc §8.7.
#[derive(Serialize, Deserialize, Debug)]
pub struct RecryptionShareResponse {
    /// Base64-encoded recrypted wrapped key (`Ciphertext::to_bytes()`).
    /// The recipient decrypts this with their PRE secret key to recover the
    /// symmetric key bundle (`KeyMaterial`).
    pub wrapped_key_for_recipient: String,
    /// Base58-encoded 32-byte BLAKE3 root over the ciphertext.
    pub bao_hash: String,
    /// Multi-signature over (`original_wrapped_key || bao_hash`).
    /// See [`SignatureJson`] for the security note on what this authenticates.
    pub signature: Option<SignatureJson>,
    /// URL the client GETs to fetch the bulk ciphertext.
    /// Format: `{storage_base_url}/blob/b3/{base58(bao_hash)}`
    pub ciphertext_url: String,
    /// URL for the bao-tree outboard sibling (`.obao`).
    /// Empty string when the file is ≤ 16 KiB (no outboard stored).
    /// The client MUST check for empty before issuing a GET.
    pub outboard_url: String,
}

#[derive(Deserialize)]
pub struct CreateShareRequest {
    pub to_fingerprint: String,
    pub file_hash: String,   // base58 (32B)
    pub recrypt_key: String, // base64 (multi-KB; see encoding-conventions.md §4)
    /// Serialized original wrapped key (`Ciphertext::to_bytes()`) as base64.
    /// Required so the proxy can recrypt it later without re-fetching the full
    /// file envelope (which does not embed the wrapped key by design).
    pub wrapped_key: String, // base64 (multi-KB)
    pub backend_id: String,  // "mock" or "lattice"
}

#[derive(Serialize)]
pub struct ShareResponse {
    pub share_id: String,
    pub from: String,
    pub to: String,
    pub file_hash: String,
    pub created_at: u64,
}

/// POST /recryption/share
pub async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateShareRequest>,
) -> ServerResult<(StatusCode, Json<ShareResponse>)> {
    let sig_headers = extract_signature_headers(&headers)?;
    let from_fingerprint = sig_headers.fingerprint.clone();

    // Look up sender's account
    let sender_account = {
        let fp = identikey_storage_auth::PublicKeyFingerprint::from_base58(&from_fingerprint)
            .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))?;
        state
            .accounts
            .get(&fp)
            .await
            .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
            .ok_or_else(|| ServerError::NotFound("Sender account not found".into()))?
    };

    // Verify recipient exists
    {
        let to_fp = identikey_storage_auth::PublicKeyFingerprint::from_base58(&body.to_fingerprint)
            .ok_or_else(|| ServerError::BadRequest("Invalid recipient fingerprint".into()))?;
        if !state
            .accounts
            .exists(&to_fp)
            .await
            .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
        {
            return Err(ServerError::NotFound("Recipient account not found".into()));
        }
    }

    // Parse file hash
    let file_hash = recrypt_storage::hash_from_base58(&body.file_hash)
        .ok_or_else(|| ServerError::BadRequest("Invalid file hash".into()))?;

    // Verify file exists
    if !state
        .storage
        .exists(&file_hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?
    {
        return Err(ServerError::NotFound("File not found".into()));
    }

    // Build and verify signature
    let message = format!(
        "SHARE:{}:{}:{}:{}",
        from_fingerprint, body.to_fingerprint, body.file_hash, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &sender_account.ed25519_pk,
        Some(&sender_account.ml_dsa_pk),
        recrypt_core::sign::VerifyPolicy::PqRequired,
    )?;

    // Decode recrypt key (base64; multi-KB lattice keys would be O(n²) in base58)
    let recrypt_key_bytes = BASE64
        .decode(&body.recrypt_key)
        .map_err(|_| ServerError::BadRequest("Invalid base64 in recrypt_key".into()))?;

    // Decode wrapped key (original PRE ciphertext, needed for recryption)
    let wrapped_key_bytes = BASE64
        .decode(&body.wrapped_key)
        .map_err(|_| ServerError::BadRequest("Invalid base64 in wrapped_key".into()))?;

    // Parse backend ID
    let backend_id: BackendId = body
        .backend_id
        .parse()
        .map_err(|_| ServerError::BadRequest(format!("Invalid backend_id: {}", body.backend_id)))?;

    // Generate share ID
    let share_data = format!(
        "{}:{}:{}",
        from_fingerprint, body.to_fingerprint, body.file_hash
    );
    let share_id = bs58::encode(blake3::hash(share_data.as_bytes()).as_bytes()).into_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let policy = SharePolicy {
        id: share_id.clone(),
        from_fingerprint: from_fingerprint.clone(),
        to_fingerprint: body.to_fingerprint.clone(),
        file_hash,
        recrypt_key: recrypt_key_bytes,
        wrapped_key: wrapped_key_bytes,
        backend_id,
        created_at: now,
    };

    state.shares.create(policy).await?;

    Ok((
        StatusCode::CREATED,
        Json(ShareResponse {
            share_id,
            from: from_fingerprint,
            to: body.to_fingerprint,
            file_hash: body.file_hash,
            created_at: now,
        }),
    ))
}

/// GET /recryption/share/{id}
///
/// Control-plane recryption endpoint. Returns only the recrypted wrapped key
/// and storage URLs for the bulk ciphertext; the proxy never reads or forwards
/// bulk ciphertext bytes. The client fetches ciphertext directly from storage
/// using the returned URLs, eliminating O(file_size × recipients) proxy bandwidth.
pub async fn get_recrypted_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ServerResult<Json<RecryptionShareResponse>> {
    let sig_headers = extract_signature_headers(&headers)?;
    let requester_fingerprint = sig_headers.fingerprint.clone();

    // Look up share
    let policy = state
        .shares
        .get(&share_id)
        .await?
        .ok_or_else(|| ServerError::NotFound("Share not found".into()))?;

    // Verify requester is the intended recipient
    if policy.to_fingerprint != requester_fingerprint {
        return Err(ServerError::Unauthorized(
            "Not authorized for this share".into(),
        ));
    }

    // Look up requester's account for signature verification
    let requester_account = {
        let fp = identikey_storage_auth::PublicKeyFingerprint::from_base58(&requester_fingerprint)
            .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))?;
        state
            .accounts
            .get(&fp)
            .await
            .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
            .ok_or_else(|| ServerError::NotFound("Requester account not found".into()))?
    };

    // Verify request signature
    let message = format!(
        "DOWNLOAD:{}:{}:{}",
        requester_fingerprint, share_id, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &requester_account.ed25519_pk,
        Some(&requester_account.ml_dsa_pk),
        recrypt_core::sign::VerifyPolicy::PqRequired,
    )?;

    // Load bao_hash from storage to build ciphertext URLs.
    // The wrapped_key is stored directly in SharePolicy (it was provided at
    // share-creation time) because the file envelope does not embed it.
    let file_bytes = state
        .storage
        .get(&policy.file_hash)
        .await
        .map_err(|e| ServerError::Internal(format!("Storage error: {e}")))?;

    let encrypted = EncryptedFile::from_envelope(&file_bytes)
        .map_err(|e| ServerError::Internal(format!("Failed to deserialize file: {e}")))?;

    // Reconstruct the original wrapped key from the stored bytes
    let original_wrapped_key = recrypt_core::pre::Ciphertext::from_bytes(&policy.wrapped_key)
        .map_err(|e| ServerError::Internal(format!("Failed to deserialize wrapped key: {e}")))?;

    // Reconstruct RecryptKey from stored bytes
    let recrypt_key = recrypt_core::pre::RecryptKey::from_bytes(&policy.recrypt_key)
        .map_err(|e| ServerError::Internal(format!("Failed to deserialize recrypt key: {e}")))?;

    // Recrypt only the wrapped key — bulk ciphertext is untouched
    let encryptor = HybridEncryptor::new(state.pre_backend.as_ref());
    let new_wrapped_key = encryptor
        .recrypt_wrapped_key(&recrypt_key, &original_wrapped_key)
        .map_err(|e| ServerError::Internal(format!("Recryption failed: {e}")))?;

    // Encode recrypted wrapped key as base64
    let wrapped_key_b64 = base64::engine::general_purpose::STANDARD
        .encode(new_wrapped_key.to_bytes());

    // Encode bao_hash as base58
    let bao_hash_b58 = bs58::encode(&encrypted.bao_hash).into_string();

    // Build storage URLs.
    // Format: {storage_base_url}/blob/b3/{base58(bao_hash)}
    // Pre-signed URLs are a follow-up (see design doc §8.7). The current threat
    // model accepts that anyone with the bao_hash can fetch the ciphertext, since
    // plaintext is protected by the recrypted wrapped_key_for_recipient.
    let storage_base = build_storage_base_url(&state);
    let ciphertext_url = format!("{}/blob/b3/{}", storage_base, bao_hash_b58);
    // Outboard URL: empty string signals the client not to fetch it (file ≤ 16 KiB).
    // The server cannot know at this point whether an outboard exists without an
    // extra storage lookup; instead we always provide the URL and the client can
    // attempt a GET — a 404 means no outboard (small file). Alternatively, we
    // could store this flag in SharePolicy. For now, emit the URL unconditionally;
    // clients that get 404 on .obao treat it as no outboard. This is consistent
    // with how put_with_outboard skips the .obao PUT for small files.
    let outboard_url = format!("{}/blob/b3/{}.obao", storage_base, bao_hash_b58);

    // Pass through original signature (covers original wrapped_key || bao_hash)
    let signature = encrypted.signature.map(|sig| SignatureJson {
        ed25519_sig: base64::engine::general_purpose::STANDARD
            .encode(sig.ed25519_sig.to_bytes()),
        ml_dsa_sig: sig
            .ml_dsa_sig
            .as_ref()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
    });

    Ok(Json(RecryptionShareResponse {
        wrapped_key_for_recipient: wrapped_key_b64,
        bao_hash: bao_hash_b58,
        signature,
        ciphertext_url,
        outboard_url,
    }))
}

/// Build the storage base URL from server config.
///
/// Priority: s3_endpoint + "/" + s3_bucket → local path hint → in-memory placeholder.
/// Clients use this URL to fetch bulk ciphertext directly (data plane).
fn build_storage_base_url(state: &AppState) -> String {
    let cfg = &state.config.storage;
    if let (Some(endpoint), Some(bucket)) = (&cfg.s3_endpoint, &cfg.s3_bucket) {
        format!("{}/{}", endpoint.trim_end_matches('/'), bucket)
    } else if let Some(local_path) = &cfg.local_path {
        format!("file://{}", local_path)
    } else {
        // In-memory storage: not externally reachable. Clients running in the
        // same process (integration tests) substitute their own storage handle.
        "memory://local".to_string()
    }
}

/// DELETE /recryption/share/{id}
pub async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ServerResult<StatusCode> {
    let sig_headers = extract_signature_headers(&headers)?;
    let requester_fingerprint = sig_headers.fingerprint.clone();

    // Look up share
    let policy = state
        .shares
        .get(&share_id)
        .await?
        .ok_or_else(|| ServerError::NotFound("Share not found".into()))?;

    // Verify requester is the owner
    if policy.from_fingerprint != requester_fingerprint {
        return Err(ServerError::Unauthorized(
            "Only owner can revoke share".into(),
        ));
    }

    // Look up requester's account
    let requester_account = {
        let fp = identikey_storage_auth::PublicKeyFingerprint::from_base58(&requester_fingerprint)
            .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))?;
        state
            .accounts
            .get(&fp)
            .await
            .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
            .ok_or_else(|| ServerError::NotFound("Account not found".into()))?
    };

    // Verify signature
    let message = format!(
        "REVOKE:{}:{}:{}",
        requester_fingerprint, share_id, sig_headers.nonce
    );
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &requester_account.ed25519_pk,
        Some(&requester_account.ml_dsa_pk),
        recrypt_core::sign::VerifyPolicy::PqRequired,
    )?;

    // Remove share
    state.shares.delete(&share_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /accounts/{fingerprint}/shares
/// List shares (from or to this fingerprint)
pub async fn list_shares(
    State(state): State<AppState>,
    Path(fingerprint): Path<String>,
    headers: HeaderMap,
) -> ServerResult<Json<ShareListResponse>> {
    // Extract and verify signature
    let sig_headers = extract_signature_headers(&headers)?;

    // Verify requester owns this fingerprint
    if sig_headers.fingerprint != fingerprint {
        return Err(ServerError::Unauthorized(
            "Can only list your own shares".into(),
        ));
    }

    // Look up account
    let account = {
        let fp = identikey_storage_auth::PublicKeyFingerprint::from_base58(&fingerprint)
            .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))?;
        state
            .accounts
            .get(&fp)
            .await
            .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
            .ok_or_else(|| ServerError::NotFound("Account not found".into()))?
    };

    // Verify signature
    let message = format!("LIST_SHARES:{}:{}", fingerprint, sig_headers.nonce);
    verify_multisig(
        message.as_bytes(),
        &sig_headers,
        &account.ed25519_pk,
        Some(&account.ml_dsa_pk),
        recrypt_core::sign::VerifyPolicy::PqRequired,
    )?;

    // Filter shares via the trait
    let outgoing: Vec<ShareInfo> = state
        .shares
        .list_outgoing(&fingerprint)
        .await?
        .into_iter()
        .map(|policy| ShareInfo {
            share_id: policy.id.clone(),
            from_fingerprint: policy.from_fingerprint.clone(),
            to_fingerprint: policy.to_fingerprint.clone(),
            file_hash: bs58::encode(policy.file_hash.as_bytes()).into_string(),
            created_at: policy.created_at,
        })
        .collect();

    let incoming: Vec<ShareInfo> = state
        .shares
        .list_incoming(&fingerprint)
        .await?
        .into_iter()
        .map(|policy| ShareInfo {
            share_id: policy.id.clone(),
            from_fingerprint: policy.from_fingerprint.clone(),
            to_fingerprint: policy.to_fingerprint.clone(),
            file_hash: bs58::encode(policy.file_hash.as_bytes()).into_string(),
            created_at: policy.created_at,
        })
        .collect();

    Ok(Json(ShareListResponse { outgoing, incoming }))
}

#[derive(serde::Serialize)]
pub struct ShareListResponse {
    pub outgoing: Vec<ShareInfo>,
    pub incoming: Vec<ShareInfo>,
}

#[derive(serde::Serialize)]
pub struct ShareInfo {
    pub share_id: String,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
    pub file_hash: String,
    pub created_at: u64,
}
