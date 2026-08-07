//! HTTP routes for keyspace and grant management.
//!
//! # Authorization model (pre-audit, Phase B)
//!
//! The Phase-C plan is a MultiSig over the full `KeyspaceDoc` / `AccessGrant`
//! body, verified against a member's keys from the keyspace itself. Until
//! that lands, we gate every mutating endpoint on a caller-binding check:
//!
//! 1. `validate_nonce` middleware guarantees a fresh nonce.
//! 2. Each mutating handler extracts the X-Signature-* headers, looks up
//!    the caller's account by `X-Public-Key`, and requires a valid
//!    multisig over a short canonical request message that includes the
//!    content hash of the submitted body. This means a well-formed request
//!    proves the caller (by their registered account keys) authorized
//!    exactly this body at this nonce.
//! 3. On top of that, body-level identity fields must match the caller:
//!    - grant `issuer` MUST equal caller fp
//!    - keyspace `added_by` for every member MUST equal caller fp on create
//!    - revocation caller MUST equal grant's stored issuer
//!
//! This is strictly weaker than the Phase-C design but prevents the
//! pre-Phase-C handlers from being open impersonation endpoints.

use crate::error::{ServerError, ServerResult};
use crate::middleware::{extract_signature_headers, verify_multisig};
use crate::state::AppState;
use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use recrypt_storage_auth::{
    AccessGrant, GrantId, KeyspaceDoc, KeyspaceDocHash, KeyspaceId, Permission,
    PublicKeyFingerprint,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Bytes encoding helpers (multi-KB blobs)
// ---------------------------------------------------------------------------
//
// `root_pk` and `signatures` can be multi-KB (root_pk is unbounded; each
// signature is a MultiSig with an ED25519 64 B + ML-DSA-87 ~4.6 KB component
// once Phase C lands). Base58 of multi-KB is O(n²) bignum arithmetic — the
// same regression `recrypt-jtw` / `recrypt-fil` / `recrypt-n1e` fixed
// elsewhere. Output uses `b64:<base64>`. Input accepts `b64:`, `b58:`, or a
// bare string (treated as base58 for backward compat with pre-2026 clients).

fn encode_bytes_b64(bytes: &[u8]) -> String {
    format!("b64:{}", B64.encode(bytes))
}

fn decode_bytes_tagged(s: &str, label: &str) -> ServerResult<Vec<u8>> {
    if let Some(b64) = s.strip_prefix("b64:") {
        return B64
            .decode(b64)
            .map_err(|e| ServerError::BadRequest(format!("Invalid base64 {label}: {e}")));
    }
    let b58 = s.strip_prefix("b58:").unwrap_or(s);
    bs58::decode(b58)
        .into_vec()
        .map_err(|e| ServerError::BadRequest(format!("Invalid base58 {label}: {e}")))
}

// ---------------------------------------------------------------------------
// JSON request/response types
// ---------------------------------------------------------------------------

/// JSON representation of a keyspace member.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemberJson {
    pub fingerprint: String,
    pub permissions: Vec<String>,
    /// Currently only `"standalone"` is accepted. Threshold shares will
    /// land in Phase C; submitting any other value is rejected.
    pub decryption_policy: String,
    pub added_at: u64,
    pub added_by: String,
}

/// JSON representation of a keyspace document.
///
/// Encoding: short identifiers (id, fingerprints, doc hashes, epoch_pre_pk)
/// stay base58 — they're 32 bytes and shown to humans. Multi-KB blobs
/// (`root_pk`, each signature in `signatures`) emit `b64:<base64>` and
/// accept any of `b64:`/`b58:`/bare-base58 on input. See module-level
/// "Bytes encoding helpers" comment.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyspaceDocJson {
    pub id: String,
    pub version: u64,
    pub parent: Option<String>,
    pub mode: String,
    pub name: String,
    pub root_pk: String,
    pub epoch_pre_pk: String,
    pub epoch: u64,
    pub members: Vec<MemberJson>,
    pub quorum: u8,
    pub signatures: Vec<String>,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct CreateKeyspaceResponse {
    pub id: String,
    pub doc_hash: String,
}

#[derive(Serialize)]
pub struct VersionListResponse {
    pub keyspace_id: String,
    pub versions: Vec<String>,
}

/// JSON representation of an access grant.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccessGrantJson {
    pub keyspace_id: String,
    pub keyspace_version: u64,
    pub subject: String,
    pub issuer: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<u64>,
    pub delegation_depth: u8,
    pub parent_grant: Option<String>,
    /// Server-authoritative on issuance; any value supplied by the client
    /// is ignored in `issue_grant` to prevent id-replay via `created_at`
    /// collisions.
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct GrantResponse {
    pub grant_id: String,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn parse_keyspace_id(s: &str) -> ServerResult<KeyspaceId> {
    KeyspaceId::from_str(s)
        .map_err(|e| ServerError::BadRequest(format!("Invalid keyspace id: {e}")))
}

fn parse_doc_hash(s: &str) -> ServerResult<KeyspaceDocHash> {
    KeyspaceDocHash::from_str(s)
        .map_err(|e| ServerError::BadRequest(format!("Invalid doc hash: {e}")))
}

fn parse_fingerprint(s: &str) -> ServerResult<PublicKeyFingerprint> {
    PublicKeyFingerprint::from_base58(s)
        .ok_or_else(|| ServerError::BadRequest("Invalid fingerprint".into()))
}

fn parse_grant_id(s: &str) -> ServerResult<GrantId> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| ServerError::BadRequest(format!("Invalid base58 grant id: {e}")))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
        ServerError::BadRequest(format!("Expected 32 bytes, got {}", v.len()))
    })?;
    Ok(GrantId::from_bytes(arr))
}

fn auth_err(e: recrypt_storage_auth::AuthError) -> ServerError {
    match e {
        recrypt_storage_auth::AuthError::AlreadyExists(msg) => ServerError::Conflict(msg),
        other => ServerError::Internal(format!("Store error: {other}")),
    }
}

fn mode_to_string(mode: &recrypt_storage_auth::RotationMode) -> String {
    use recrypt_storage_auth::RotationMode;
    match mode {
        RotationMode::Create => "create".into(),
        RotationMode::Additive => "additive".into(),
        RotationMode::Hygiene => "hygiene".into(),
        RotationMode::Revoke { .. } => "revoke".into(),
        RotationMode::Burn { .. } => "burn".into(),
        RotationMode::Fork { .. } => "fork".into(),
        RotationMode::Tombstone => "tombstone".into(),
    }
}

fn string_to_mode(s: &str) -> ServerResult<recrypt_storage_auth::RotationMode> {
    use recrypt_storage_auth::RotationMode;
    match s {
        "create" => Ok(RotationMode::Create),
        "additive" => Ok(RotationMode::Additive),
        "hygiene" => Ok(RotationMode::Hygiene),
        "tombstone" => Ok(RotationMode::Tombstone),
        other => Err(ServerError::BadRequest(format!(
            "Unsupported rotation mode '{other}'. Use create/additive/hygiene/tombstone."
        ))),
    }
}

/// Parse `decryption_policy` JSON string. Phase-C threshold shares are
/// not yet supported at the HTTP layer; submitting anything other than
/// `"standalone"` is rejected loudly rather than silently rewritten.
fn string_to_decryption_policy(s: &str) -> ServerResult<recrypt_storage_auth::DecryptionPolicy> {
    use recrypt_storage_auth::DecryptionPolicy;
    match s {
        "standalone" => Ok(DecryptionPolicy::Standalone),
        other => Err(ServerError::BadRequest(format!(
            "decryption_policy '{other}' not supported at this phase (only 'standalone')"
        ))),
    }
}

fn doc_to_json(doc: &KeyspaceDoc) -> KeyspaceDocJson {
    KeyspaceDocJson {
        id: doc.id.to_string(),
        version: doc.version,
        parent: doc.parent.map(|h| h.to_string()),
        mode: mode_to_string(&doc.mode),
        name: doc.name.clone(),
        root_pk: encode_bytes_b64(&doc.root_pk),
        epoch_pre_pk: bs58::encode(&doc.epoch_pre_pk).into_string(),
        epoch: doc.epoch,
        members: doc
            .members
            .iter()
            .map(|m| MemberJson {
                fingerprint: m.fingerprint.to_base58(),
                permissions: m
                    .permissions
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect(),
                decryption_policy: match &m.decryption_policy {
                    recrypt_storage_auth::DecryptionPolicy::Standalone => "standalone".into(),
                    recrypt_storage_auth::DecryptionPolicy::ThresholdShare {
                        threshold,
                        total,
                        ..
                    } => {
                        format!("threshold({}/{})", threshold, total)
                    }
                },
                added_at: m.added_at,
                added_by: m.added_by.to_base58(),
            })
            .collect(),
        quorum: doc.quorum,
        signatures: doc.signatures.iter().map(|s| encode_bytes_b64(s)).collect(),
        created_at: doc.created_at,
    }
}

fn json_to_doc(json: &KeyspaceDocJson) -> ServerResult<KeyspaceDoc> {
    let id = parse_keyspace_id(&json.id)?;
    let parent = json.parent.as_deref().map(parse_doc_hash).transpose()?;
    let mode = string_to_mode(&json.mode)?;
    let root_pk = decode_bytes_tagged(&json.root_pk, "root_pk")?;
    let epoch_pre_pk_bytes = bs58::decode(&json.epoch_pre_pk)
        .into_vec()
        .map_err(|e| ServerError::BadRequest(format!("Invalid base58 epoch_pre_pk: {e}")))?;
    let epoch_pre_pk: [u8; 32] = epoch_pre_pk_bytes.try_into().map_err(|v: Vec<u8>| {
        ServerError::BadRequest(format!("epoch_pre_pk must be 32 bytes, got {}", v.len()))
    })?;

    let members = json
        .members
        .iter()
        .map(|m| {
            let fp = parse_fingerprint(&m.fingerprint)?;
            let caps: BTreeSet<_> = m
                .permissions
                .iter()
                .map(|c| {
                    Permission::parse(c)
                        .ok_or_else(|| ServerError::BadRequest(format!("Unknown capability: {c}")))
                })
                .collect::<ServerResult<_>>()?;
            let added_by = parse_fingerprint(&m.added_by)?;
            let decryption_policy = string_to_decryption_policy(&m.decryption_policy)?;
            Ok(recrypt_storage_auth::Member {
                fingerprint: fp,
                permissions: caps,
                decryption_policy,
                added_at: m.added_at,
                added_by,
            })
        })
        .collect::<ServerResult<Vec<_>>>()?;

    let signatures = json
        .signatures
        .iter()
        .map(|s| decode_bytes_tagged(s, "signature"))
        .collect::<ServerResult<Vec<_>>>()?;

    Ok(KeyspaceDoc {
        id,
        version: json.version,
        parent,
        mode,
        name: json.name.clone(),
        root_pk,
        epoch_pre_pk,
        epoch: json.epoch,
        members,
        quorum: json.quorum,
        signatures,
        created_at: json.created_at,
    })
}

fn grant_to_json(grant: &AccessGrant, _id: &GrantId) -> AccessGrantJson {
    AccessGrantJson {
        keyspace_id: bs58::encode(&grant.keyspace_id).into_string(),
        keyspace_version: grant.keyspace_version,
        subject: grant.subject.to_base58(),
        issuer: grant.issuer.to_base58(),
        permissions: grant
            .permissions
            .iter()
            .map(|c| c.as_str().to_string())
            .collect(),
        expires_at: grant.expires_at,
        delegation_depth: grant.delegation_depth,
        parent_grant: grant.parent_grant.as_ref().map(|g| g.to_base58()),
        created_at: grant.created_at,
    }
}

/// Build an `AccessGrant` from a client JSON payload.
///
/// `created_at` is overridden by the server so the caller cannot control
/// the eventual `GrantId` (which is `Blake3(canonical_bytes)` and would
/// otherwise allow replay of identical bytes across revoke cycles).
fn json_to_grant(json: &AccessGrantJson, server_created_at: u64) -> ServerResult<AccessGrant> {
    let keyspace_id_bytes = bs58::decode(&json.keyspace_id)
        .into_vec()
        .map_err(|e| ServerError::BadRequest(format!("Invalid base58 keyspace_id: {e}")))?;
    let keyspace_id: [u8; 32] = keyspace_id_bytes.try_into().map_err(|v: Vec<u8>| {
        ServerError::BadRequest(format!("keyspace_id must be 32 bytes, got {}", v.len()))
    })?;
    let subject = parse_fingerprint(&json.subject)?;
    let issuer = parse_fingerprint(&json.issuer)?;
    let permissions: BTreeSet<_> = json
        .permissions
        .iter()
        .map(|c| {
            Permission::parse(c)
                .ok_or_else(|| ServerError::BadRequest(format!("Unknown capability: {c}")))
        })
        .collect::<ServerResult<_>>()?;
    let parent_grant = json
        .parent_grant
        .as_deref()
        .map(parse_grant_id)
        .transpose()?;

    Ok(AccessGrant {
        version: AccessGrant::VERSION,
        keyspace_id,
        keyspace_version: json.keyspace_version,
        subject,
        issuer,
        permissions,
        expires_at: json.expires_at,
        delegation_depth: json.delegation_depth,
        parent_grant,
        created_at: server_created_at,
        signature: None,
    })
}

// ---------------------------------------------------------------------------
// Caller authentication (pre-Phase-C)
// ---------------------------------------------------------------------------

/// Verify the caller's multisig over `request_tag || body_hash || nonce`.
/// Returns the caller's fingerprint on success.
///
/// Pre-Phase-C authorization: the caller's account keys are looked up
/// from the account store and used to verify a compact request message
/// bound to the body's content hash and the request nonce. This proves
/// the caller authorized exactly this body at this nonce, without yet
/// implementing the full MultiSig-over-KeyspaceDoc scheme.
async fn verify_caller(
    state: &AppState,
    headers: &HeaderMap,
    request_tag: &[u8],
    body_hash: &[u8; 32],
) -> ServerResult<PublicKeyFingerprint> {
    let sig_headers = extract_signature_headers(headers)?;

    let fp = PublicKeyFingerprint::from_base58(&sig_headers.fingerprint)
        .ok_or_else(|| ServerError::BadRequest("Invalid X-Public-Key fingerprint".into()))?;

    let account = state
        .accounts
        .get(&fp)
        .await
        .map_err(|e| ServerError::Internal(format!("AccountStore error: {e}")))?
        .ok_or_else(|| ServerError::Unauthorized("Caller account not registered".into()))?;

    let mut message = Vec::with_capacity(request_tag.len() + 32 + sig_headers.nonce.len() + 2);
    message.extend_from_slice(request_tag);
    message.push(b':');
    message.extend_from_slice(body_hash);
    message.push(b':');
    message.extend_from_slice(sig_headers.nonce.as_bytes());

    verify_multisig(
        &message,
        &sig_headers,
        &account.ed25519_pk,
        Some(&account.ml_dsa_pk),
        recrypt_core::sign::VerifyPolicy::PqRequired,
    )?;

    Ok(fp)
}

// ---------------------------------------------------------------------------
// Keyspace routes
// ---------------------------------------------------------------------------

/// POST /keyspaces
pub async fn create_keyspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<KeyspaceDocJson>,
) -> ServerResult<(StatusCode, Json<CreateKeyspaceResponse>)> {
    if body.version != 0 {
        return Err(ServerError::BadRequest(
            "create_keyspace requires version 0".into(),
        ));
    }
    let doc = json_to_doc(&body)?;
    let doc_hash = doc.doc_hash();

    let caller_fp =
        verify_caller(&state, &headers, b"KEYSPACE_CREATE", doc_hash.as_bytes()).await?;

    // Body-level binding: every member listed as newly added must be added
    // by the caller. We cannot yet enforce that the caller is a signer of
    // the doc (that requires the Phase-C signature verification path).
    for m in &doc.members {
        if m.added_by != caller_fp {
            return Err(ServerError::Unauthorized(format!(
                "member {} claims added_by != caller",
                m.fingerprint
            )));
        }
    }

    let hash = state.keyspaces.put(doc).await.map_err(auth_err)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateKeyspaceResponse {
            id: body.id,
            doc_hash: hash.to_string(),
        }),
    ))
}

/// GET /keyspaces/:id
pub async fn get_keyspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ServerResult<Json<KeyspaceDocJson>> {
    let ks_id = parse_keyspace_id(&id)?;
    let doc = state
        .keyspaces
        .get_latest(&ks_id)
        .await
        .map_err(auth_err)?
        .ok_or_else(|| ServerError::NotFound("Keyspace not found".into()))?;
    Ok(Json(doc_to_json(&doc)))
}

/// GET /keyspaces/:id/versions
pub async fn list_versions(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ServerResult<Json<VersionListResponse>> {
    let ks_id = parse_keyspace_id(&id)?;
    let hashes = state
        .keyspaces
        .list_versions(&ks_id)
        .await
        .map_err(auth_err)?;
    Ok(Json(VersionListResponse {
        keyspace_id: id,
        versions: hashes.iter().map(|h| h.to_string()).collect(),
    }))
}

/// POST /keyspaces/:id/versions
pub async fn publish_version(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<KeyspaceDocJson>,
) -> ServerResult<(StatusCode, Json<CreateKeyspaceResponse>)> {
    let ks_id = parse_keyspace_id(&id)?;
    let doc = json_to_doc(&body)?;

    if doc.id != ks_id {
        return Err(ServerError::BadRequest(
            "Path keyspace id does not match document id".into(),
        ));
    }

    let doc_hash = doc.doc_hash();
    let caller_fp =
        verify_caller(&state, &headers, b"KEYSPACE_PUBLISH", doc_hash.as_bytes()).await?;

    // Caller MUST currently be a member with SignRotation on the prior
    // version. Phase-C will replace this with quorum verification of
    // `doc.signatures`.
    let prev = state
        .keyspaces
        .get_latest(&ks_id)
        .await
        .map_err(auth_err)?
        .ok_or_else(|| ServerError::NotFound("Keyspace not found".into()))?;
    let is_signer = prev.members.iter().any(|m| {
        m.fingerprint == caller_fp && m.permissions.contains(&Permission::SignRotation)
    });
    if !is_signer {
        return Err(ServerError::Unauthorized(
            "Caller is not a SignRotation member of the current keyspace version".into(),
        ));
    }

    let hash = state.keyspaces.put(doc).await.map_err(auth_err)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateKeyspaceResponse {
            id,
            doc_hash: hash.to_string(),
        }),
    ))
}

/// GET /members/:fp/keyspaces
pub async fn list_by_member(
    State(state): State<AppState>,
    Path(fp): Path<String>,
) -> ServerResult<Json<Vec<String>>> {
    let fingerprint = parse_fingerprint(&fp)?;
    let ids = state
        .keyspaces
        .list_by_member(&fingerprint)
        .await
        .map_err(auth_err)?;
    Ok(Json(ids.iter().map(|id| id.to_string()).collect()))
}

// ---------------------------------------------------------------------------
// Grant routes
// ---------------------------------------------------------------------------

/// POST /grants
pub async fn issue_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AccessGrantJson>,
) -> ServerResult<(StatusCode, Json<GrantResponse>)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = json_to_grant(&body, now)?;

    // Bind request to the *content* of the grant (post-created_at override).
    let grant_id = GrantId::from_grant(&grant);
    let caller_fp = verify_caller(&state, &headers, b"GRANT_ISSUE", grant_id.as_bytes()).await?;

    // Body-level binding: issuer must equal caller.
    if grant.issuer != caller_fp {
        return Err(ServerError::Unauthorized(
            "grant.issuer does not match caller".into(),
        ));
    }

    // Validate the referenced keyspace exists and the version is in range.
    let ks_id = KeyspaceId::from_bytes(grant.keyspace_id);
    let latest = state
        .keyspaces
        .get_latest(&ks_id)
        .await
        .map_err(auth_err)?
        .ok_or_else(|| {
            ServerError::BadRequest("grant.keyspace_id does not refer to a stored keyspace".into())
        })?;
    if grant.keyspace_version > latest.version {
        return Err(ServerError::BadRequest(format!(
            "grant.keyspace_version {} exceeds latest version {}",
            grant.keyspace_version, latest.version
        )));
    }

    // Issuer must be a member of the current keyspace version with at
    // least `Delegate` capability.
    let issuer_member = latest
        .members
        .iter()
        .find(|m| m.fingerprint == grant.issuer)
        .ok_or_else(|| {
            ServerError::Unauthorized("issuer is not a member of this keyspace".into())
        })?;
    if !issuer_member
        .permissions
        .contains(&Permission::Delegate)
    {
        return Err(ServerError::Unauthorized(
            "issuer lacks Delegate capability on this keyspace".into(),
        ));
    }

    let id = state.grants.issue(grant).await.map_err(auth_err)?;
    Ok((
        StatusCode::CREATED,
        Json(GrantResponse {
            grant_id: id.to_base58(),
        }),
    ))
}

/// GET /grants/:id
pub async fn get_grant(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ServerResult<Json<AccessGrantJson>> {
    let grant_id = parse_grant_id(&id)?;
    let grant = state
        .grants
        .get(&grant_id)
        .await
        .map_err(auth_err)?
        .ok_or_else(|| ServerError::NotFound("Grant not found".into()))?;
    Ok(Json(grant_to_json(&grant, &grant_id)))
}

/// DELETE /grants/:id
pub async fn revoke_grant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ServerResult<StatusCode> {
    let grant_id = parse_grant_id(&id)?;

    // Verify the grant exists, then bind the request to the grant id and
    // require the caller to match the grant's issuer.
    let existing = state
        .grants
        .get(&grant_id)
        .await
        .map_err(auth_err)?
        .ok_or_else(|| ServerError::NotFound("Grant not found".into()))?;

    let caller_fp = verify_caller(&state, &headers, b"GRANT_REVOKE", grant_id.as_bytes()).await?;

    if existing.issuer != caller_fp {
        return Err(ServerError::Unauthorized(
            "Only the grant issuer may revoke".into(),
        ));
    }

    state.grants.revoke(&grant_id).await.map_err(auth_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /subjects/:fp/grants
pub async fn list_grants_by_subject(
    State(state): State<AppState>,
    Path(fp): Path<String>,
) -> ServerResult<Json<Vec<AccessGrantJson>>> {
    let fingerprint = parse_fingerprint(&fp)?;
    let grants = state
        .grants
        .list_by_subject(&fingerprint)
        .await
        .map_err(auth_err)?;
    Ok(Json(
        grants
            .iter()
            .map(|g| {
                let id = GrantId::from_grant(g);
                grant_to_json(g, &id)
            })
            .collect(),
    ))
}

/// GET /keyspaces/:id/grants
pub async fn list_grants_by_keyspace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ServerResult<Json<Vec<AccessGrantJson>>> {
    let keyspace_id_bytes = bs58::decode(&id)
        .into_vec()
        .map_err(|e| ServerError::BadRequest(format!("Invalid base58 keyspace id: {e}")))?;
    let keyspace_id: [u8; 32] = keyspace_id_bytes.try_into().map_err(|v: Vec<u8>| {
        ServerError::BadRequest(format!("Expected 32 bytes, got {}", v.len()))
    })?;
    let grants = state
        .grants
        .list_by_keyspace(&keyspace_id)
        .await
        .map_err(auth_err)?;
    Ok(Json(
        grants
            .iter()
            .map(|g| {
                let id = GrantId::from_grant(g);
                grant_to_json(g, &id)
            })
            .collect(),
    ))
}
