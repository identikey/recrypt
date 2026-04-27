// API client for recrypt-server

use anyhow::{Context as AnyhowContext, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};

use super::auth::{add_auth_headers, sign_request_with_nonce};
use crate::wallet::Identity;

pub struct ApiClient {
    client: Client,
    server_url: String,
}

impl ApiClient {
    pub fn new(server_url: String) -> Self {
        Self {
            client: Client::new(),
            server_url: server_url.trim_end_matches('/').to_string(),
        }
    }

    /// Fetch a nonce from the server
    async fn fetch_nonce(&self) -> Result<String> {
        let nonce_url = format!("{}/nonce", self.server_url);
        let response = self
            .client
            .get(&nonce_url)
            .send()
            .await
            .context("Failed to fetch nonce")?;

        let nonce_data: serde_json::Value = response.json().await?;
        nonce_data["nonce"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid nonce response"))
            .map(String::from)
    }

    /// Register an account on the server
    pub async fn register_account(&self, identity: &Identity) -> Result<RegisterResponse> {
        // ed25519 (32B) → base58; ml-dsa-87 (~2.5KB) → base64
        // (encoding-conventions.md §4: base58 is O(n²); use base64 for >256B)
        let request_body = RegisterRequest {
            ed25519_pk: bs58::encode(&identity.ed25519.public).into_string(),
            ml_dsa_pk: BASE64.encode(&identity.ml_dsa.public),
        };

        let nonce = self.fetch_nonce().await?;

        let message = format!(
            "CREATE:{}:{}:{}",
            request_body.ed25519_pk, request_body.ml_dsa_pk, nonce
        );

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let response = add_auth_headers(
            self.client.post(format!("{}/accounts", self.server_url)),
            &auth,
        )
        .json(&request_body)
        .send()
        .await
        .context("Failed to send register request")?;

        handle_response(response).await
    }

    /// Get account info
    pub async fn get_account(&self, fingerprint: &str) -> Result<AccountInfo> {
        let response = self
            .client
            .get(format!("{}/accounts/{}", self.server_url, fingerprint))
            .send()
            .await
            .context("Failed to send get account request")?;

        handle_response(response).await
    }

    /// Upload a file
    pub async fn upload_file(
        &self,
        identity: &Identity,
        file_data: Vec<u8>,
    ) -> Result<UploadResponse> {
        let hash = bs58::encode(blake3::hash(&file_data).as_bytes()).into_string();

        let nonce = self.fetch_nonce().await?;
        let fingerprint = bs58::encode(identity.fingerprint).into_string();

        let message = format!("UPLOAD:{fingerprint}:{hash}:{nonce}");

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let response = add_auth_headers(
            self.client.post(format!("{}/files", self.server_url)),
            &auth,
        )
        .body(file_data)
        .send()
        .await
        .context("Failed to send upload request")?;

        handle_response(response).await
    }

    /// Download a file
    pub async fn download_file(&self, hash: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(format!("{}/files/{}", self.server_url, hash))
            .send()
            .await
            .context("Failed to send download request")?;

        if !response.status().is_success() {
            anyhow::bail!("Download failed: {}", response.status());
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .context("Failed to read file data")
    }

    /// Delete a file
    pub async fn delete_file(&self, identity: &Identity, hash: &str) -> Result<()> {
        let nonce = self.fetch_nonce().await?;
        let fingerprint = bs58::encode(identity.fingerprint).into_string();

        let message = format!("DELETE:{fingerprint}:{hash}:{nonce}");

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let response = add_auth_headers(
            self.client
                .delete(format!("{}/files/{}", self.server_url, hash)),
            &auth,
        )
        .send()
        .await
        .context("Failed to send delete request")?;

        if !response.status().is_success() {
            anyhow::bail!("Delete failed: {}", response.status());
        }

        Ok(())
    }

    /// Create a share
    pub async fn create_share(
        &self,
        identity: &Identity,
        file_hash: String,
        to_fingerprint: String,
        recrypt_key: Vec<u8>,
        backend_id: recrypt_core::pre::BackendId,
    ) -> Result<ShareResponse> {
        let nonce = self.fetch_nonce().await?;
        let fingerprint = bs58::encode(identity.fingerprint).into_string();

        let message = format!("SHARE:{fingerprint}:{to_fingerprint}:{file_hash}:{nonce}");

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let request_body = CreateShareRequest {
            to_fingerprint,
            file_hash,
            // base64: lattice recryption keys are multi-KB (encoding-conventions.md §4)
            recrypt_key: BASE64.encode(&recrypt_key),
            backend_id: backend_id.to_string(),
        };

        let response = add_auth_headers(
            self.client
                .post(format!("{}/recryption/share", self.server_url)),
            &auth,
        )
        .json(&request_body)
        .send()
        .await
        .context("Failed to send create share request")?;

        handle_response(response).await
    }

    /// Download a shared file
    pub async fn download_share(&self, identity: &Identity, share_id: &str) -> Result<Vec<u8>> {
        let nonce = self.fetch_nonce().await?;
        let fingerprint = bs58::encode(identity.fingerprint).into_string();

        let message = format!("DOWNLOAD:{fingerprint}:{share_id}:{nonce}");

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let response = add_auth_headers(
            self.client.get(format!(
                "{}/recryption/share/{}/file",
                self.server_url, share_id
            )),
            &auth,
        )
        .send()
        .await
        .context("Failed to send download share request")?;

        if !response.status().is_success() {
            anyhow::bail!("Download share failed: {}", response.status());
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .context("Failed to read share data")
    }

    /// Revoke a share
    pub async fn revoke_share(&self, identity: &Identity, share_id: &str) -> Result<()> {
        let nonce = self.fetch_nonce().await?;
        let fingerprint = bs58::encode(identity.fingerprint).into_string();

        let message = format!("REVOKE:{fingerprint}:{share_id}:{nonce}");

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let response = add_auth_headers(
            self.client
                .delete(format!("{}/recryption/share/{}", self.server_url, share_id)),
            &auth,
        )
        .send()
        .await
        .context("Failed to send revoke request")?;

        if !response.status().is_success() {
            anyhow::bail!("Revoke failed: {}", response.status());
        }

        Ok(())
    }

    /// List files owned by an account
    pub async fn list_files(&self, fingerprint: &str) -> Result<Vec<FileInfo>> {
        let response = self
            .client
            .get(format!(
                "{}/accounts/{}/files",
                self.server_url, fingerprint
            ))
            .send()
            .await
            .context("Failed to send list files request")?;

        handle_response(response).await
    }

    /// List shares for an account (requires auth)
    pub async fn list_shares(&self, identity: &Identity) -> Result<ShareListResponse> {
        let nonce = self.fetch_nonce().await?;
        let fingerprint = bs58::encode(identity.fingerprint).into_string();

        let message = format!("LIST_SHARES:{fingerprint}:{nonce}");

        let auth =
            sign_request_with_nonce(&self.client, &self.server_url, &message, identity, nonce)
                .await?;

        let response = add_auth_headers(
            self.client.get(format!(
                "{}/accounts/{fingerprint}/shares",
                self.server_url
            )),
            &auth,
        )
        .send()
        .await
        .context("Failed to send list shares request")?;

        handle_response(response).await
    }
}

// Request/Response types

#[derive(Serialize)]
struct RegisterRequest {
    ed25519_pk: String,
    ml_dsa_pk: String,
}

#[derive(Deserialize, Serialize)]
pub struct RegisterResponse {
    pub fingerprint: String,
    pub ed25519_pk: String,
    pub ml_dsa_pk: String,
    pub created_at: u64,
}

#[derive(Deserialize, Serialize)]
pub struct AccountInfo {
    pub fingerprint: String,
    pub ed25519_pk: String,
    pub ml_dsa_pk: String,
    pub created_at: u64,
}

#[derive(Deserialize, Serialize)]
pub struct UploadResponse {
    pub hash: String,
}

#[derive(Serialize)]
struct CreateShareRequest {
    to_fingerprint: String,
    file_hash: String,
    recrypt_key: String,
    backend_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct ShareResponse {
    pub share_id: String,
}

#[derive(Deserialize, Serialize)]
pub struct FileInfo {
    pub hash: String,
}

#[derive(Deserialize, Serialize)]
pub struct ShareListResponse {
    pub outgoing: Vec<ShareInfo>,
    pub incoming: Vec<ShareInfo>,
}

#[derive(Deserialize, Serialize)]
pub struct ShareInfo {
    pub share_id: String,
    pub from_fingerprint: String,
    pub to_fingerprint: String,
    pub file_hash: String,
    pub created_at: u64,
}

// Helper to handle JSON responses
async fn handle_response<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Request failed ({status}): {body}");
    }

    response
        .json()
        .await
        .context("Failed to parse JSON response")
}
