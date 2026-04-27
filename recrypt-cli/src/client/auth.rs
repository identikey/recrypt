// Authentication helpers for signing API requests

use anyhow::{Context as AnyhowContext, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, SigningKey};
use recrypt_ffi::ed25519;
use recrypt_ffi::liboqs::{pq_sign, PqAlgorithm};
use serde::Deserialize;

use crate::wallet::Identity;

#[derive(Debug)]
pub struct AuthHeaders {
    pub fingerprint: String,
    pub nonce: String,
    pub ed25519_sig: String, // base64
    pub ml_dsa_sig: String,  // base64
}

#[derive(Deserialize)]
struct NonceResponse {
    nonce: String,
    #[allow(dead_code)]
    expires_at: u64,
}

// Note: sign_request is kept for future use when we need to fetch nonce inline
#[allow(dead_code)]
/// Fetch nonce and sign a request message
pub async fn sign_request(
    client: &reqwest::Client,
    server: &str,
    message: &str,
    identity: &Identity,
) -> Result<AuthHeaders> {
    // 1. Fetch nonce from server
    let nonce_url = format!("{}/nonce", server.trim_end_matches('/'));
    let response = client
        .get(&nonce_url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch nonce from {nonce_url}"))?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to fetch nonce: {}", response.status());
    }

    let nonce_resp: NonceResponse = response
        .json()
        .await
        .context("Failed to parse nonce response")?;

    sign_with_nonce(client, message, identity, nonce_resp.nonce).await
}

/// Sign a request message with a pre-fetched nonce
pub async fn sign_request_with_nonce(
    _client: &reqwest::Client,
    _server: &str,
    message: &str,
    identity: &Identity,
    nonce: String,
) -> Result<AuthHeaders> {
    sign_with_nonce(_client, message, identity, nonce).await
}

/// Internal helper to sign with a given nonce
async fn sign_with_nonce(
    _client: &reqwest::Client,
    message: &str,
    identity: &Identity,
    nonce: String,
) -> Result<AuthHeaders> {
    // 2. Build signing message
    let signing_message = message.as_bytes();

    // 3. Sign with ED25519
    let ed25519_sk: [u8; 32] = identity
        .ed25519
        .secret
        .as_slice()
        .try_into()
        .context("ED25519 secret key must be 32 bytes")?;

    let signing_key = SigningKey::from_bytes(&ed25519_sk);
    let ed25519_sig: Signature = ed25519::ed25519_sign(&signing_key, signing_message);

    // 4. Sign with ML-DSA
    let ml_dsa_sk_bytes = &identity.ml_dsa.secret;

    let ml_dsa_sig = pq_sign(&ml_dsa_sk_bytes, PqAlgorithm::MlDsa87, signing_message)
        .context("Failed to sign with ML-DSA")?;

    // 5. Return headers
    Ok(AuthHeaders {
        fingerprint: bs58::encode(identity.fingerprint).into_string(),
        nonce,
        ed25519_sig: BASE64.encode(ed25519_sig.to_bytes()),
        ml_dsa_sig: BASE64.encode(&ml_dsa_sig),
    })
}

/// Add auth headers to a request builder
pub fn add_auth_headers(
    builder: reqwest::RequestBuilder,
    auth: &AuthHeaders,
) -> reqwest::RequestBuilder {
    builder
        .header("X-Public-Key", &auth.fingerprint)
        .header("X-Nonce", &auth.nonce)
        .header("X-Signature-Ed25519", &auth.ed25519_sig)
        .header("X-Signature-MlDsa", &auth.ml_dsa_sig)
}
