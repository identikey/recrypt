//! API test client: direct HTTP calls with dual-signature authentication.
//!
//! Reuses the signing pattern from `recrypt-server/tests/recryption_share_test.rs`.

use base64::Engine as _;
use ed25519_dalek::Signer;
use recrypt_core::pre::{self, PreBackend};
use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen, pq_sign};
use reqwest::Client;
use std::time::{SystemTime, UNIX_EPOCH};

/// A test identity with all key material needed for signing.
pub struct TestIdentity {
    pub fingerprint: String,
    pub ed_key: ed25519_dalek::SigningKey,
    pub ed_pk_b58: String,
    pub ml_dsa_secret: Vec<u8>,
    pub ml_dsa_pk_b58: String,
    pub pre_kp: pre::KeyPair,
}

impl TestIdentity {
    /// Generate a new random test identity using the given PRE backend.
    pub fn new(backend: &dyn PreBackend) -> Self {
        use recrypt_ffi::ed25519::ed25519_keygen;

        let ed_kp = ed25519_keygen();
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let pre_kp = backend.generate_keypair().unwrap();

        let ed_pk_bytes = ed_kp.verifying_key.to_bytes();
        let fingerprint = bs58::encode(blake3::hash(&ed_pk_bytes).as_bytes()).into_string();

        Self {
            fingerprint,
            ed_key: ed_kp.signing_key,
            ed_pk_b58: bs58::encode(ed_pk_bytes).into_string(),
            ml_dsa_secret: pq_kp.secret_key,
            ml_dsa_pk_b58: bs58::encode(&pq_kp.public_key).into_string(),
            pre_kp,
        }
    }

    /// Sign a message with both ED25519 and ML-DSA-87, returning (ed_sig_b64, ml_sig_b64).
    pub fn sign(&self, message: &str) -> (String, String) {
        let b64 = base64::engine::general_purpose::STANDARD;

        let ed_sig = self.ed_key.sign(message.as_bytes());
        let ed_sig_b64 = b64.encode(ed_sig.to_bytes());

        let ml_sig = pq_sign(&self.ml_dsa_secret, PqAlgorithm::MlDsa87, message.as_bytes())
            .expect("ml-dsa sign failed");
        let ml_sig_b64 = b64.encode(&ml_sig);

        (ed_sig_b64, ml_sig_b64)
    }
}

/// Generate a fresh nonce in the server's expected format.
pub fn fresh_nonce() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{}:{}", ts, uuid::Uuid::new_v4())
}

/// HTTP client for the recrypt server API with signing helpers.
pub struct ApiTestClient {
    pub client: Client,
    pub base_url: String,
}

impl ApiTestClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    // ── Account operations ──────────────────────────────────────────────

    /// Register an identity on the server. Returns the HTTP response.
    pub async fn register(&self, id: &TestIdentity) -> reqwest::Response {
        let nonce = fresh_nonce();
        let message = format!("CREATE:{}:{}:{}", id.ed_pk_b58, id.ml_dsa_pk_b58, nonce);
        let (ed_sig, ml_sig) = id.sign(&message);

        self.client
            .post(format!("{}/accounts", self.base_url))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &id.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .json(&serde_json::json!({
                "ed25519_pk": id.ed_pk_b58,
                "ml_dsa_pk": id.ml_dsa_pk_b58,
            }))
            .send()
            .await
            .expect("register request failed")
    }

    /// Get account info by fingerprint (public endpoint, no auth).
    pub async fn get_account(&self, fingerprint: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/accounts/{}", self.base_url, fingerprint))
            .send()
            .await
            .expect("get_account request failed")
    }

    // ── File operations ─────────────────────────────────────────────────

    /// Upload a file (raw bytes). Returns the HTTP response.
    pub async fn upload_file(
        &self,
        id: &TestIdentity,
        file_bytes: &[u8],
    ) -> reqwest::Response {
        let file_hash = bs58::encode(blake3::hash(file_bytes).as_bytes()).into_string();
        let nonce = fresh_nonce();
        let message = format!("UPLOAD:{}:{}:{}", id.fingerprint, file_hash, nonce);
        let (ed_sig, ml_sig) = id.sign(&message);

        self.client
            .post(format!("{}/files", self.base_url))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &id.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .header("content-type", "application/octet-stream")
            .body(file_bytes.to_vec())
            .send()
            .await
            .expect("upload request failed")
    }

    /// Download a file by hash (public endpoint).
    pub async fn download_file(&self, hash: &str) -> reqwest::Response {
        self.client
            .get(format!("{}/files/{}", self.base_url, hash))
            .send()
            .await
            .expect("download request failed")
    }

    /// Delete a file by hash.
    pub async fn delete_file(
        &self,
        id: &TestIdentity,
        file_hash: &str,
    ) -> reqwest::Response {
        let nonce = fresh_nonce();
        let message = format!("DELETE:{}:{}:{}", id.fingerprint, file_hash, nonce);
        let (ed_sig, ml_sig) = id.sign(&message);

        self.client
            .delete(format!("{}/files/{}", self.base_url, file_hash))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &id.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .send()
            .await
            .expect("delete request failed")
    }

    // ── Share operations ────────────────────────────────────────────────

    /// Create a share (recryption key + original wrapped key). Returns the HTTP response.
    pub async fn create_share(
        &self,
        from: &TestIdentity,
        to: &TestIdentity,
        file_hash: &str,
        recrypt_key_b58: &str,
        wrapped_key_b58: &str,
    ) -> reqwest::Response {
        let nonce = fresh_nonce();
        let message = format!(
            "SHARE:{}:{}:{}:{}",
            from.fingerprint, to.fingerprint, file_hash, nonce
        );
        let (ed_sig, ml_sig) = from.sign(&message);

        self.client
            .post(format!("{}/recryption/share", self.base_url))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &from.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .json(&serde_json::json!({
                "to_fingerprint": to.fingerprint,
                "file_hash": file_hash,
                "recrypt_key": recrypt_key_b58,
                "wrapped_key": wrapped_key_b58,
                "backend_id": "mock",
            }))
            .send()
            .await
            .expect("create_share request failed")
    }

    /// Get a recrypted share by ID (Bob fetches).
    pub async fn get_share(
        &self,
        id: &TestIdentity,
        share_id: &str,
    ) -> reqwest::Response {
        let nonce = fresh_nonce();
        let message = format!("DOWNLOAD:{}:{}:{}", id.fingerprint, share_id, nonce);
        let (ed_sig, ml_sig) = id.sign(&message);

        self.client
            .get(format!("{}/recryption/share/{}", self.base_url, share_id))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &id.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .send()
            .await
            .expect("get_share request failed")
    }

    /// Revoke a share.
    pub async fn revoke_share(
        &self,
        id: &TestIdentity,
        share_id: &str,
    ) -> reqwest::Response {
        let nonce = fresh_nonce();
        let message = format!("REVOKE:{}:{}:{}", id.fingerprint, share_id, nonce);
        let (ed_sig, ml_sig) = id.sign(&message);

        self.client
            .delete(format!("{}/recryption/share/{}", self.base_url, share_id))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &id.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .send()
            .await
            .expect("revoke_share request failed")
    }

    /// List shares for a fingerprint.
    pub async fn list_shares(
        &self,
        id: &TestIdentity,
    ) -> reqwest::Response {
        let nonce = fresh_nonce();
        let message = format!("LIST_SHARES:{}:{}", id.fingerprint, nonce);
        let (ed_sig, ml_sig) = id.sign(&message);

        self.client
            .get(format!(
                "{}/accounts/{}/shares",
                self.base_url, id.fingerprint
            ))
            .header("X-Nonce", &nonce)
            .header("X-Public-Key", &id.fingerprint)
            .header("X-Signature-Ed25519", &ed_sig)
            .header("X-Signature-MlDsa", &ml_sig)
            .send()
            .await
            .expect("list_shares request failed")
    }

    // ── Public/health endpoints ─────────────────────────────────────────

    /// Hit the health endpoint.
    pub async fn health(&self) -> reqwest::Response {
        self.client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .expect("health request failed")
    }

    /// Get a nonce from the server.
    pub async fn get_nonce(&self) -> reqwest::Response {
        self.client
            .get(format!("{}/nonce", self.base_url))
            .send()
            .await
            .expect("get_nonce request failed")
    }

    /// List files owned by a fingerprint (public endpoint).
    pub async fn list_files(&self, fingerprint: &str) -> reqwest::Response {
        self.client
            .get(format!(
                "{}/accounts/{}/files",
                self.base_url, fingerprint
            ))
            .send()
            .await
            .expect("list_files request failed")
    }
}
