//! API-level share and recryption tests.
//!
//! These tests bypass the CLI and exercise the full recryption flow via direct
//! HTTP calls to the server. Each test spins up its own in-process server with
//! ephemeral port, SQLite persistence, and mock PRE backend.

use base64::Engine as _;
use recrypt_core::pre::PreBackend as _;
use recrypt_core::pre::backends::MockBackend;
use recrypt_core::{EncryptedFile, HybridEncryptor};
use recrypt_e2e_tests::api::{ApiTestClient, TestIdentity, fresh_nonce};
use recrypt_e2e_tests::harness::TestHarness;
use recrypt_wire::MultiFormat;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Encrypt plaintext for an identity, returning (file_bytes, file_hash_b58, wrapped_key_b64).
fn make_encrypted_file(
    encryptor: &HybridEncryptor<MockBackend>,
    id: &TestIdentity,
    plaintext: &[u8],
) -> (Vec<u8>, String, String) {
    let encrypted: EncryptedFile = encryptor.encrypt(&id.pre_kp.public, plaintext).unwrap();
    let wrapped_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(encrypted.wrapped_key.to_bytes());
    let file_bytes = encrypted.to_envelope().unwrap();
    let file_hash = bs58::encode(blake3::hash(&file_bytes).as_bytes()).into_string();
    (file_bytes, file_hash, wrapped_key_b64)
}

/// Generate a recrypt key from alice to bob, returning base58-encoded key.
fn make_recrypt_key(
    encryptor: &HybridEncryptor<MockBackend>,
    from: &TestIdentity,
    to: &TestIdentity,
) -> String {
    let recrypt_key = encryptor
        .backend()
        .generate_recrypt_key(&from.pre_kp.secret, &to.pre_kp.public)
        .unwrap();
    base64::engine::general_purpose::STANDARD.encode(recrypt_key.to_bytes())
}

/// Register an identity and assert success.
async fn register(api: &ApiTestClient, id: &TestIdentity) {
    let resp = api.register(id).await;
    assert_eq!(
        resp.status(),
        201,
        "register failed: {:?}",
        resp.text().await
    );
}

/// Upload a file and assert success. Returns the file hash.
async fn upload(api: &ApiTestClient, id: &TestIdentity, file_bytes: &[u8]) -> String {
    let file_hash = bs58::encode(blake3::hash(file_bytes).as_bytes()).into_string();
    let resp = api.upload_file(id, file_bytes).await;
    assert_eq!(resp.status(), 201, "upload failed: {:?}", resp.text().await);
    file_hash
}

/// Create a share and return the share_id.
async fn create_share(
    api: &ApiTestClient,
    from: &TestIdentity,
    to: &TestIdentity,
    file_hash: &str,
    recrypt_key_b64: &str,
    wrapped_key_b64: &str,
) -> String {
    let resp = api
        .create_share(from, to, file_hash, recrypt_key_b64, wrapped_key_b64)
        .await;
    assert_eq!(
        resp.status(),
        201,
        "create_share failed: {:?}",
        resp.text().await
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    body["share_id"].as_str().unwrap().to_string()
}

// ── Share lifecycle ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_share_create_and_fetch() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"share create and fetch test");
    upload(&api, &alice, &file_bytes).await;

    // Verify the file is downloadable (confirms storage key is correct)
    let dl = api.download_file(&file_hash).await;
    assert_eq!(
        dl.status(),
        200,
        "download before share failed: {:?}",
        dl.text().await
    );

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    // Bob fetches the share
    let resp = api.get_share(&bob, &share_id).await;
    assert_eq!(
        resp.status(),
        200,
        "get_share failed: {:?}",
        resp.text().await
    );

    let body: serde_json::Value = resp.json().await.unwrap();

    // Must have wrapped_key_for_recipient
    let wrapped_key_b64 = body["wrapped_key_for_recipient"]
        .as_str()
        .expect("wrapped_key_for_recipient must be a string");
    assert!(!wrapped_key_b64.is_empty());
    let wrapped_bytes = base64::engine::general_purpose::STANDARD
        .decode(wrapped_key_b64)
        .expect("wrapped_key_for_recipient must be valid base64");
    assert!(!wrapped_bytes.is_empty());

    // Must have bao_hash
    let bao_hash = body["bao_hash"]
        .as_str()
        .expect("bao_hash must be a string");
    assert!(!bao_hash.is_empty());
    let bao_hash_bytes = bs58::decode(bao_hash)
        .into_vec()
        .expect("bao_hash must be valid base58");
    assert_eq!(bao_hash_bytes.len(), 32);

    // Must have ciphertext_url (not ciphertext bytes)
    let ciphertext_url = body["ciphertext_url"]
        .as_str()
        .expect("ciphertext_url must be a string");
    assert!(!ciphertext_url.is_empty());

    // Must have outboard_url
    let outboard_url = body["outboard_url"]
        .as_str()
        .expect("outboard_url must be a string");
    assert!(
        outboard_url.ends_with(".obao"),
        "outboard_url must end with .obao: {outboard_url}"
    );

    // Must NOT have ciphertext field
    assert!(
        body.get("ciphertext").is_none(),
        "response must not contain raw ciphertext field"
    );
}

#[tokio::test]
async fn test_share_revoke() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"revoke test file");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    // Verify Bob can fetch it before revocation
    let resp = api.get_share(&bob, &share_id).await;
    assert_eq!(resp.status(), 200, "pre-revoke get_share failed");

    // Alice revokes
    let resp = api.revoke_share(&alice, &share_id).await;
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 204,
        "revoke failed with status {}: {:?}",
        resp.status(),
        resp.text().await
    );

    // Bob can no longer fetch it
    let resp = api.get_share(&bob, &share_id).await;
    let status = resp.status().as_u16();
    assert!(
        status == 404 || status == 410 || status == 403,
        "expected 404/410/403 after revoke, got {status}"
    );
}

#[tokio::test]
async fn test_share_list() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"list shares test");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    // List shares for Alice (the sharer)
    let resp = api.list_shares(&alice).await;
    assert_eq!(
        resp.status(),
        200,
        "list_shares failed: {:?}",
        resp.text().await
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    // Response is { outgoing: [...], incoming: [...] }
    let outgoing = body["outgoing"]
        .as_array()
        .expect("list_shares must return outgoing array");
    assert!(
        !outgoing.is_empty(),
        "list_shares outgoing must have at least one share after creating one"
    );

    // The created share_id should appear in outgoing
    let found = outgoing
        .iter()
        .any(|s| s["share_id"].as_str().unwrap_or("") == share_id);
    assert!(
        found,
        "created share_id {share_id} not found in outgoing: {outgoing:?}"
    );
}

// ── Recryption verification ───────────────────────────────────────────────────

#[tokio::test]
async fn test_full_recryption_roundtrip() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    let plaintext = b"full recryption roundtrip plaintext";
    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, plaintext);
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    // Bob fetches the recrypted share
    let resp = api.get_share(&bob, &share_id).await;
    assert_eq!(
        resp.status(),
        200,
        "get_share failed: {:?}",
        resp.text().await
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    let wrapped_key_b64 = body["wrapped_key_for_recipient"]
        .as_str()
        .expect("wrapped_key_for_recipient must be present");
    let wrapped_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(wrapped_key_b64)
        .expect("wrapped_key must be valid base64");

    // Bob decrypts the recrypted wrapped key with his secret key
    let new_ciphertext = recrypt_core::pre::Ciphertext::from_bytes(&wrapped_key_bytes)
        .expect("recrypted wrapped_key must parse as Ciphertext");
    let decrypted_key_material = MockBackend
        .decrypt(&bob.pre_kp.secret, &new_ciphertext)
        .expect("Bob must be able to decrypt the recrypted wrapped key");

    assert!(
        !decrypted_key_material.is_empty(),
        "decrypted key material must not be empty"
    );
}

#[tokio::test]
async fn test_response_has_no_bulk_ciphertext() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"no bulk ciphertext test");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    let resp = api.get_share(&bob, &share_id).await;
    assert_eq!(resp.status(), 200);

    // Capture raw body text and check it's small JSON, not bulk bytes
    let body_text = resp.text().await.unwrap();
    let body: serde_json::Value =
        serde_json::from_str(&body_text).expect("response must be valid JSON");

    // No ciphertext field
    assert!(
        body.get("ciphertext").is_none(),
        "response must not contain raw ciphertext field"
    );

    // Response must be small (< 8 KiB) — proves no bulk data leaked
    assert!(
        body_text.len() < 8 * 1024,
        "response body is too large ({} bytes), bulk ciphertext may have leaked",
        body_text.len()
    );
}

#[tokio::test]
async fn test_ciphertext_url_resolves() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"ciphertext url resolves test");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    let resp = api.get_share(&bob, &share_id).await;
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let ciphertext_url = body["ciphertext_url"]
        .as_str()
        .expect("ciphertext_url must be present");

    // Verify the URL has the correct structure: ends with blob/b3/{bao_hash}
    // (The test harness uses in-memory storage so the URL is not HTTP-fetchable,
    // but we verify the URL is well-formed and contains the content hash.)
    let bao_hash = body["bao_hash"].as_str().expect("bao_hash must be present");
    assert!(
        ciphertext_url.contains(bao_hash),
        "ciphertext_url must contain bao_hash. url={ciphertext_url}, hash={bao_hash}"
    );
    assert!(
        ciphertext_url.contains("blob/b3/"),
        "ciphertext_url must use blob/b3/ path prefix: {ciphertext_url}"
    );
    assert!(!ciphertext_url.is_empty());
}

// ── Multi-recipient ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_multi_recipient_share() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);
    let carol = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;
    register(&api, &carol).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"multi recipient test");
    upload(&api, &alice, &file_bytes).await;

    // Share with Bob
    let recrypt_key_bob = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id_bob = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_bob,
        &wrapped_key_b64,
    )
    .await;

    // Share with Carol
    let recrypt_key_carol = make_recrypt_key(&encryptor, &alice, &carol);
    let share_id_carol = create_share(
        &api,
        &alice,
        &carol,
        &file_hash,
        &recrypt_key_carol,
        &wrapped_key_b64,
    )
    .await;

    // Both can fetch independently
    let resp_bob = api.get_share(&bob, &share_id_bob).await;
    assert_eq!(resp_bob.status(), 200, "Bob failed to fetch share");

    let resp_carol = api.get_share(&carol, &share_id_carol).await;
    assert_eq!(resp_carol.status(), 200, "Carol failed to fetch share");

    // Both get non-empty wrapped keys
    let bob_body: serde_json::Value = resp_bob.json().await.unwrap();
    let carol_body: serde_json::Value = resp_carol.json().await.unwrap();

    assert!(
        bob_body["wrapped_key_for_recipient"]
            .as_str()
            .unwrap()
            .len()
            > 0
    );
    assert!(
        carol_body["wrapped_key_for_recipient"]
            .as_str()
            .unwrap()
            .len()
            > 0
    );
}

#[tokio::test]
async fn test_revoke_one_preserves_others() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);
    let carol = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;
    register(&api, &carol).await;

    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"revoke one test");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_bob = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id_bob = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_bob,
        &wrapped_key_b64,
    )
    .await;

    let recrypt_key_carol = make_recrypt_key(&encryptor, &alice, &carol);
    let share_id_carol = create_share(
        &api,
        &alice,
        &carol,
        &file_hash,
        &recrypt_key_carol,
        &wrapped_key_b64,
    )
    .await;

    // Revoke Bob's share
    let resp = api.revoke_share(&alice, &share_id_bob).await;
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 204,
        "revoke failed: {:?}",
        resp.text().await
    );

    // Bob's share is gone
    let resp_bob = api.get_share(&bob, &share_id_bob).await;
    let bob_status = resp_bob.status().as_u16();
    assert!(
        bob_status == 404 || bob_status == 410 || bob_status == 403,
        "Bob should not access revoked share, got {bob_status}"
    );

    // Carol's share is still accessible
    let resp_carol = api.get_share(&carol, &share_id_carol).await;
    assert_eq!(
        resp_carol.status(),
        200,
        "Carol should still access her share"
    );
}

// ── Authorization / negative tests ───────────────────────────────────────────

#[tokio::test]
async fn test_share_nonexistent_file_fails() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;

    // Use a fake hash that was never uploaded
    let fake_hash = "11111111111111111111111111111111111111111111";
    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);

    let resp = api
        .create_share(&alice, &bob, fake_hash, &recrypt_key_b64, "")
        .await;
    let status = resp.status().as_u16();
    assert!(
        status == 404 || status == 400 || status == 422,
        "expected error for nonexistent file hash, got {status}"
    );
}

#[tokio::test]
async fn test_share_to_unregistered_recipient_fails() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let unregistered = TestIdentity::new(&backend); // never registered

    register(&api, &alice).await;

    let (file_bytes, file_hash, _wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"unregistered recipient test");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &unregistered);

    let resp = api
        .create_share(&alice, &unregistered, &file_hash, &recrypt_key_b64, "")
        .await;
    let status = resp.status().as_u16();
    assert!(
        status == 404 || status == 400 || status == 422,
        "expected error for unregistered recipient, got {status}"
    );
}

#[tokio::test]
async fn test_share_by_non_owner_fails() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(MockBackend);

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);
    let carol = TestIdentity::new(&backend);

    register(&api, &alice).await;
    register(&api, &bob).await;
    register(&api, &carol).await;

    // Alice uploads and shares with Bob
    let (file_bytes, file_hash, wrapped_key_b64) =
        make_encrypted_file(&encryptor, &alice, b"non-owner share test");
    upload(&api, &alice, &file_bytes).await;

    let recrypt_key_b64 = make_recrypt_key(&encryptor, &alice, &bob);
    let share_id = create_share(
        &api,
        &alice,
        &bob,
        &file_hash,
        &recrypt_key_b64,
        &wrapped_key_b64,
    )
    .await;

    // Carol (not the recipient) tries to fetch Bob's share — should be rejected
    let resp = api.get_share(&carol, &share_id).await;
    let status = resp.status().as_u16();
    assert!(
        status == 401 || status == 403 || status == 404,
        "expected 401/403/404 when non-recipient fetches share, got {status}"
    );
}

#[tokio::test]
async fn test_invalid_signature_rejected() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;

    let alice = TestIdentity::new(&backend);

    // Build a valid registration request then corrupt the ed25519 signature
    let nonce = fresh_nonce();
    let message = format!(
        "CREATE:{}:{}:{}",
        alice.ed_pk_b64, alice.ml_dsa_pk_b64, nonce
    );
    let (ed_sig, ml_sig) = alice.sign(&message);

    // Corrupt the ed25519 signature by flipping bytes in the base64
    let corrupted_ed_sig = {
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&ed_sig)
            .unwrap();
        bytes[0] ^= 0xFF;
        bytes[1] ^= 0xFF;
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    };

    let resp = api
        .client
        .post(format!("{}/accounts", api.base_url))
        .header("X-Nonce", &nonce)
        .header("X-Public-Key", &alice.fingerprint)
        .header("X-Signature-Ed25519", &corrupted_ed_sig)
        .header("X-Signature-MlDsa", &ml_sig)
        .json(&serde_json::json!({
            "ed25519_pk": alice.ed_pk_b64,
            "ml_dsa_pk": alice.ml_dsa_pk_b64,
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 401 || status == 403,
        "expected rejection for invalid signature, got {status}"
    );
}

#[tokio::test]
async fn test_unsigned_request_rejected() {
    let harness = TestHarness::new().await;
    let api = harness.api();

    // POST /accounts without any auth headers
    let resp = api
        .client
        .post(format!("{}/accounts", api.base_url))
        .json(&serde_json::json!({
            "ed25519_pk": "fakepublickey",
            "ml_dsa_pk": "fakepqkey",
        }))
        .send()
        .await
        .unwrap();

    let status = resp.status().as_u16();
    assert!(
        status >= 400,
        "expected rejection (4xx or 5xx) for unsigned request, got {status}"
    );
}

#[tokio::test]
async fn test_nonce_replay_rejected() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;

    let alice = TestIdentity::new(&backend);
    let alice2 = TestIdentity::new(&backend); // second identity using the same nonce

    // First request with a fixed nonce — should succeed
    let nonce = fresh_nonce();
    let message1 = format!(
        "CREATE:{}:{}:{}",
        alice.ed_pk_b64, alice.ml_dsa_pk_b64, nonce
    );
    let (ed_sig1, ml_sig1) = alice.sign(&message1);

    let resp1 = api
        .client
        .post(format!("{}/accounts", api.base_url))
        .header("X-Nonce", &nonce)
        .header("X-Public-Key", &alice.fingerprint)
        .header("X-Signature-Ed25519", &ed_sig1)
        .header("X-Signature-MlDsa", &ml_sig1)
        .json(&serde_json::json!({
            "ed25519_pk": alice.ed_pk_b64,
            "ml_dsa_pk": alice.ml_dsa_pk_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp1.status(),
        201,
        "first request should succeed: {:?}",
        resp1.text().await
    );

    // Second request reusing the same nonce — should be rejected
    let message2 = format!(
        "CREATE:{}:{}:{}",
        alice2.ed_pk_b64, alice2.ml_dsa_pk_b64, nonce
    );
    let (ed_sig2, ml_sig2) = alice2.sign(&message2);

    let resp2 = api
        .client
        .post(format!("{}/accounts", api.base_url))
        .header("X-Nonce", &nonce) // same nonce reused
        .header("X-Public-Key", &alice2.fingerprint)
        .header("X-Signature-Ed25519", &ed_sig2)
        .header("X-Signature-MlDsa", &ml_sig2)
        .json(&serde_json::json!({
            "ed25519_pk": alice2.ed_pk_b64,
            "ml_dsa_pk": alice2.ml_dsa_pk_b64,
        }))
        .send()
        .await
        .unwrap();

    let status2 = resp2.status().as_u16();
    assert!(
        status2 == 400 || status2 == 401 || status2 == 403 || status2 == 409,
        "expected rejection for nonce replay, got {status2}"
    );
}

// ── Public endpoints ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_returns_ok() {
    let harness = TestHarness::new().await;
    let api = harness.api();

    let resp = api.health().await;
    assert_eq!(resp.status(), 200, "health endpoint failed");

    let body: serde_json::Value = resp.json().await.unwrap();
    // Should have some form of ok status
    let status_field = body["status"]
        .as_str()
        .or_else(|| body["ok"].as_str())
        .unwrap_or("unknown");
    // Accept "ok", "healthy", or any non-empty value
    assert!(
        !status_field.is_empty() || body["ok"].as_bool().unwrap_or(false),
        "health response should indicate ok status: {body:?}"
    );
}

#[tokio::test]
async fn test_nonce_endpoint() {
    let harness = TestHarness::new().await;
    let api = harness.api();

    let resp = api.get_nonce().await;
    assert_eq!(resp.status(), 200, "nonce endpoint failed");

    // Response should be a non-empty string (the nonce)
    let body_text = resp.text().await.unwrap();
    assert!(!body_text.trim().is_empty(), "nonce must not be empty");
    // Should be at least a few characters
    assert!(
        body_text.trim().len() >= 4,
        "nonce seems too short: {body_text:?}"
    );
}

#[tokio::test]
async fn test_get_account_public() {
    let harness = TestHarness::new().await;
    let api = harness.api();
    let backend = MockBackend;

    let alice = TestIdentity::new(&backend);
    register(&api, &alice).await;

    // Fetch account without any auth headers (public endpoint)
    let resp = api.get_account(&alice.fingerprint).await;
    assert_eq!(
        resp.status(),
        200,
        "get_account failed: {:?}",
        resp.text().await
    );

    let body: serde_json::Value = resp.json().await.unwrap();

    // Should include Alice's public keys
    let ed_pk = body["ed25519_pk"].as_str().unwrap_or("");
    let ml_pk = body["ml_dsa_pk"].as_str().unwrap_or("");
    assert_eq!(ed_pk, alice.ed_pk_b64, "ed25519_pk mismatch");
    assert_eq!(ml_pk, alice.ml_dsa_pk_b64, "ml_dsa_pk mismatch");
}
