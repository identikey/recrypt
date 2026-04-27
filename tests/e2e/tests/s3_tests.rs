//! S3/Minio integration tests.
//!
//! These tests require a running Docker daemon. They are gated behind the
//! `s3-tests` Cargo feature:
//!
//!   cargo test -p recrypt-e2e-tests --features s3-tests -- s3
//!
//! Each test starts (or reuses) a Minio container and creates its own bucket
//! so tests are fully isolated. The in-process server talks to Minio; the CLI
//! talks to the in-process server, so no S3 config is needed on the CLI side.

#![cfg(feature = "s3-tests")]

use base64::Engine as _;
use recrypt_core::{HybridEncryptor, pre::backends::MockBackend};
use recrypt_e2e_tests::{
    api::TestIdentity,
    harness::TestHarness,
    minio::MinioContext,
};
use std::fs;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Build a harness backed by a fresh Minio bucket.
async fn s3_harness() -> (MinioContext, TestHarness) {
    let minio = MinioContext::start()
        .await
        .expect("MinioContext::start failed — is Docker running?");
    let harness = TestHarness::with_config(minio.storage_config()).await;
    (minio, harness)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Upload an encrypted file via CLI and download it back, verifying the bytes
/// match end-to-end with an S3 storage backend.
#[tokio::test]
async fn test_upload_download_via_s3() {
    let (_minio, harness) = s3_harness().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;

    cli.run_ok(&["account", "register"]).await;

    let input_path = harness.tmp().join("s3_upload.txt");
    let enc_path = harness.tmp().join("s3_upload.enc");
    let download_path = harness.tmp().join("s3_downloaded.enc");

    let original = b"Hello from S3 storage backend!";
    fs::write(&input_path, original).unwrap();

    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ]).await;

    let upload_result = cli.run_ok(&["file", "upload", enc_path.to_str().unwrap()]).await;
    let hash = upload_result.json()["hash"]
        .as_str()
        .expect("upload should return hash")
        .to_string();
    assert!(!hash.is_empty());

    cli.run_ok(&[
        "file",
        "download",
        &hash,
        "--output",
        download_path.to_str().unwrap(),
    ]).await;

    let enc_bytes = fs::read(&enc_path).unwrap();
    let downloaded_bytes = fs::read(&download_path).unwrap();
    assert_eq!(
        downloaded_bytes, enc_bytes,
        "downloaded bytes must match uploaded bytes"
    );
}

/// Upload a file via CLI, delete it, and verify that a subsequent download fails.
#[tokio::test]
async fn test_file_delete_from_s3() {
    let (_minio, harness) = s3_harness().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;

    cli.run_ok(&["account", "register"]).await;

    let file_path = harness.tmp().join("to_delete.enc");
    fs::write(&file_path, b"delete me from S3").unwrap();

    let upload_result = cli.run_ok(&["file", "upload", file_path.to_str().unwrap()]).await;
    let hash = upload_result.json()["hash"]
        .as_str()
        .unwrap()
        .to_string();

    let del_result = cli.run_ok(&["file", "delete", &hash]).await;
    assert_eq!(del_result.json()["deleted"], hash);

    let output_path = harness.tmp().join("should_not_exist.enc");
    cli.run_err(&[
        "file",
        "download",
        &hash,
        "--output",
        output_path.to_str().unwrap(),
    ]).await;
}

/// Full recryption flow via the API with an S3 storage backend.
///
/// Alice uploads a file → creates a share for Bob → Bob fetches the recrypted
/// share → the response contains a `ciphertext_url` whose data is served from
/// the server (which proxies from S3).
#[tokio::test]
async fn test_share_through_s3() {
    let (_minio, harness) = s3_harness().await;
    let api = harness.api();
    let backend = MockBackend;

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    // Register both identities.
    let resp = api.register(&alice).await;
    assert_eq!(resp.status().as_u16(), 201, "alice register failed");

    let resp = api.register(&bob).await;
    assert_eq!(resp.status().as_u16(), 201, "bob register failed");

    // Alice uploads a file (arbitrary encrypted bytes).
    let file_bytes = b"Shared secret data stored in S3";
    let upload_resp = api.upload_file(&alice, file_bytes).await;
    assert_eq!(
        upload_resp.status().as_u16(),
        201,
        "upload failed"
    );
    let upload_json: serde_json::Value = upload_resp.json().await.unwrap();
    let file_hash = upload_json["hash"].as_str().expect("upload missing hash").to_string();

    // Alice generates a recryption key for Bob.
    let encryptor = HybridEncryptor::new(MockBackend);
    let recrypt_key = encryptor
        .backend()
        .generate_recrypt_key(&alice.pre_kp.secret, &bob.pre_kp.public)
        .expect("generate_recrypt_key failed");
    let recrypt_key_b64 = base64::engine::general_purpose::STANDARD.encode(recrypt_key.to_bytes());

    // Alice creates a share.
    let share_resp = api
        .create_share(&alice, &bob, &file_hash, &recrypt_key_b64, "")
        .await;
    assert_eq!(share_resp.status().as_u16(), 201, "create_share failed");
    let share_json: serde_json::Value = share_resp.json().await.unwrap();
    let share_id = share_json["share_id"].as_str().expect("missing share_id").to_string();

    // Bob fetches the recrypted share.
    let get_resp = api.get_share(&bob, &share_id).await;
    assert_eq!(
        get_resp.status().as_u16(),
        200,
        "get_share failed"
    );
    let get_json: serde_json::Value = get_resp.json().await.unwrap();

    // The response must contain a ciphertext_url pointing into the server's blob endpoint.
    let ciphertext_url = get_json["ciphertext_url"]
        .as_str()
        .expect("get_share response missing ciphertext_url")
        .to_string();
    assert!(
        !ciphertext_url.is_empty(),
        "ciphertext_url should be non-empty"
    );

    // Verify the URL resolves to actual data (the server proxies from S3).
    let data_resp = reqwest::Client::new()
        .get(&ciphertext_url)
        .send()
        .await
        .expect("GET ciphertext_url failed");
    assert_eq!(
        data_resp.status().as_u16(),
        200,
        "ciphertext_url should return 200"
    );
    let body = data_resp.bytes().await.expect("read ciphertext body");
    assert!(!body.is_empty(), "ciphertext body should be non-empty");
}

/// Upload a 1 MB file to S3 and verify the downloaded content matches exactly.
///
/// 1 MB is large enough to exercise multi-chunk S3 behaviour without making
/// the test prohibitively slow.
#[tokio::test]
async fn test_large_file_s3() {
    let (_minio, harness) = s3_harness().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;

    cli.run_ok(&["account", "register"]).await;

    // 1 MB of repeating pattern.
    let pattern = b"LARGE_S3_FILE_PATTERN_0123456789ABCDEF";
    let size = 1024 * 1024;
    let data: Vec<u8> = pattern.iter().cloned().cycle().take(size).collect();

    let input_path = harness.tmp().join("large_s3.bin");
    let enc_path = harness.tmp().join("large_s3.enc");
    let download_path = harness.tmp().join("large_s3_downloaded.bin");

    fs::write(&input_path, &data).unwrap();

    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ]).await;

    let upload_result = cli.run_ok(&["file", "upload", enc_path.to_str().unwrap()]).await;
    let hash = upload_result.json()["hash"]
        .as_str()
        .expect("upload should return hash")
        .to_string();

    cli.run_ok(&[
        "file",
        "download",
        &hash,
        "--output",
        download_path.to_str().unwrap(),
    ]).await;

    let enc_bytes = fs::read(&enc_path).unwrap();
    let downloaded_bytes = fs::read(&download_path).unwrap();
    assert_eq!(
        downloaded_bytes.len(),
        enc_bytes.len(),
        "downloaded size must match uploaded size"
    );
    assert_eq!(
        downloaded_bytes, enc_bytes,
        "downloaded content must match uploaded content"
    );
}
