use recrypt_e2e_tests::harness::TestHarness;
use std::fs;

// ── Identity tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_identity_new() {
    let harness = TestHarness::new().await;
    let result = harness
        .cli()
        .run_ok(&["identity", "new", "--name", "alice"]).await;
    let json = result.json();
    assert_eq!(json["name"], "alice");
    assert!(
        json["fingerprint"].is_string(),
        "fingerprint should be a string"
    );
    let fp = json["fingerprint"].as_str().unwrap();
    assert!(!fp.is_empty(), "fingerprint should be non-empty");
}

#[tokio::test]
async fn test_identity_list() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.run_ok(&["identity", "new", "--name", "bob"]).await;

    let result = cli.run_ok(&["identity", "list"]).await;
    let json = result.json();
    let arr = json.as_array().expect("list should return array");
    assert_eq!(arr.len(), 2);

    let names: Vec<&str> = arr
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"alice"), "alice should be in list");
    assert!(names.contains(&"bob"), "bob should be in list");
}

#[tokio::test]
async fn test_identity_show() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    let result = cli.run_ok(&["identity", "show", "--name", "alice"]).await;
    let json = result.json();

    assert_eq!(json["name"], "alice");
    assert!(json["fingerprint"].is_string());
    assert!(json["ed25519_public"].is_string());
    assert!(json["ml_dsa_public"].is_string());
    assert!(json["pre_public"].is_string());
    assert!(!json["ed25519_public"].as_str().unwrap().is_empty());
    assert!(!json["ml_dsa_public"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_identity_use() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.run_ok(&["identity", "new", "--name", "bob"]).await;

    // Switch active to bob
    let result = cli.run_ok(&["identity", "use", "bob"]).await;
    let json = result.json();
    assert_eq!(json["active_identity"], "bob");

    // Verify list reflects the change
    let list_result = cli.run_ok(&["identity", "list"]).await;
    let arr = list_result.json();
    let arr = arr.as_array().unwrap();
    let bob = arr.iter().find(|v| v["name"] == "bob").unwrap();
    assert_eq!(bob["is_active"], true);

    let alice = arr.iter().find(|v| v["name"] == "alice").unwrap();
    assert_eq!(alice["is_active"], false);
}

#[tokio::test]
async fn test_identity_duplicate_name_fails() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.run_err(&["identity", "new", "--name", "alice"]).await;
}

// ── Account tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_account_register() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    let result = cli.run_ok(&["account", "register"]).await;
    let json = result.json();
    assert!(
        json["fingerprint"].is_string(),
        "register should return fingerprint"
    );
    assert!(!json["fingerprint"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_account_get() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    let result = cli.run_ok(&["account", "show"]).await;
    let json = result.json();
    assert!(json["ed25519_pk"].is_string());
    assert!(json["ml_dsa_pk"].is_string());
    assert!(!json["ed25519_pk"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_account_get_nonexistent() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    // Use show with an explicit fingerprint that doesn't exist
    cli.run_err(&["account", "show", "nonexistentfingerprint1234567890"]).await;
}

// ── Encrypt/decrypt tests (local, no server) ──────────────────────────────────

#[tokio::test]
#[ignore = "Blocked: Gordian Envelope from_envelope() doesn't roundtrip wrapped_key/ciphertext"]
async fn test_encrypt_decrypt_roundtrip() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");

    let input_path = harness.tmp().join("input.txt");
    let enc_path = harness.tmp().join("input.enc");
    let dec_path = harness.tmp().join("decrypted.txt");

    fs::write(&input_path, b"Hello, recrypt world!").unwrap();

    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ]).await;

    assert!(enc_path.exists(), "encrypted file should exist");

    cli.run_ok(&[
        "decrypt",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ]).await;

    let decrypted = fs::read(&dec_path).unwrap();
    assert_eq!(decrypted, b"Hello, recrypt world!");
}

#[tokio::test]
async fn test_encrypt_missing_file_fails() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");

    cli.run_err(&[
        "encrypt",
        "/nonexistent/path/to/file.txt",
        "--for",
        "alice",
    ]).await;
}

#[tokio::test]
#[ignore = "Blocked: Gordian Envelope from_envelope() doesn't roundtrip wrapped_key/ciphertext"]
async fn test_encrypt_empty_file() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");

    let input_path = harness.tmp().join("empty.txt");
    let enc_path = harness.tmp().join("empty.enc");
    let dec_path = harness.tmp().join("empty_decrypted.txt");

    fs::write(&input_path, b"").unwrap();

    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ]).await;

    cli.run_ok(&[
        "decrypt",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ]).await;

    let decrypted = fs::read(&dec_path).unwrap();
    assert!(decrypted.is_empty(), "decrypted empty file should be empty");
}

#[tokio::test]
#[ignore = "Blocked: Gordian Envelope from_envelope() doesn't roundtrip wrapped_key/ciphertext"]
async fn test_encrypt_large_file() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");

    // 10 MB of repeating pattern
    let pattern = b"LARGE_FILE_TEST_PATTERN_0123456789ABCDEF";
    let size = 10 * 1024 * 1024;
    let data: Vec<u8> = pattern
        .iter()
        .cloned()
        .cycle()
        .take(size)
        .collect();

    let input_path = harness.tmp().join("large.bin");
    let enc_path = harness.tmp().join("large.enc");
    let dec_path = harness.tmp().join("large_decrypted.bin");

    fs::write(&input_path, &data).unwrap();

    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ]).await;

    assert!(enc_path.exists(), "encrypted large file should exist");

    cli.run_ok(&[
        "decrypt",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ]).await;

    let decrypted = fs::read(&dec_path).unwrap();
    assert_eq!(decrypted.len(), size, "decrypted size should match original");
    assert_eq!(decrypted, data, "decrypted content should match original");
}

// ── File lifecycle tests (requires server) ────────────────────────────────────

#[tokio::test]
async fn test_file_upload_download() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    let input_path = harness.tmp().join("upload_me.txt");
    let enc_path = harness.tmp().join("upload_me.enc");
    let download_path = harness.tmp().join("downloaded.enc");

    let original = b"Data to upload and download";
    fs::write(&input_path, original).unwrap();

    // Encrypt first
    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ]).await;

    // Upload the encrypted file
    let upload_result = cli.run_ok(&["file", "upload", enc_path.to_str().unwrap()]).await;
    let upload_json = upload_result.json();
    let hash = upload_json["hash"].as_str().expect("upload should return hash");
    assert!(!hash.is_empty());

    // Download by hash
    cli.run_ok(&[
        "file",
        "download",
        hash,
        "--output",
        download_path.to_str().unwrap(),
    ]).await;

    // Uploaded and downloaded bytes should match
    let enc_bytes = fs::read(&enc_path).unwrap();
    let downloaded_bytes = fs::read(&download_path).unwrap();
    assert_eq!(downloaded_bytes, enc_bytes, "downloaded bytes should match uploaded bytes");
}

#[tokio::test]
async fn test_file_list() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    // Upload two files
    for (name, content) in [("file1.enc", b"content one"), ("file2.enc", b"content two")] {
        let path = harness.tmp().join(name);
        fs::write(&path, content).unwrap();
        cli.run_ok(&["file", "upload", path.to_str().unwrap()]).await;
    }

    let list_result = cli.run_ok(&["file", "list"]).await;
    let json = list_result.json();
    let arr = json.as_array().expect("file list should return array");
    assert_eq!(arr.len(), 2, "should have 2 files listed");
    for item in arr {
        assert!(item["hash"].is_string(), "each file should have a hash");
    }
}

#[tokio::test]
async fn test_file_delete() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    let file_path = harness.tmp().join("to_delete.enc");
    fs::write(&file_path, b"delete me").unwrap();

    let upload_result = cli.run_ok(&["file", "upload", file_path.to_str().unwrap()]).await;
    let hash = upload_result.json()["hash"]
        .as_str()
        .unwrap()
        .to_string();

    // Delete
    let del_result = cli.run_ok(&["file", "delete", &hash]).await;
    assert_eq!(del_result.json()["deleted"], hash);

    // Download should now fail
    let download_path = harness.tmp().join("should_not_exist.enc");
    cli.run_err(&[
        "file",
        "download",
        &hash,
        "--output",
        download_path.to_str().unwrap(),
    ]).await;
}

#[tokio::test]
async fn test_file_download_nonexistent() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    let bogus_hash = "11111111111111111111111111111111111111111111";
    let output_path = harness.tmp().join("nonexistent.enc");
    cli.run_err(&[
        "file",
        "download",
        bogus_hash,
        "--output",
        output_path.to_str().unwrap(),
    ]).await;
}

// ── Share tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_share_create_disabled() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    // share create should return an error about disabled feature
    let result = cli.run_err(&[
        "share",
        "create",
        "fakehash1234",
        "--to",
        "somerecipientfingerprint",
    ]).await;
    // Should mention the disabled state or Keyspace/Grant
    let combined = format!("{}{}", result.stdout, result.stderr);
    assert!(
        combined.contains("disabled") || combined.contains("Keyspace") || combined.contains("Grant"),
        "error should mention feature is disabled; got: {combined}"
    );
}

#[tokio::test]
async fn test_share_list_empty() {
    let harness = TestHarness::new().await;
    let mut cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;
    cli.set_identity("alice");
    cli.run_ok(&["account", "register"]).await;

    let result = cli.run_ok(&["share", "list"]).await;
    let json = result.json();
    // Should have outgoing and incoming arrays, both empty
    let outgoing = json["outgoing"].as_array().expect("outgoing should be array");
    let incoming = json["incoming"].as_array().expect("incoming should be array");
    assert!(outgoing.is_empty(), "outgoing should be empty");
    assert!(incoming.is_empty(), "incoming should be empty");
}

// ── Health smoke test ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let harness = TestHarness::new().await;
    let api = harness.api();

    let resp = api.health().await;
    assert_eq!(resp.status().as_u16(), 200, "health endpoint should return 200");
}
