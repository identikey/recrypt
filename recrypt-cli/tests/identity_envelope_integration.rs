use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn recrypt_cmd(wallet_path: &str, config_dir: &str) -> Command {
    let mut cmd = Command::cargo_bin("recrypt").unwrap();
    cmd.args(["--json", "--backend", "mock", "--wallet", wallet_path])
        .env("RECRYPT_WALLET_PASSWORD", "testpass123")
        .env("RECRYPT_CONFIG_DIR", config_dir)
        .env("RECRYPT_NO_KEYCHAIN", "1");
    cmd
}

fn setup() -> (TempDir, String, String) {
    let tmp = tempfile::tempdir().unwrap();
    let wallet = tmp.path().join("test-wallet.recrypt");
    let config_dir = tmp.path().to_str().unwrap().to_string();
    let wallet_path = wallet.to_str().unwrap().to_string();
    (tmp, wallet_path, config_dir)
}

#[test]
fn export_envelope_writes_cbor_tag_200_prefix() {
    let (tmp, wallet_path, config_dir) = setup();

    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "new", "--name", "alice"])
        .assert()
        .success();

    let output_path = tmp.path().join("alice.envelope");
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "export",
            "alice",
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "envelope",
        ])
        .assert()
        .success();

    assert!(output_path.exists(), "export file should exist");
    let bytes = fs::read(&output_path).unwrap();
    assert!(bytes.len() >= 2, "export file too short");
    assert_eq!(
        bytes[0], 0xd8,
        "first byte should be 0xd8 (CBOR tag high byte)"
    );
    assert_eq!(
        bytes[1], 0xc8,
        "second byte should be 0xc8 (CBOR tag 200 low byte)"
    );
}

#[test]
fn import_envelope_roundtrip() {
    let (tmp, wallet_path, config_dir) = setup();

    // Create identity and record fingerprint
    let create_out = recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "new", "--name", "alice"])
        .output()
        .unwrap();
    assert!(create_out.status.success());
    let create_json: serde_json::Value = serde_json::from_slice(&create_out.stdout).unwrap();
    let original_fp = create_json["fingerprint"].as_str().unwrap().to_string();

    // Export as envelope
    let output_path = tmp.path().join("alice.envelope");
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "export",
            "alice",
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "envelope",
        ])
        .assert()
        .success();

    // Delete original identity
    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "delete", "alice"])
        .assert()
        .success();

    // Import from envelope
    let import_out = recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "import",
            output_path.to_str().unwrap(),
            "--name",
            "alice-restored",
        ])
        .output()
        .unwrap();
    assert!(
        import_out.status.success(),
        "import failed: {}",
        String::from_utf8_lossy(&import_out.stderr)
    );

    // Show restored identity and verify fingerprint
    let show_out = recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "show", "--name", "alice-restored"])
        .output()
        .unwrap();
    assert!(show_out.status.success());
    let show_json: serde_json::Value = serde_json::from_slice(&show_out.stdout).unwrap();
    let restored_fp = show_json["fingerprint"].as_str().unwrap();

    assert_eq!(
        original_fp, restored_fp,
        "fingerprint should be preserved across envelope export/import"
    );
}

#[test]
fn import_json_still_works() {
    let (tmp, wallet_path, config_dir) = setup();

    // Create identity
    let create_out = recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "new", "--name", "alice"])
        .output()
        .unwrap();
    assert!(create_out.status.success());
    let create_json: serde_json::Value = serde_json::from_slice(&create_out.stdout).unwrap();
    let original_fp = create_json["fingerprint"].as_str().unwrap().to_string();

    // Export as JSON
    let json_path = tmp.path().join("alice.json");
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "export",
            "alice",
            "--output",
            json_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    // Verify it looks like JSON
    let file_bytes = fs::read(&json_path).unwrap();
    assert_eq!(file_bytes[0], b'{', "JSON export should start with '{{'");

    // Delete and re-import via auto-detect
    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "delete", "alice"])
        .assert()
        .success();

    let import_out = recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "import",
            json_path.to_str().unwrap(),
            "--name",
            "alice-json",
        ])
        .output()
        .unwrap();
    assert!(
        import_out.status.success(),
        "json import failed: {}",
        String::from_utf8_lossy(&import_out.stderr)
    );

    // Verify fingerprint
    let show_out = recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "show", "--name", "alice-json"])
        .output()
        .unwrap();
    assert!(show_out.status.success());
    let show_json: serde_json::Value = serde_json::from_slice(&show_out.stdout).unwrap();
    assert_eq!(
        original_fp,
        show_json["fingerprint"].as_str().unwrap(),
        "fingerprint should be preserved across JSON export/import"
    );
}

#[test]
fn import_auto_detect_both_formats() {
    let (tmp, wallet_path, config_dir) = setup();

    // Create two identities
    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "new", "--name", "alice"])
        .assert()
        .success();
    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "new", "--name", "bob"])
        .assert()
        .success();

    let env_path = tmp.path().join("alice.envelope");
    let json_path = tmp.path().join("bob.json");

    // Export both formats
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "export",
            "alice",
            "--output",
            env_path.to_str().unwrap(),
            "--format",
            "envelope",
        ])
        .assert()
        .success();
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "export",
            "bob",
            "--output",
            json_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success();

    // Delete both
    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "delete", "alice"])
        .assert()
        .success();
    recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "delete", "bob"])
        .assert()
        .success();

    // Import both via same `identity import` command (auto-detect)
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "import",
            env_path.to_str().unwrap(),
            "--name",
            "alice-env",
        ])
        .assert()
        .success();
    recrypt_cmd(&wallet_path, &config_dir)
        .args([
            "identity",
            "import",
            json_path.to_str().unwrap(),
            "--name",
            "bob-json",
        ])
        .assert()
        .success();

    // Both should now be in the wallet
    let list_out = recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "list"])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let names: Vec<&str> = list_json
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"alice-env"),
        "alice-env should be in wallet"
    );
    assert!(names.contains(&"bob-json"), "bob-json should be in wallet");
}

#[test]
fn import_ed25519_only_envelope_rejected() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/fixtures/identity/identity-ed25519-only.envelope"
    );

    if !std::path::Path::new(fixture_path).exists() {
        eprintln!("Skipping: fixture not found at {fixture_path}");
        return;
    }

    let (_tmp, wallet_path, config_dir) = setup();

    let output = recrypt_cmd(&wallet_path, &config_dir)
        .args(["identity", "import", fixture_path, "--name", "should-fail"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "importing an ed25519-only envelope into a wallet should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ml-dsa") || stderr.contains("PRE") || stderr.contains("secret"),
        "error should mention missing key material; got: {stderr}"
    );
}
