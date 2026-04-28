//! Crypto-correctness tests against the real OpenFHE BFV (lattice) backend.
//!
//! The default e2e suite uses MockBackend so tests run in seconds — that
//! catches plumbing regressions but does not exercise the actual
//! post-quantum recryption math. These tests do.
//!
//! Gated behind the `lattice-tests` cargo feature; OpenFHE global state
//! still requires `--test-threads=1`:
//!
//!   cargo test -p recrypt-e2e-tests --features lattice-tests -- --test-threads=1
//!
//! Or via just:
//!
//!   just test-e2e-lattice-rust

#![cfg(feature = "lattice-tests")]

use base64::Engine as _;
use recrypt_core::pre::backends::LatticeBackend;
use recrypt_core::pre::{BackendId, PreBackend as _};
use recrypt_core::{EncryptedFile, HybridEncryptor};
use recrypt_e2e_tests::api::TestIdentity;
use recrypt_e2e_tests::harness::TestHarness;
use recrypt_wire::MultiFormat;
use std::fs;

// ── API: full recryption math round-trip ─────────────────────────────────────

/// Alice → Bob recryption, verifying Bob can decrypt the recrypted wrapped key
/// using his real lattice secret key. Mirrors `test_full_recryption_roundtrip`
/// from api_share_tests.rs but with the real PRE backend.
#[tokio::test]
async fn test_full_recryption_roundtrip_lattice() {
    let harness = TestHarness::with_backend(BackendId::Lattice).await;
    let api = harness.api();
    let backend = LatticeBackend::new().expect("lattice backend init");
    let encryptor = HybridEncryptor::new(LatticeBackend::new().expect("lattice backend init"));

    let alice = TestIdentity::new(&backend);
    let bob = TestIdentity::new(&backend);

    let resp = api.register(&alice).await;
    assert_eq!(resp.status(), 201, "alice register failed");
    let resp = api.register(&bob).await;
    assert_eq!(resp.status(), 201, "bob register failed");

    let plaintext = b"lattice recryption roundtrip plaintext";
    let encrypted: EncryptedFile = encryptor.encrypt(&alice.pre_kp.public, plaintext).unwrap();
    let wrapped_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(encrypted.wrapped_key.to_bytes());
    let file_bytes = encrypted.to_envelope().unwrap();
    let file_hash = bs58::encode(blake3::hash(&file_bytes).as_bytes()).into_string();

    let upload = api.upload_file(&alice, &file_bytes).await;
    assert_eq!(upload.status(), 201, "upload failed");

    let recrypt_key = backend
        .generate_recrypt_key(&alice.pre_kp.secret, &bob.pre_kp.public)
        .expect("generate_recrypt_key");
    let recrypt_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(recrypt_key.to_bytes());

    let resp = api
        .create_share(&alice, &bob, &file_hash, &recrypt_key_b64, &wrapped_key_b64)
        .await;
    assert_eq!(
        resp.status(),
        201,
        "create_share failed: {:?}",
        resp.text().await
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    let share_id = body["share_id"].as_str().unwrap().to_string();

    // Bob fetches the recrypted share and decrypts the wrapped key with his real secret.
    let resp = api.get_share(&bob, &share_id).await;
    assert_eq!(resp.status(), 200, "get_share failed");
    let body: serde_json::Value = resp.json().await.unwrap();

    let recrypted_b64 = body["wrapped_key_for_recipient"]
        .as_str()
        .expect("wrapped_key_for_recipient must be present");
    let recrypted_bytes = base64::engine::general_purpose::STANDARD
        .decode(recrypted_b64)
        .expect("recrypted wrapped_key must be valid base64");
    let recrypted_ct = recrypt_core::pre::Ciphertext::from_bytes(&recrypted_bytes)
        .expect("recrypted wrapped_key must parse as Ciphertext");

    let recovered = backend
        .decrypt(&bob.pre_kp.secret, &recrypted_ct)
        .expect("Bob must decrypt the recrypted wrapped key with his lattice secret");

    // The recovered bytes must deserialize as a valid KeyMaterial — which means
    // the lattice round-trip preserved every byte (in particular byte[0] = 1,
    // the KeyMaterial version tag).
    recrypt_core::KeyMaterial::from_bytes(&recovered)
        .expect("recovered bytes must round-trip as KeyMaterial — version byte must equal 1");
}

// ── CLI: encrypt/decrypt round-trips with real lattice keys ───────────────────

#[tokio::test]
async fn test_encrypt_decrypt_roundtrip_lattice() {
    let harness = TestHarness::with_backend(BackendId::Lattice).await;
    let cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;

    let input_path = harness.tmp().join("input.txt");
    let enc_path = harness.tmp().join("input.enc");
    let dec_path = harness.tmp().join("decrypted.txt");

    fs::write(&input_path, b"Hello, lattice recrypt!").unwrap();

    cli.run_ok(&[
        "encrypt",
        input_path.to_str().unwrap(),
        "--for",
        "alice",
        "--output",
        enc_path.to_str().unwrap(),
    ])
    .await;

    cli.run_ok(&[
        "decrypt",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ])
    .await;

    let decrypted = fs::read(&dec_path).unwrap();
    assert_eq!(decrypted, b"Hello, lattice recrypt!");
}

#[tokio::test]
async fn test_encrypt_empty_file_lattice() {
    let harness = TestHarness::with_backend(BackendId::Lattice).await;
    let cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;

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
    ])
    .await;

    cli.run_ok(&[
        "decrypt",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ])
    .await;

    let decrypted = fs::read(&dec_path).unwrap();
    assert!(decrypted.is_empty(), "decrypted empty file should be empty");
}

#[tokio::test]
async fn test_encrypt_large_file_lattice() {
    let harness = TestHarness::with_backend(BackendId::Lattice).await;
    let cli = harness.cli();

    cli.run_ok(&["identity", "new", "--name", "alice"]).await;

    // 1 MB — large enough to verify chunking, small enough that the lattice
    // KEM step (which dominates) doesn't make the test prohibitively slow.
    let pattern = b"LATTICE_LARGE_PATTERN_0123456789ABCDEF";
    let size = 1024 * 1024;
    let data: Vec<u8> = pattern.iter().cloned().cycle().take(size).collect();

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
    ])
    .await;

    cli.run_ok(&[
        "decrypt",
        enc_path.to_str().unwrap(),
        "--output",
        dec_path.to_str().unwrap(),
    ])
    .await;

    let decrypted = fs::read(&dec_path).unwrap();
    assert_eq!(decrypted.len(), size);
    assert_eq!(decrypted, data);
}
