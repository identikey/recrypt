//! Canonical identity fixture tests.
//!
//! Run `cargo test -p recrypt-wire --test fixture_regenerate -- --ignored --nocapture`
//! to regenerate fixture files, then run without `--ignored` to verify them.

use bc_envelope::prelude::*;
use ed25519_dalek::SigningKey;
use recrypt_wire::{Identity, MlDsaKeyPair, PreKeyMaterial};
use std::fs;
use std::path::PathBuf;

fn fixtures_dir() -> PathBuf {
    // tests/fixtures/identity/ at the repo root
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
        .join("identity")
}

fn fixture_path(name: &str) -> PathBuf {
    fixtures_dir().join(name)
}

fn ed25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(seed);
    signing_key.verifying_key().to_bytes()
}

fn fingerprint_of(ed25519_public: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(ed25519_public).as_bytes()
}

// ── Fixture builders ──────────────────────────────────────────────────────────

fn build_ed25519_only() -> (Identity, Vec<u8>) {
    let seed = [0x11u8; 32];
    let ed25519_public = ed25519_public_from_seed(&seed);
    let fingerprint = fingerprint_of(&ed25519_public);
    let identity = Identity {
        fingerprint,
        ed25519_public,
        ed25519_secret: None,
        name: None,
        created: None,
        ml_dsa: None,
        pre: None,
        unknown_assertions: vec![],
    };
    let bytes = identity.to_envelope_bytes().unwrap();
    (identity, bytes)
}

fn build_hybrid_no_pre() -> (Identity, Vec<u8>) {
    // This fixture is authored manually as an external envelope to prove
    // unknown-assertion round-trip preservation, then parsed and re-emitted.
    let seed = [0x22u8; 32];
    let ed25519_public = ed25519_public_from_seed(&seed);
    let ed25519_secret = SigningKey::from_bytes(&seed).to_bytes();
    let fingerprint = fingerprint_of(&ed25519_public);

    // Build as external envelope (Dreamball's shape) with unknown assertion.
    let mut subject = Map::new();
    subject.insert("type", "recrypt.identity");
    subject.insert("format-version", 1_u32);
    subject.insert("fingerprint", ByteString::from(fingerprint.to_vec()));

    let created_cbor = CBOR::to_tagged_value(Tag::with_value(1), 1713652800u64);

    let envelope = Envelope::new(CBOR::from(subject))
        .add_assertion("created", created_cbor)
        .add_assertion("ed25519-public", ByteString::from(ed25519_public.to_vec()))
        .add_assertion("ed25519-secret", ByteString::from(ed25519_secret.to_vec()))
        .add_assertion(
            "ml-dsa-public",
            ByteString::from(vec![0xAAu8; 2592]),
        )
        .add_assertion(
            "ml-dsa-secret",
            ByteString::from(vec![0xBBu8; 4896]),
        )
        .add_assertion("name", "dreamball-owner")
        .add_assertion(
            "dreamball-lineage",
            ByteString::from(vec![0xDEu8, 0xAD, 0xBE, 0xEF]),
        );

    let original_bytes = envelope.to_cbor_data();

    // Parse via from_envelope_bytes (must preserve unknown assertion).
    let parsed = Identity::from_envelope_bytes(&original_bytes).unwrap();

    // Re-emit — byte-equal to original.
    let re_emitted = parsed.to_envelope_bytes().unwrap();

    (parsed, re_emitted)
}

fn build_full() -> (Identity, Vec<u8>) {
    let seed = [0x33u8; 32];
    let ed25519_public = ed25519_public_from_seed(&seed);
    let ed25519_secret = SigningKey::from_bytes(&seed).to_bytes();
    let fingerprint = fingerprint_of(&ed25519_public);
    let identity = Identity {
        fingerprint,
        ed25519_public,
        ed25519_secret: Some(ed25519_secret),
        name: Some("alice".to_string()),
        created: Some(1713652800),
        ml_dsa: Some(MlDsaKeyPair {
            public: vec![0xAAu8; 2592],
            secret: Some(vec![0xBBu8; 4896]),
        }),
        pre: Some(PreKeyMaterial {
            backend: "lattice-bfv".to_string(),
            public: vec![0xCCu8; 64],
            secret: Some(vec![0xDDu8; 64]),
        }),
        unknown_assertions: vec![],
    };
    let bytes = identity.to_envelope_bytes().unwrap();
    (identity, bytes)
}

// ── Regenerate (ignored) ──────────────────────────────────────────────────────

#[test]
#[ignore]
fn regenerate_fixtures() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).unwrap();

    let (id1, bytes1) = build_ed25519_only();
    let fp1 = hex::encode(id1.fingerprint);
    fs::write(fixture_path("identity-ed25519-only.envelope"), &bytes1).unwrap();
    let meta1 = serde_json::json!({
        "description": "Minimal identity: ed25519 public key only. No name, no created, no secrets, no ml-dsa, no PRE.",
        "fingerprint_hex": fp1,
        "byte_length": bytes1.len(),
        "assertions_present": ["ed25519-public"],
        "assertions_absent": ["ed25519-secret", "name", "created", "ml-dsa-public", "ml-dsa-secret", "pre-backend", "pre-public", "pre-secret"]
    });
    fs::write(
        fixture_path("identity-ed25519-only.json"),
        serde_json::to_string_pretty(&meta1).unwrap(),
    )
    .unwrap();
    println!(
        "identity-ed25519-only.envelope: {} bytes, fingerprint={}",
        bytes1.len(),
        fp1
    );

    let (id2, bytes2) = build_hybrid_no_pre();
    let fp2 = hex::encode(id2.fingerprint);
    fs::write(fixture_path("identity-hybrid-no-pre.envelope"), &bytes2).unwrap();
    let meta2 = serde_json::json!({
        "description": "Dreamball-shaped identity: ed25519+ml-dsa keypairs, name, created, NO PRE. Contains unknown assertion 'dreamball-lineage' (ByteString [0xDE,0xAD,0xBE,0xEF]). Proves round-trip preservation of externally-authored assertions.",
        "fingerprint_hex": fp2,
        "byte_length": bytes2.len(),
        "assertions_present": ["ed25519-public", "ed25519-secret", "ml-dsa-public", "ml-dsa-secret", "name", "created", "dreamball-lineage"],
        "assertions_absent": ["pre-backend", "pre-public", "pre-secret"]
    });
    fs::write(
        fixture_path("identity-hybrid-no-pre.json"),
        serde_json::to_string_pretty(&meta2).unwrap(),
    )
    .unwrap();
    println!(
        "identity-hybrid-no-pre.envelope: {} bytes, fingerprint={}",
        bytes2.len(),
        fp2
    );

    let (id3, bytes3) = build_full();
    let fp3 = hex::encode(id3.fingerprint);
    fs::write(fixture_path("identity-full.envelope"), &bytes3).unwrap();
    let meta3 = serde_json::json!({
        "description": "Full recrypt identity: ed25519+ml-dsa keypairs, name='alice', created, PRE backend='lattice-bfv' with placeholder key bytes.",
        "fingerprint_hex": fp3,
        "byte_length": bytes3.len(),
        "assertions_present": ["ed25519-public", "ed25519-secret", "ml-dsa-public", "ml-dsa-secret", "name", "created", "pre-backend", "pre-public", "pre-secret"],
        "assertions_absent": []
    });
    fs::write(
        fixture_path("identity-full.json"),
        serde_json::to_string_pretty(&meta3).unwrap(),
    )
    .unwrap();
    println!(
        "identity-full.envelope: {} bytes, fingerprint={}",
        bytes3.len(),
        fp3
    );
}

// ── Verification tests (non-ignored) ─────────────────────────────────────────

fn load_metadata(name: &str) -> serde_json::Value {
    let path = fixture_path(&format!("{name}.json"));
    let data = fs::read(&path).unwrap_or_else(|e| panic!("missing metadata {path:?}: {e}"));
    serde_json::from_slice(&data).unwrap()
}

fn load_envelope_bytes(name: &str) -> Vec<u8> {
    let path = fixture_path(&format!("{name}.envelope"));
    fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {path:?}: {e}\n\nRun: cargo test -p recrypt-wire --test fixture_regenerate -- --ignored --nocapture"))
}

#[test]
fn verify_ed25519_only_fixture() {
    let raw = load_envelope_bytes("identity-ed25519-only");
    let meta = load_metadata("identity-ed25519-only");

    let expected_fp = meta["fingerprint_hex"].as_str().unwrap();
    let expected_len = meta["byte_length"].as_u64().unwrap() as usize;

    assert_eq!(raw.len(), expected_len, "byte_length mismatch");

    let parsed = Identity::from_envelope_bytes(&raw).expect("parse failed");
    let actual_fp = hex::encode(parsed.fingerprint);
    assert_eq!(actual_fp, expected_fp, "fingerprint mismatch");

    let re_emitted = parsed.to_envelope_bytes().unwrap();
    assert_eq!(raw, re_emitted, "round-trip must be byte-identical");

    assert_eq!(parsed.ed25519_secret, None);
    assert_eq!(parsed.name, None);
    assert_eq!(parsed.created, None);
    assert!(parsed.ml_dsa.is_none());
    assert!(parsed.pre.is_none());
    assert!(parsed.unknown_assertions.is_empty());
}

#[test]
fn verify_hybrid_no_pre_fixture() {
    let raw = load_envelope_bytes("identity-hybrid-no-pre");
    let meta = load_metadata("identity-hybrid-no-pre");

    let expected_fp = meta["fingerprint_hex"].as_str().unwrap();
    let expected_len = meta["byte_length"].as_u64().unwrap() as usize;

    assert_eq!(raw.len(), expected_len, "byte_length mismatch");

    let parsed = Identity::from_envelope_bytes(&raw).expect("parse failed");
    let actual_fp = hex::encode(parsed.fingerprint);
    assert_eq!(actual_fp, expected_fp, "fingerprint mismatch");

    // Must have preserved the unknown "dreamball-lineage" assertion.
    assert_eq!(
        parsed.unknown_assertions.len(),
        1,
        "expected exactly 1 unknown assertion"
    );
    let (pred, _obj) = &parsed.unknown_assertions[0];
    let pred_leaf = pred.try_leaf().unwrap();
    let pred_str: String = pred_leaf.try_into().unwrap();
    assert_eq!(
        pred_str, "dreamball-lineage",
        "unknown assertion predicate must be 'dreamball-lineage'"
    );

    let re_emitted = parsed.to_envelope_bytes().unwrap();
    assert_eq!(raw, re_emitted, "round-trip must be byte-identical");

    assert!(parsed.pre.is_none());
    assert_eq!(parsed.name.as_deref(), Some("dreamball-owner"));
    assert_eq!(parsed.created, Some(1713652800));
}

#[test]
fn verify_full_fixture() {
    let raw = load_envelope_bytes("identity-full");
    let meta = load_metadata("identity-full");

    let expected_fp = meta["fingerprint_hex"].as_str().unwrap();
    let expected_len = meta["byte_length"].as_u64().unwrap() as usize;

    assert_eq!(raw.len(), expected_len, "byte_length mismatch");

    let parsed = Identity::from_envelope_bytes(&raw).expect("parse failed");
    let actual_fp = hex::encode(parsed.fingerprint);
    assert_eq!(actual_fp, expected_fp, "fingerprint mismatch");

    let re_emitted = parsed.to_envelope_bytes().unwrap();
    assert_eq!(raw, re_emitted, "round-trip must be byte-identical");

    assert!(parsed.pre.is_some());
    let pre = parsed.pre.as_ref().unwrap();
    assert_eq!(pre.backend, "lattice-bfv");
    assert_eq!(parsed.name.as_deref(), Some("alice"));
    assert_eq!(parsed.created, Some(1713652800));
    assert!(parsed.unknown_assertions.is_empty());
}
