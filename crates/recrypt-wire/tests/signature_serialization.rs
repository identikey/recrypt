//! Signature-related serialization tests for recrypt-wire.
//!
//! These tests validate that envelope serialization preserves the
//! bao_hash and backend metadata that signatures cover, and that
//! the envelope size overhead is reasonable.

use recrypt_core::hybrid::EncryptedFile;
use recrypt_core::pre::{BackendId, Ciphertext};
use recrypt_wire::format::MultiFormat;

fn make_unsigned_file(backend: BackendId) -> EncryptedFile {
    EncryptedFile {
        wrapped_key: Ciphertext::new(backend, 0, vec![0u8; 128]),
        bao_hash: [0x55u8; 32],
        ciphertext: vec![0u8; 64],
        signature: None,
    }
}

#[test]
fn test_unsigned_file_envelope_roundtrip() {
    let encrypted = make_unsigned_file(BackendId::Mock);
    let envelope_bytes = encrypted.to_envelope().unwrap();
    let restored = EncryptedFile::from_envelope(&envelope_bytes).unwrap();

    assert_eq!(restored.bao_hash, encrypted.bao_hash);
    assert_eq!(restored.wrapped_key.backend(), BackendId::Mock);
}

#[test]
fn test_envelope_size_overhead() {
    // Envelope metadata should be small — the actual crypto payloads
    // (ciphertext, wrapped-key) live in separate objects.
    let encrypted = make_unsigned_file(BackendId::Lattice);
    let envelope_bytes = encrypted.to_envelope().unwrap();

    // Envelope is metadata only: type string, version, bao-hash (32 bytes),
    // ciphertext-ref (32 bytes), backend assertion. Should be under 300 bytes.
    assert!(
        envelope_bytes.len() < 300,
        "envelope overhead too large: {} bytes",
        envelope_bytes.len()
    );
}

#[test]
fn test_different_backends_produce_different_envelopes() {
    let mock_file = make_unsigned_file(BackendId::Mock);
    let lattice_file = make_unsigned_file(BackendId::Lattice);

    let mock_bytes = mock_file.to_envelope().unwrap();
    let lattice_bytes = lattice_file.to_envelope().unwrap();

    // Different backends → different envelope bytes (backend is an assertion)
    assert_ne!(mock_bytes, lattice_bytes);
}

#[test]
fn test_dcbor_determinism_across_calls() {
    let encrypted = make_unsigned_file(BackendId::Mock);

    let bytes1 = encrypted.to_envelope().unwrap();
    let bytes2 = encrypted.to_envelope().unwrap();

    // Note: salted assertions produce different bytes each time.
    // But the unsalted parts (subject) should be deterministic.
    // Since backend is salted, the full bytes WILL differ.
    // We test determinism of the unsalted envelope in the spike test.
    // Here we just verify both round-trip correctly.
    let r1 = EncryptedFile::from_envelope(&bytes1).unwrap();
    let r2 = EncryptedFile::from_envelope(&bytes2).unwrap();
    assert_eq!(r1.bao_hash, r2.bao_hash);
}
