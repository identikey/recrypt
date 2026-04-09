//! Round-trip tests for recrypt-wire Gordian Envelope serialization.

use recrypt_core::hybrid::EncryptedFile;
use recrypt_core::pre::{BackendId, Ciphertext};
use recrypt_wire::format::{Format, MultiFormat, detect_format};

fn make_test_file() -> EncryptedFile {
    EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Mock, 0, vec![1, 2, 3, 4]),
        bao_hash: [42u8; 32],
        ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
        signature: None,
    }
}

#[test]
fn test_envelope_roundtrip() {
    let encrypted = make_test_file();
    let envelope_bytes = encrypted.to_envelope().unwrap();
    assert!(!envelope_bytes.is_empty());

    let restored = EncryptedFile::from_envelope(&envelope_bytes).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
    assert_eq!(restored.wrapped_key.backend(), encrypted.wrapped_key.backend());
}

#[test]
fn test_armor_roundtrip() {
    let encrypted = make_test_file();
    let armored = encrypted.to_armor().unwrap();

    assert!(armored.contains("----- BEGIN RECRYPT ENCRYPTED FILE -----"));
    assert!(armored.contains("----- END RECRYPT ENCRYPTED FILE -----"));
    assert!(armored.contains("Format: envelope+cbor"));

    let restored = EncryptedFile::from_armor(&armored).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
}

#[test]
fn test_format_detection() {
    let encrypted = make_test_file();
    let envelope_bytes = encrypted.to_envelope().unwrap();
    assert_eq!(detect_format(&envelope_bytes), Format::Envelope);

    let armored = encrypted.to_armor().unwrap();
    assert_eq!(detect_format(armored.as_bytes()), Format::Armor);
}

#[test]
fn test_from_any_envelope() {
    let encrypted = make_test_file();
    let envelope_bytes = encrypted.to_envelope().unwrap();
    let restored = EncryptedFile::from_any(&envelope_bytes).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
}

#[test]
fn test_from_any_armor() {
    let encrypted = make_test_file();
    let armored = encrypted.to_armor().unwrap();
    let restored = EncryptedFile::from_any(armored.as_bytes()).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
}

#[test]
fn test_large_file_metadata_only() {
    // Ciphertext is NOT in the envelope (it's a sidecar S3 object).
    // The envelope carries only metadata (bao-hash, backend, etc.).
    let encrypted = EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Lattice, 0, vec![0u8; 4096]),
        bao_hash: [0xABu8; 32],
        ciphertext: vec![0u8; 1_000_000],
        signature: None,
    };

    let envelope_bytes = encrypted.to_envelope().unwrap();
    assert!(
        envelope_bytes.len() < 1000,
        "envelope should be metadata-only, got {} bytes",
        envelope_bytes.len()
    );

    let restored = EncryptedFile::from_envelope(&envelope_bytes).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
}
