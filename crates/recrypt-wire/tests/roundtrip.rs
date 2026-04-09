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
fn test_large_file_inline_roundtrip() {
    // When ciphertext is present (local CLI mode), the envelope carries
    // everything inline. When ciphertext is empty (server mode), only
    // metadata is in the envelope.
    let encrypted = EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Lattice, 0, vec![0u8; 4096]),
        bao_hash: [0xABu8; 32],
        ciphertext: vec![0u8; 1_000_000],
        signature: None,
    };

    let envelope_bytes = encrypted.to_envelope().unwrap();
    // Envelope includes 1 MB inline ciphertext + 4 KB wrapped key
    assert!(envelope_bytes.len() > 1_000_000, "envelope should include inline ciphertext");

    let restored = EncryptedFile::from_envelope(&envelope_bytes).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
    assert_eq!(restored.ciphertext.len(), 1_000_000);
    assert_eq!(restored.wrapped_key.as_bytes().len(), 4096);
}

#[test]
fn test_metadata_only_envelope() {
    // When ciphertext is empty (server-mediated flow), the envelope
    // is metadata-only and small.
    let encrypted = EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Lattice, 0, Vec::new()),
        bao_hash: [0xABu8; 32],
        ciphertext: Vec::new(),
        signature: None,
    };

    let envelope_bytes = encrypted.to_envelope().unwrap();
    assert!(
        envelope_bytes.len() < 500,
        "metadata-only envelope should be small, got {} bytes",
        envelope_bytes.len()
    );

    let restored = EncryptedFile::from_envelope(&envelope_bytes).unwrap();
    assert_eq!(restored.bao_hash, encrypted.bao_hash);
    assert!(restored.ciphertext.is_empty());
}

#[test]
fn test_wrapped_key_roundtrip_with_data() {
    // Simulate a realistic wrapped key (PRE ciphertext with actual content)
    let wrapped_key_data = vec![0xCA; 512]; // 512 bytes of PRE ciphertext
    let encrypted = EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Mock, 0, wrapped_key_data.clone()),
        bao_hash: [0x11u8; 32],
        ciphertext: vec![0xEE; 256],
        signature: None,
    };

    let envelope_bytes = encrypted.to_envelope().unwrap();
    let restored = EncryptedFile::from_envelope(&envelope_bytes).unwrap();

    // Verify wrapped key roundtrips correctly
    assert_eq!(restored.wrapped_key.backend(), BackendId::Mock);
    assert_eq!(restored.wrapped_key.level(), 0);
    assert_eq!(restored.wrapped_key.as_bytes(), &wrapped_key_data[..],
        "wrapped key inner bytes must match");

    // Verify ciphertext roundtrips
    assert_eq!(restored.ciphertext, vec![0xEE; 256]);
    assert_eq!(restored.bao_hash, [0x11u8; 32]);
}

#[test]
fn test_empty_wrapped_key_does_not_serialize() {
    // If wrapped_key has no inner bytes but has backend+level,
    // to_bytes() still produces 2 bytes (backend, level).
    // Verify this roundtrips.
    let ct = Ciphertext::new(BackendId::Mock, 0, Vec::new());
    let bytes = ct.to_bytes();
    println!("empty ciphertext to_bytes: {:?} (len={})", bytes, bytes.len());
    assert_eq!(bytes.len(), 2); // backend byte + level byte
    let restored = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(restored.as_bytes().len(), 0);
}
