//! Roundtrip tests for all serialization formats

use recrypt_core::PreBackend;
use recrypt_core::hybrid::HybridEncryptor;
use recrypt_core::pre::backends::mock::MockBackend;
use recrypt_proto::format::MultiFormat;

#[test]
fn test_protobuf_roundtrip() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Hello, Recrypt Protocol Layer!";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

    // Serialize to protobuf
    let proto_bytes = encrypted.to_protobuf().unwrap();
    assert!(!proto_bytes.is_empty());

    // Deserialize
    let restored = recrypt_core::hybrid::EncryptedFile::from_protobuf(&proto_bytes).unwrap();

    // Decrypt
    let decrypted = encryptor.decrypt(&kp.secret, &restored).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_json_roundtrip() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"JSON serialization test";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

    // Serialize to JSON
    let json_str = encrypted.to_json().unwrap();
    assert!(json_str.contains("\"version\": 3"));
    assert!(json_str.contains("\"bao_hash\""));

    // Deserialize
    let restored = recrypt_core::hybrid::EncryptedFile::from_json(&json_str).unwrap();

    // Decrypt
    let decrypted = encryptor.decrypt(&kp.secret, &restored).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_armor_roundtrip() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Armor test";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

    // Serialize to armor
    let armored = encrypted
        .to_armor(recrypt_proto::armor::ArmorType::EncryptedFile)
        .unwrap();
    assert!(armored.contains("----- BEGIN RECRYPT ENCRYPTED FILE -----"));
    assert!(armored.contains("----- END RECRYPT ENCRYPTED FILE -----"));

    // Deserialize
    let restored = recrypt_core::hybrid::EncryptedFile::from_armor(&armored).unwrap();

    // Decrypt
    let decrypted = encryptor.decrypt(&kp.secret, &restored).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_format_detection() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let plaintext = b"Format detection test";
    let encrypted = encryptor.encrypt(&kp.public, plaintext).unwrap();

    // Test each format
    let proto_bytes = encrypted.to_protobuf().unwrap();
    let json_bytes = encrypted.to_json().unwrap();
    let armor_bytes = encrypted
        .to_armor(recrypt_proto::armor::ArmorType::EncryptedFile)
        .unwrap();

    // Auto-detect and parse
    let from_proto = recrypt_core::hybrid::EncryptedFile::from_any(&proto_bytes).unwrap();
    let from_json = recrypt_core::hybrid::EncryptedFile::from_any(json_bytes.as_bytes()).unwrap();
    let from_armor = recrypt_core::hybrid::EncryptedFile::from_any(armor_bytes.as_bytes()).unwrap();

    // All should decrypt successfully
    assert_eq!(
        encryptor.decrypt(&kp.secret, &from_proto).unwrap(),
        plaintext
    );
    assert_eq!(
        encryptor.decrypt(&kp.secret, &from_json).unwrap(),
        plaintext
    );
    assert_eq!(
        encryptor.decrypt(&kp.secret, &from_armor).unwrap(),
        plaintext
    );
}

#[test]
fn test_large_file_roundtrip() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    // 1 MB plaintext
    let plaintext = vec![42u8; 1024 * 1024];
    let encrypted = encryptor.encrypt(&kp.public, &plaintext).unwrap();

    // Protobuf roundtrip
    let proto_bytes = encrypted.to_protobuf().unwrap();
    let restored = recrypt_core::hybrid::EncryptedFile::from_protobuf(&proto_bytes).unwrap();
    let decrypted = encryptor.decrypt(&kp.secret, &restored).unwrap();

    assert_eq!(decrypted, plaintext);
}
