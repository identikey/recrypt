//! Signature integration tests

use recrypt_core::PreBackend;
use recrypt_core::hybrid::HybridEncryptor;
use recrypt_core::pre::backends::mock::MockBackend;
use recrypt_core::sign::{SigningKeys, VerifyPolicy, VerifyingKeys};
use recrypt_ffi::ed25519::ed25519_keygen;
use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

fn hybrid_keys() -> (SigningKeys, VerifyingKeys) {
    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
    (
        SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: Some(pq_kp.secret_key.clone()),
        },
        VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: Some(pq_kp.public_key),
        },
    )
}

fn classical_keys() -> (SigningKeys, VerifyingKeys) {
    let ed_kp = ed25519_keygen();
    (
        SigningKeys {
            ed25519: ed_kp.signing_key,
            ml_dsa: None,
        },
        VerifyingKeys {
            ed25519: ed_kp.verifying_key,
            ml_dsa: None,
        },
    )
}

#[test]
fn test_sign_and_verify() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let (signing_keys, verifying_keys) = hybrid_keys();

    // Encrypt and sign
    let plaintext = b"Signed message test";
    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Verify signature is present
    assert!(encrypted.signature.is_some());

    // Decrypt with PqRequired — hybrid sig satisfies it.
    let decrypted = encryptor
        .decrypt_and_verify(
            &kp.secret,
            &encrypted,
            &verifying_keys,
            VerifyPolicy::PqRequired,
        )
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_tampered_wrapped_key_detected() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let (signing_keys, verifying_keys) = hybrid_keys();

    let plaintext = b"Integrity test";
    let mut encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Tamper with wrapped_key (part of signature payload)
    let tampered_bytes = vec![0u8; encrypted.wrapped_key.as_bytes().len()];
    encrypted.wrapped_key = recrypt_core::pre::Ciphertext::new(
        encrypted.wrapped_key.backend(),
        encrypted.wrapped_key.level(),
        tampered_bytes,
    );

    // Signature verification should fail
    let result = encryptor.decrypt_and_verify(
        &kp.secret,
        &encrypted,
        &verifying_keys,
        VerifyPolicy::PqOptional,
    );
    assert!(result.is_err());
}

#[test]
fn test_tampered_bao_hash_detected() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let (signing_keys, verifying_keys) = hybrid_keys();

    let plaintext = b"Hash tampering test";
    let mut encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Tamper with bao_hash (part of signature payload)
    encrypted.bao_hash = [0u8; 32];

    // Signature verification should fail
    let result = encryptor.decrypt_and_verify(
        &kp.secret,
        &encrypted,
        &verifying_keys,
        VerifyPolicy::PqOptional,
    );
    assert!(result.is_err());
}

#[test]
fn test_wrong_verifying_key() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let (signing_keys, _) = hybrid_keys();
    // Different verifying key
    let (_, wrong_verifying_keys) = hybrid_keys();

    let plaintext = b"Wrong key test";
    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Verification should fail with wrong key
    let result = encryptor.decrypt_and_verify(
        &kp.secret,
        &encrypted,
        &wrong_verifying_keys,
        VerifyPolicy::PqOptional,
    );
    assert!(result.is_err());
}

#[test]
fn classical_only_sign_and_verify_roundtrip() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let (signing_keys, verifying_keys) = classical_keys();

    let plaintext = b"classical-only file";
    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, plaintext, &signing_keys)
        .unwrap();

    // Sig is present but ML-DSA component is absent.
    let sig = encrypted
        .signature
        .as_ref()
        .expect("signature should be present");
    assert!(sig.ml_dsa_sig.is_none());

    // PqOptional accepts the ED25519-only signature.
    let decrypted = encryptor
        .decrypt_and_verify(
            &kp.secret,
            &encrypted,
            &verifying_keys,
            VerifyPolicy::PqOptional,
        )
        .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn classical_only_rejected_when_policy_requires_pq() {
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();

    let (signing_keys, verifying_keys) = classical_keys();

    let encrypted = encryptor
        .encrypt_and_sign(&kp.public, b"payload", &signing_keys)
        .unwrap();

    let result = encryptor.decrypt_and_verify(
        &kp.secret,
        &encrypted,
        &verifying_keys,
        VerifyPolicy::PqRequired,
    );
    assert!(result.is_err(), "PqRequired must reject classical-only sig");
}
