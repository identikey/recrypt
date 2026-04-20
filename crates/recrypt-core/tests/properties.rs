//! Property-based tests for cryptographic operations
//!
//! These tests validate SEMANTIC correctness, not byte-level equality.
//! Ciphertexts/keys are non-deterministic, so we test behavior.

#[cfg(feature = "proptest")]
mod proptest_suite {
    use proptest::prelude::*;
    use recrypt_core::pre::backends::MockBackend;
    use recrypt_core::*;

    proptest! {
        /// Property: decrypt(encrypt(x)) == x
        #[test]
        fn prop_encrypt_decrypt_roundtrip(data in prop::collection::vec(any::<u8>(), 1..1000)) {
            let backend = MockBackend;
            let encryptor = HybridEncryptor::new(backend);
            let kp = encryptor.backend().generate_keypair().unwrap();

            let encrypted = encryptor.encrypt(&kp.public, &data).unwrap();
            let decrypted = encryptor.decrypt(&kp.secret, &encrypted).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        /// Property: decrypt_bob(recrypt(encrypt_alice(x))) == x
        #[test]
        fn prop_recryption_preserves_plaintext(data in prop::collection::vec(any::<u8>(), 1..500)) {
            let backend = MockBackend;
            let encryptor = HybridEncryptor::new(backend);

            let alice = encryptor.backend().generate_keypair().unwrap();
            let bob = encryptor.backend().generate_keypair().unwrap();

            let encrypted_alice = encryptor.encrypt(&alice.public, &data).unwrap();
            let rk = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public).unwrap();
            let encrypted_bob = encryptor.recrypt(&rk, &encrypted_alice).unwrap();
            let decrypted = encryptor.decrypt(&bob.secret, &encrypted_bob).unwrap();

            prop_assert_eq!(decrypted, data);
        }

        /// Property: verify(sign(msg)) == true
        #[test]
        fn prop_signature_roundtrip(msg in prop::collection::vec(any::<u8>(), 1..1000)) {
            use recrypt_ffi::ed25519::ed25519_keygen;
            use recrypt_ffi::liboqs::{pq_keygen, PqAlgorithm};
            use recrypt_core::sign::*;

            let ed_kp = ed25519_keygen();
            let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

            let signing_keys = SigningKeys {
                ed25519: ed_kp.signing_key,
                ml_dsa: Some(pq_kp.secret_key.clone()),
            };

            let verifying_keys = VerifyingKeys {
                ed25519: ed_kp.verifying_key,
                ml_dsa: Some(pq_kp.public_key.clone()),
            };

            let sig = sign_message(&msg, &signing_keys).unwrap();
            let valid = verify_message(&msg, &sig, &verifying_keys, VerifyPolicy::PqRequired).unwrap();

            prop_assert!(valid);
        }
    }
}
