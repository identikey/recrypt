//! Integration tests: auth + storage working together

use identikey_storage_auth::{
    AccessGrant, Capability, InMemoryOwnershipStore, Operation, OwnershipStore,
    PublicKeyFingerprint,
};
use recrypt_core::sign::{SigningKeys, VerifyingKeys};
use recrypt_ffi::ed25519::ed25519_keygen;
use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};
use recrypt_storage::{BlobStorage, InMemoryProviderIndex, InMemoryStorage, ProviderIndex};

fn test_keys() -> (SigningKeys, VerifyingKeys, PublicKeyFingerprint) {
    let ed_kp = ed25519_keygen();
    let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

    // Create fingerprint from combined key material
    let mut key_bytes = ed_kp.verifying_key.to_bytes().to_vec();
    key_bytes.extend(&pq_kp.public_key);
    let fingerprint = PublicKeyFingerprint::from_public_key(&key_bytes);

    let signing = SigningKeys {
        ed25519: ed_kp.signing_key,
        ml_dsa: pq_kp.secret_key,
    };

    let verifying = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: pq_kp.public_key,
    };

    (signing, verifying, fingerprint)
}

#[tokio::test]
async fn test_full_upload_flow() {
    // Setup
    let storage = InMemoryStorage::new();
    let ownership = InMemoryOwnershipStore::new();
    let providers = InMemoryProviderIndex::new();

    let (_signing_keys, _verifying_keys, owner_fp) = test_keys();

    // 1. Upload encrypted file
    let _plaintext = b"Secret document content";
    let ciphertext = b"encrypted-bytes-here"; // Simulated
    let file_hash = blake3::hash(ciphertext);

    storage.put(&file_hash, ciphertext).await.unwrap();

    // 2. Register ownership
    ownership.register(&owner_fp, &file_hash).await.unwrap();

    // 3. Register provider location
    let provider_url = "https://minio.local:9000/recrypt/blob/b3/".to_string();
    providers.register(&file_hash, &provider_url).await.unwrap();

    // Verify
    assert!(ownership.is_owner(&owner_fp, &file_hash).await.unwrap());
    let locations = providers.lookup(&file_hash).await.unwrap();
    assert_eq!(locations.len(), 1);
}

#[tokio::test]
async fn test_share_flow() {
    let ownership = InMemoryOwnershipStore::new();

    let (alice_signing, alice_verifying, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let file_hash = blake3::hash(b"alice's secret");

    // Alice uploads and registers
    ownership.register(&alice_fp, &file_hash).await.unwrap();

    // Alice grants Bob read access
    let grant = AccessGrant::new(file_hash, alice_fp, bob_fp, vec![Operation::Read], None);
    ownership.grant_access(grant).await.unwrap();

    // Bob can read but not write
    assert!(
        ownership
            .has_access(&bob_fp, &file_hash, Operation::Read)
            .await
            .unwrap()
    );
    assert!(
        !ownership
            .has_access(&bob_fp, &file_hash, Operation::Write)
            .await
            .unwrap()
    );

    // Alice issues signed capability for Bob
    let cap = Capability::new_signed(
        file_hash,
        bob_fp,
        vec![Operation::Read],
        None,
        alice_fp,
        &alice_signing,
    )
    .unwrap();

    // Bob can verify the capability
    cap.verify(&alice_verifying, Operation::Read).unwrap();
}

#[tokio::test]
async fn test_revoke_flow() {
    let ownership = InMemoryOwnershipStore::new();

    let (_, _, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let file_hash = blake3::hash(b"secret");

    ownership.register(&alice_fp, &file_hash).await.unwrap();

    // Grant then revoke
    let grant = AccessGrant::new(file_hash, alice_fp, bob_fp, vec![Operation::Read], None);
    ownership.grant_access(grant).await.unwrap();

    assert!(
        ownership
            .has_access(&bob_fp, &file_hash, Operation::Read)
            .await
            .unwrap()
    );

    ownership
        .revoke_access(&alice_fp, &bob_fp, &file_hash)
        .await
        .unwrap();

    assert!(
        !ownership
            .has_access(&bob_fp, &file_hash, Operation::Read)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_capability_expiry() {
    let (signing_keys, verifying_keys, issuer_fp) = test_keys();
    let (_, _, grantee_fp) = test_keys();

    let file_hash = blake3::hash(b"test");

    // Create expired capability
    let cap = Capability::new_signed(
        file_hash,
        grantee_fp,
        vec![Operation::Read],
        Some(1), // Expired timestamp
        issuer_fp,
        &signing_keys,
    )
    .unwrap();

    // Signature is valid but capability is expired
    assert!(cap.verify_signature(&verifying_keys).is_ok());
    assert!(cap.is_expired());
    assert!(cap.verify(&verifying_keys, Operation::Read).is_err());
}
