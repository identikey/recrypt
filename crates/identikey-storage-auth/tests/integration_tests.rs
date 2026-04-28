//! Integration tests: auth + storage working together

use std::collections::BTreeSet;

use identikey_storage_auth::{
    AccessGrant, Capability, DecryptionPolicy, GrantStore, InMemoryGrantStore,
    InMemoryKeyspaceStore, InMemoryOwnershipStore, KeyspaceDoc, KeyspaceId, KeyspaceStore, Member,
    OwnershipStore, Permission, PublicKeyFingerprint, RotationMode, SubjectKind,
};
use recrypt_core::sign::{SigningKeys, VerifyPolicy, VerifyingKeys};
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
        ml_dsa: Some(pq_kp.secret_key),
    };

    let verifying = VerifyingKeys {
        ed25519: ed_kp.verifying_key,
        ml_dsa: Some(pq_kp.public_key),
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
    let grant_store = InMemoryGrantStore::new();

    let (alice_signing, alice_verifying, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let keyspace_id = [42u8; 32];

    // Alice grants Bob read access via keyspace grant
    let grant = AccessGrant::new(
        keyspace_id,
        0,
        bob_fp,
        alice_fp,
        BTreeSet::from([Permission::Read]),
        None,
    );
    let grant_id = grant_store.issue(grant).await.unwrap();

    // Verify grant was stored
    let retrieved = grant_store.get(&grant_id).await.unwrap().unwrap();
    assert!(retrieved.permits(Permission::Read));
    assert!(!retrieved.permits(Permission::Write));

    // Alice issues signed capability for Bob (envelope-native; CBOR bytes)
    let cap = Capability::new(
        keyspace_id,
        SubjectKind::Keyspace,
        bob_fp,
        alice_fp,
        BTreeSet::from([Permission::Read]),
        None,
    );
    let bytes = cap.sign(&alice_signing).unwrap();

    // Bob (or anyone) can verify the capability bytes
    let parsed =
        Capability::verify_full(&bytes, &alice_verifying, VerifyPolicy::PqRequired, Permission::Read)
            .unwrap();
    assert_eq!(parsed.subject, keyspace_id);
    assert_eq!(parsed.subject_kind, SubjectKind::Keyspace);
}

#[tokio::test]
async fn test_revoke_flow() {
    let grant_store = InMemoryGrantStore::new();

    let (_, _, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let keyspace_id = [42u8; 32];

    // Issue then revoke a grant
    let grant = AccessGrant::new(
        keyspace_id,
        0,
        bob_fp,
        alice_fp,
        BTreeSet::from([Permission::Read]),
        None,
    );
    let grant_id = grant_store.issue(grant).await.unwrap();

    // Grant exists
    assert!(grant_store.get(&grant_id).await.unwrap().is_some());

    // Revoke
    grant_store.revoke(&grant_id).await.unwrap();

    // Grant is gone
    assert!(grant_store.get(&grant_id).await.unwrap().is_none());

    // Idempotent revoke
    grant_store.revoke(&grant_id).await.unwrap();
}

#[tokio::test]
async fn test_keyspace_grant_capability_end_to_end() {
    // Exercise the keyspace → grant → capability path end-to-end against
    // the in-memory stores: create a keyspace naming Alice as a Delegate
    // member, issue a grant to Bob, and verify a matching signed
    // capability is accepted for that keyspace.
    let keyspaces = InMemoryKeyspaceStore::new();
    let grants = InMemoryGrantStore::new();

    let (alice_signing, alice_verifying, alice_fp) = test_keys();
    let (_, _, bob_fp) = test_keys();

    let id = KeyspaceId::random();
    let alice_member = Member {
        fingerprint: alice_fp,
        permissions: BTreeSet::from([
            Permission::Read,
            Permission::Delegate,
            Permission::SignRotation,
        ]),
        decryption_policy: DecryptionPolicy::Standalone,
        added_at: 0,
        added_by: alice_fp,
    };

    let doc = KeyspaceDoc {
        id,
        version: 0,
        parent: None,
        mode: RotationMode::Create,
        name: "e2e-test".to_string(),
        root_pk: vec![],
        epoch_pre_pk: [0u8; 32],
        epoch: 0,
        members: vec![alice_member],
        quorum: 1,
        signatures: vec![],
        created_at: 0,
    };

    keyspaces.put(doc.clone()).await.unwrap();

    let grant = AccessGrant::new(
        *id.as_bytes(),
        0,
        bob_fp,
        alice_fp,
        BTreeSet::from([Permission::Read]),
        None,
    );
    let grant_id = grants.issue(grant).await.unwrap();

    let retrieved = grants.get(&grant_id).await.unwrap().unwrap();
    assert_eq!(&retrieved.keyspace_id, id.as_bytes());

    // Cap referencing the same keyspace verifies cleanly.
    let cap = Capability::new(
        *id.as_bytes(),
        SubjectKind::Keyspace,
        bob_fp,
        alice_fp,
        BTreeSet::from([Permission::Read]),
        None,
    );
    let bytes = cap.sign(&alice_signing).unwrap();
    let parsed =
        Capability::verify_full(&bytes, &alice_verifying, VerifyPolicy::PqRequired, Permission::Read)
            .unwrap();
    assert_eq!(&parsed.subject, &retrieved.keyspace_id);
}

#[tokio::test]
async fn test_capability_expiry() {
    let (signing_keys, verifying_keys, issuer_fp) = test_keys();
    let (_, _, grantee_fp) = test_keys();

    let keyspace_id = [42u8; 32];

    // Issue an already-expired capability.
    let mut cap = Capability::new(
        keyspace_id,
        SubjectKind::Keyspace,
        grantee_fp,
        issuer_fp,
        BTreeSet::from([Permission::Read]),
        Some(1),
    );
    cap.expires_at = Some(1);
    let bytes = cap.sign(&signing_keys).unwrap();

    // Signature alone parses fine — the parsed cap is what reports expiry.
    let parsed = Capability::verify(&bytes, &verifying_keys, VerifyPolicy::PqRequired).unwrap();
    assert!(parsed.is_expired());

    // verify_full bundles the expiry check into a hard error.
    assert!(
        Capability::verify_full(
            &bytes,
            &verifying_keys,
            VerifyPolicy::PqRequired,
            Permission::Read,
        )
        .is_err()
    );
}
