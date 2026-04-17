//! Verifies that SQLite-backed state survives a fresh `AppState::from_config`
//! call against the same database file. The HTTP layer is intentionally
//! bypassed: registering an account / creating a share via HTTP requires
//! signing nonces and constructing recryption keys, which is not what this
//! test is exercising. The point is to prove the trait-backed stores actually
//! persist their data — driving them via `Arc<dyn ...>` directly is the
//! minimum reproducer for that property.

use std::path::PathBuf;

use identikey_storage_auth::{AccountRecord, PublicKeyFingerprint};
use recrypt_core::pre::BackendId;
use recrypt_server::config::{
    Config, NonceConfig, PersistenceConfig, RateLimitConfig, StorageConfig,
};
use recrypt_server::shares::SharePolicy;
use recrypt_server::state::AppState;
use tempfile::tempdir;

fn config_with_sqlite(path: PathBuf) -> Config {
    // Build a Config without going through figment so the test is hermetic.
    // We rely on `Default` for substructs that have it and set persistence
    // explicitly.
    let toml = format!(
        r#"
host = "127.0.0.1"
port = 0
pre_backend = "mock"

[storage]
backend = "memory"

[persistence]
backend = "sqlite"
sqlite_path = "{}"
"#,
        path.display()
    );
    use figment::providers::Format;
    figment::Figment::new()
        .merge(figment::providers::Toml::string(&toml))
        .extract()
        .expect("config parse")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_persistence_survives_restart() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("recrypt.db");

    let config = config_with_sqlite(db_path.clone());

    // ---- First "process" ----
    let state = AppState::from_config(&config).await.expect("first state");

    let ed25519_pk = vec![7u8; 32];
    let fp = PublicKeyFingerprint::from_public_key(&ed25519_pk);
    let record = AccountRecord {
        fingerprint: fp.to_base58(),
        ed25519_pk: ed25519_pk.clone(),
        ml_dsa_pk: vec![8u8; 64],
        created_at: 100,
    };
    state
        .accounts
        .register(record.clone())
        .await
        .expect("register account");

    let policy = SharePolicy {
        id: "share-1".to_string(),
        from_fingerprint: fp.to_base58(),
        to_fingerprint: "bob".to_string(),
        file_hash: blake3::hash(b"some-file"),
        recrypt_key: vec![1, 2, 3, 4, 5],
        wrapped_key: vec![10, 20, 30],
        backend_id: BackendId::Mock,
        created_at: 200,
    };
    state
        .shares
        .create(policy.clone())
        .await
        .expect("create share");

    // Drop everything (simulates process exit). The nonce-GC task is aborted
    // via the NonceGcHandle drop guard inside AppState.
    drop(state);

    // Give SQLite a moment to flush WAL — not strictly required, but cheap
    // insurance.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ---- Second "process" — fresh AppState pointing at the same DB ----
    let state2 = AppState::from_config(&config).await.expect("second state");

    let got = state2
        .accounts
        .get(&fp)
        .await
        .expect("account lookup")
        .expect("account present after restart");
    assert_eq!(got.ed25519_pk, ed25519_pk);
    assert_eq!(got.created_at, 100);

    let got_share = state2
        .shares
        .get(&"share-1".to_string())
        .await
        .expect("share lookup")
        .expect("share present after restart");
    assert_eq!(got_share.to_fingerprint, "bob");
    assert_eq!(got_share.recrypt_key, vec![1, 2, 3, 4, 5]);
    assert_eq!(got_share.backend_id, BackendId::Mock);

    // Silence unused-import lint on shape-only structs (Default impls).
    let _ = (
        StorageConfig::default(),
        NonceConfig::default(),
        PersistenceConfig::default(),
        RateLimitConfig::default(),
    );
}
