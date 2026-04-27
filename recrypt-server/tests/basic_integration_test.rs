//! Basic integration tests for recrypt-server

use reqwest::Client;

mod common;

#[tokio::test]
async fn test_health_check() {
    let server = common::TestServer::start().await;
    let client = Client::new();

    let response = client
        .get(format!("{}/health", server.url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_nonce_generation() {
    let server = common::TestServer::start().await;
    let client = Client::new();

    let response = client
        .get(format!("{}/nonce", server.url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.expect("Failed to parse JSON");
    assert!(body["nonce"].is_string());
    assert!(body["expires_at"].is_number());

    // Verify nonce format: {timestamp}:{uuid}
    let nonce = body["nonce"].as_str().unwrap();
    assert!(nonce.contains(':'));
    let parts: Vec<&str> = nonce.split(':').collect();
    assert_eq!(parts.len(), 2);

    // First part should be a timestamp (numeric)
    assert!(parts[0].parse::<u64>().is_ok());

    // Second part should be UUID-like (has dashes)
    assert!(parts[1].contains('-'));
}

#[tokio::test]
async fn test_account_malformed_fingerprint() {
    // A bare "nonexistent" path segment fails fingerprint parsing before the
    // store lookup, so it must be 400 (BadRequest), not 404. The
    // well-formed-but-unknown 404 case is covered by
    // `test_account_not_found` below.
    let server = common::TestServer::start().await;
    let client = Client::new();

    let response = client
        .get(format!("{}/accounts/nonexistent", server.url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_account_not_found() {
    // Well-formed fingerprint (32-byte base58) that no account ever
    // registered — must reach the store lookup and return 404.
    let server = common::TestServer::start().await;
    let client = Client::new();

    let unknown_fp = bs58::encode([0u8; 32]).into_string();
    let response = client
        .get(format!("{}/accounts/{unknown_fp}", server.url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_file_not_found() {
    let server = common::TestServer::start().await;
    let client = Client::new();

    let response = client
        .get(format!("{}/files/nonexistent", server.url))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), 400); // Invalid hash format
}
