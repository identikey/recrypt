//! Verifies tower_governor per-IP rate limiting on the live router. We spin
//! up the server on a random port, fire requests at a non-/health endpoint,
//! and assert that 429 responses appear past the configured burst.

use std::net::SocketAddr;
use std::time::Duration;

use recrypt_server::config::Config;
use recrypt_server::routes;
use recrypt_server::state::AppState;
use tokio::net::TcpListener;

fn low_limit_config() -> Config {
    let toml = r#"
host = "127.0.0.1"
port = 0
pre_backend = "mock"

[storage]
backend = "memory"

[persistence]
backend = "memory"

[rate_limit]
per_ip_rps = 2
per_ip_burst = 2
per_fingerprint_rps = 100
per_fingerprint_burst = 200
"#;
    use figment::providers::Format;
    figment::Figment::new()
        .merge(figment::providers::Toml::string(toml))
        .extract()
        .expect("config parse")
}

async fn spawn_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let config = low_limit_config();
    let state = AppState::from_config(&config).await.expect("state");
    let app = routes::router(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    // Tiny delay so the server is ready to accept.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_ip_rate_limit_returns_429_and_health_is_exempt() {
    let (addr, server) = spawn_server().await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");

    // Hit a non-/health public endpoint that doesn't require auth/nonce.
    // GET /nonce returns 200 normally and is subject to per-IP limiting.
    let target = format!("http://{}/nonce", addr);

    let mut statuses = Vec::new();
    for _ in 0..20 {
        let resp = client.get(&target).send().await.expect("send");
        statuses.push(resp.status().as_u16());
    }

    let too_many = statuses.iter().filter(|s| **s == 429).count();
    assert!(
        too_many >= 1,
        "expected at least one 429 response past burst, got: {:?}",
        statuses
    );

    // /health must be exempt from rate limiting.
    let health_url = format!("http://{}/health", addr);
    for _ in 0..10 {
        let resp = client.get(&health_url).send().await.expect("health send");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "/health should never be rate-limited"
        );
    }

    // After the burst window has passed we should see a successful request again.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let resp = client.get(&target).send().await.expect("recovered send");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "expected request to recover after waiting for burst window"
    );

    server.abort();
}
