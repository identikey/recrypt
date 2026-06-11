use std::net::SocketAddr;
use tokio::net::TcpListener;

pub struct TestServer {
    pub url: String,
    #[allow(dead_code)]
    pub addr: SocketAddr,
}

impl TestServer {
    pub async fn start() -> Self {
        let config = recrypt_server::config::Config {
            host: "127.0.0.1".into(),
            port: 0, // OS assigns port
            storage: Default::default(),
            persistence: Default::default(),
            nonce: Default::default(),
            pre_backend: "mock".into(),
            rate_limit: Default::default(),
            limits: Default::default(),
        };

        let state = recrypt_server::state::AppState::new(&config).await.unwrap();
        let app = recrypt_server::routes::router(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Give server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Self {
            url: format!("http://{addr}"),
            addr,
        }
    }
}
