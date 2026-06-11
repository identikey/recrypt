use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod limits;
mod middleware;
mod nonces;
mod openapi;
mod routes;
mod shares;
mod state;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "recrypt_server=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load config
    let config = config::Config::load()?;

    // Bound address space so malformed PRE input degrades to a catchable
    // bad_alloc instead of OOM-killing the proxy (recrypt-hrq).
    limits::apply_address_space_limit(config.limits.address_space_gb);

    // Build app state
    let state = state::AppState::from_config(&config).await?;

    // Build router
    let app = routes::router(state);

    // Start server
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    tracing::info!("Starting recrypt-server on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
