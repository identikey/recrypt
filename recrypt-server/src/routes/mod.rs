use crate::middleware::validate_nonce;
use crate::state::AppState;
use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post},
};
use std::sync::Arc;
use tower_governor::{
    GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::{KeyExtractor, SmartIpKeyExtractor},
    GovernorError,
};
use tower_http::trace::TraceLayer;

mod accounts;
mod files;
mod health;
mod keyspaces;
mod nonce;
mod recryption;

/// Per-fingerprint key extractor — pulls `X-Public-Key` header for authenticated
/// rate limiting on protected endpoints.
#[derive(Clone)]
pub struct FingerprintKeyExtractor;

impl KeyExtractor for FingerprintKeyExtractor {
    type Key = String;

    fn extract<B>(&self, req: &http::Request<B>) -> Result<Self::Key, GovernorError> {
        req.headers()
            .get("X-Public-Key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

pub fn router(state: AppState) -> Router {
    let rl = &state.config.rate_limit;

    // Per-IP limiter (applied to everything except /health)
    let per_ip_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(rl.per_ip_rps.max(1) as u64)
            .burst_size(rl.per_ip_burst.max(1))
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("valid per-ip governor config"),
    );

    // Per-fingerprint limiter (applied to authenticated/protected endpoints)
    let per_fp_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(rl.per_fingerprint_rps.max(1) as u64)
            .burst_size(rl.per_fingerprint_burst.max(1))
            .key_extractor(FingerprintKeyExtractor)
            .finish()
            .expect("valid per-fingerprint governor config"),
    );

    let per_ip_layer = GovernorLayer { config: per_ip_conf };
    let per_fp_layer = GovernorLayer { config: per_fp_conf };

    let protected = Router::new()
        .route("/accounts", post(accounts::create_account))
        .route(
            "/accounts/{fingerprint}/shares",
            get(recryption::list_shares),
        )
        .route("/files", post(files::upload_file))
        .route("/files/{hash}", delete(files::delete_file))
        .route("/recryption/share", post(recryption::create_share))
        .route(
            "/recryption/share/{id}",
            get(recryption::get_recrypted_share).delete(recryption::revoke_share),
        )
        // Keyspace & grant management
        .route("/keyspaces", post(keyspaces::create_keyspace))
        .route(
            "/keyspaces/{id}/versions",
            get(keyspaces::list_versions).post(keyspaces::publish_version),
        )
        .route("/grants", post(keyspaces::issue_grant))
        .route(
            "/grants/{id}",
            get(keyspaces::get_grant).delete(keyspaces::revoke_grant),
        )
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            validate_nonce,
        ))
        .layer(per_fp_layer);

    let public = Router::new()
        .route("/nonce", get(nonce::get_nonce))
        .route("/accounts/{fingerprint}", get(accounts::get_account))
        .route("/accounts/{fingerprint}/files", get(accounts::list_files))
        .route("/files/{hash}", get(files::download_file))
        // Read-only keyspace & grant endpoints. Reverse-index routes are
        // namespaced under `/members/` and `/subjects/` so they can never
        // shadow a literal keyspace/grant id segment.
        .route("/keyspaces/{id}", get(keyspaces::get_keyspace))
        .route(
            "/keyspaces/{id}/grants",
            get(keyspaces::list_grants_by_keyspace),
        )
        .route(
            "/members/{fp}/keyspaces",
            get(keyspaces::list_by_member),
        )
        .route(
            "/subjects/{fp}/grants",
            get(keyspaces::list_grants_by_subject),
        );

    // Health endpoint is exempt from all rate limiting.
    let health = Router::new().route("/health", get(health::health_check));

    Router::new()
        .merge(protected)
        .merge(public)
        .layer(per_ip_layer)
        .merge(health)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
