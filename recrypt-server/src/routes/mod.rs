use crate::middleware::validate_nonce;
use crate::state::AppState;
use axum::{
    Router, middleware as axum_middleware,
    routing::{delete, get, post},
};
use tower_http::trace::TraceLayer;

mod accounts;
mod files;
mod health;
mod nonce;
mod recryption;

pub fn router(state: AppState) -> Router {
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
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            validate_nonce,
        ));

    let public = Router::new()
        .route("/health", get(health::health_check))
        .route("/nonce", get(nonce::get_nonce))
        .route("/accounts/{fingerprint}", get(accounts::get_account))
        .route("/accounts/{fingerprint}/files", get(accounts::list_files))
        .route("/files/{hash}", get(files::download_file));

    Router::new()
        .merge(protected)
        .merge(public)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
