use crate::error::ServerError;
use crate::middleware::auth::extract_signature_headers;
use crate::nonces;
use crate::state::AppState;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};

/// Middleware that validates nonce freshness/format and atomically marks it used.
pub async fn validate_nonce(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ServerError> {
    let headers = extract_signature_headers(request.headers())?;
    let window = state.config.nonce.window_secs;

    if !nonces::validate_format(&headers.nonce, window) {
        return Err(ServerError::NonceInvalid);
    }
    let expires_at = nonces::nonce_expiry_secs(&headers.nonce, window);

    // Atomically claim the nonce. `false` means the nonce was already used.
    let first_use = state.nonces.mark_used(&headers.nonce, expires_at).await?;
    if !first_use {
        return Err(ServerError::NonceInvalid);
    }

    Ok(next.run(request).await)
}
