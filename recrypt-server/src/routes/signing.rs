//! Post-quantum signing delegation endpoints.
//!
//! These endpoints sign and verify arbitrary byte payloads with ML-DSA-87
//! on behalf of callers who don't have a local liboqs available (e.g. the
//! browser, or a WASM-only runtime). The caller provides the secret key
//! over the wire, so these are *delegation primitives* not vault services
//! — they carry no more authority than the caller already has.
//!
//! Wire shape (input and output): **base58 strings with an optional `b58:`
//! prefix**. This matches the Dreamball project's JSON convention
//! (`src/lib/generated/cbor.ts`) so no format translation is needed at the
//! Dreamball/Recrypt boundary.
//!
//! Security notes:
//!   - In production, run this server alongside its callers (localhost or
//!     trusted intra-cluster network). Do NOT expose /sign/ml-dsa over the
//!     public internet with raw secret-key bodies.
//!   - The endpoint is public (no auth) because the secret key IS the
//!     authority. Authentication would be tautological.
//!   - Rate-limited per-IP via the server's global governor layer.
//!
//! See `Dreamball/docs/known-gaps.md §6` and `ARCHITECTURE.md §4` for the
//! architectural context.

use axum::{Json, http::StatusCode};
use recrypt_ffi::liboqs::{PqAlgorithm, pq_sign, pq_verify};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignRequest {
    /// ML-DSA-87 secret key, base58-encoded. 4896 bytes raw.
    pub secret_key: String,
    /// Bytes to sign, base58-encoded.
    pub message: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    /// ML-DSA-87 signature, base58-encoded. ~4627 bytes raw.
    pub signature: String,
    pub algorithm: &'static str,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    /// ML-DSA-87 public key, base58-encoded. 2592 bytes raw.
    pub public_key: String,
    /// Signed message, base58-encoded.
    pub message: String,
    /// Signature to verify, base58-encoded.
    pub signature: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub ok: bool,
    pub algorithm: &'static str,
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

fn decode_b58(s: &str, label: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    let raw = s.strip_prefix("b58:").unwrap_or(s);
    bs58::decode(raw).into_vec().map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("{label}: base58 decode failed: {e}"),
            }),
        )
    })
}

/// POST /sign/ml-dsa — delegate ML-DSA-87 signing.
pub async fn sign_ml_dsa(
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let sk = decode_b58(&req.secret_key, "secret_key")?;
    let msg = decode_b58(&req.message, "message")?;

    let sig = pq_sign(&sk, PqAlgorithm::MlDsa87, &msg).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("sign failed: {e}"),
            }),
        )
    })?;

    Ok(Json(SignResponse {
        signature: format!("b58:{}", bs58::encode(sig).into_string()),
        algorithm: "ml-dsa-87",
    }))
}

/// POST /verify/ml-dsa — delegate ML-DSA-87 verification.
pub async fn verify_ml_dsa(
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pk = decode_b58(&req.public_key, "public_key")?;
    let msg = decode_b58(&req.message, "message")?;
    let sig = decode_b58(&req.signature, "signature")?;

    match pq_verify(&pk, PqAlgorithm::MlDsa87, &msg, &sig) {
        Ok(ok) => Ok(Json(VerifyResponse {
            ok,
            algorithm: "ml-dsa-87",
            reason: if ok {
                None
            } else {
                Some("signature verification failed".into())
            },
        })),
        Err(e) => Ok(Json(VerifyResponse {
            ok: false,
            algorithm: "ml-dsa-87",
            reason: Some(format!("verify error: {e}")),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sign_then_verify_roundtrip() {
        // Use the library's keygen for a known-good pair.
        let kp = recrypt_ffi::liboqs::pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let message = b"hello from jelly";

        let sign_req = Json(SignRequest {
            secret_key: format!("b58:{}", bs58::encode(&kp.secret_key).into_string()),
            message: format!("b58:{}", bs58::encode(message).into_string()),
        });
        let Json(sign_resp) = sign_ml_dsa(sign_req).await.unwrap();
        assert_eq!(sign_resp.algorithm, "ml-dsa-87");

        let verify_req = Json(VerifyRequest {
            public_key: format!("b58:{}", bs58::encode(&kp.public_key).into_string()),
            message: format!("b58:{}", bs58::encode(message).into_string()),
            signature: sign_resp.signature,
        });
        let Json(verify_resp) = verify_ml_dsa(verify_req).await.unwrap();
        assert!(verify_resp.ok);
    }
}
