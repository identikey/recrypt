//! Post-quantum signing delegation endpoints.
//!
//! These endpoints sign and verify arbitrary byte payloads with ML-DSA-87
//! on behalf of callers who don't have a local liboqs available (e.g. the
//! browser, or a WASM-only runtime). The caller provides the secret key
//! over the wire, so these are *delegation primitives* not vault services
//! — they carry no more authority than the caller already has.
//!
//! ## Wire shape
//!
//! Inputs and outputs are `"b64:<base64>"`. That is the only accepted form.
//!
//! The `b58:` tag and the bare unprefixed string were removed on 2026-08-07.
//! ML-DSA-87 payloads are multi-KB (4.9 KB secret key, 2.6 KB public key,
//! ~4.6 KB signature) and base58 is O(n²) bignum arithmetic, so those two
//! forms were an unbounded quadratic decode reachable from untrusted input on
//! a public, unauthenticated endpoint. Nothing has shipped to production, so
//! there was no compatibility worth keeping.
//!
//! Security notes:
//!   - In production, run this server alongside its callers (localhost or
//!     trusted intra-cluster network). Do NOT expose /sign/ml-dsa over the
//!     public internet with raw secret-key bodies.
//!   - The endpoint is public (no auth) because the secret key IS the
//!     authority. Authentication would be tautological.
//!   - Rate-limited per-IP via the server's global governor layer.
//!
//! See `encoding-conventions.md` (identikey-protocol/docs/standards) for the rationale behind
//! base64 over base58 for multi-KB blobs.

use axum::{Json, http::StatusCode};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use recrypt_ffi::liboqs::{PqAlgorithm, pq_sign, pq_verify};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct SignRequest {
    /// ML-DSA-87 secret key (4896 B), as `b64:<base64>`.
    pub secret_key: String,
    /// Bytes to sign. Same encoding rules as `secret_key`.
    pub message: String,
}

#[derive(Serialize, Debug)]
pub struct SignResponse {
    /// ML-DSA-87 signature (~4627 B), emitted as `b64:<base64>`.
    pub signature: String,
    pub algorithm: &'static str,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    /// ML-DSA-87 public key (2592 B). Same encoding rules as `SignRequest`.
    pub public_key: String,
    pub message: String,
    pub signature: String,
}

#[derive(Serialize, Debug)]
pub struct VerifyResponse {
    pub ok: bool,
    pub algorithm: &'static str,
    pub reason: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub error: String,
}

/// Decode a `b64:<base64>` input. No other form is accepted — see the module
/// docs for why the base58 forms were removed.
fn decode_input(s: &str, label: &str) -> Result<Vec<u8>, (StatusCode, Json<ErrorResponse>)> {
    recrypt_wire::encoding::decode_tagged(s, label).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    })
}

/// Encode bytes for the response. Always uses `b64:` — base64 is the
/// canonical wire encoding for multi-KB blobs (see encoding-conventions.md).
fn encode_output(bytes: &[u8]) -> String {
    format!("b64:{}", B64.encode(bytes))
}

/// POST /sign/ml-dsa — delegate ML-DSA-87 signing.
pub async fn sign_ml_dsa(
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let sk = decode_input(&req.secret_key, "secret_key")?;
    let msg = decode_input(&req.message, "message")?;

    let sig = pq_sign(&sk, PqAlgorithm::MlDsa87, &msg).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("sign failed: {e}"),
            }),
        )
    })?;

    Ok(Json(SignResponse {
        signature: encode_output(&sig),
        algorithm: "ml-dsa-87",
    }))
}

/// POST /verify/ml-dsa — delegate ML-DSA-87 verification.
pub async fn verify_ml_dsa(
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pk = decode_input(&req.public_key, "public_key")?;
    let msg = decode_input(&req.message, "message")?;
    let sig = decode_input(&req.signature, "signature")?;

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
    async fn sign_then_verify_b64_roundtrip() {
        let kp = recrypt_ffi::liboqs::pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let message = b"hello from jelly";

        let sign_req = Json(SignRequest {
            secret_key: format!("b64:{}", B64.encode(&kp.secret_key)),
            message: format!("b64:{}", B64.encode(message)),
        });
        let Json(sign_resp) = sign_ml_dsa(sign_req).await.unwrap();
        assert_eq!(sign_resp.algorithm, "ml-dsa-87");
        assert!(
            sign_resp.signature.starts_with("b64:"),
            "response must use b64: prefix"
        );

        let verify_req = Json(VerifyRequest {
            public_key: format!("b64:{}", B64.encode(&kp.public_key)),
            message: format!("b64:{}", B64.encode(message)),
            signature: sign_resp.signature,
        });
        let Json(verify_resp) = verify_ml_dsa(verify_req).await.unwrap();
        assert!(verify_resp.ok);
    }

    #[tokio::test]
    async fn b58_tagged_input_is_rejected() {
        // Removed 2026-08-07. This endpoint is public and unauthenticated, and
        // ML-DSA-87 payloads are multi-KB, so accepting base58 here meant an
        // unbounded O(n^2) decode driven by anonymous input. The error must
        // name the form the caller should send instead.
        let kp = recrypt_ffi::liboqs::pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let req = Json(SignRequest {
            secret_key: format!("b58:{}", bs58::encode(&kp.secret_key).into_string()),
            message: format!("b58:{}", bs58::encode(b"legacy client").into_string()),
        });
        let (status, Json(err)) = sign_ml_dsa(req).await.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            err.error.contains("b64:<base64>"),
            "error must name the required form, got: {}",
            err.error
        );
    }

    #[tokio::test]
    async fn bare_unprefixed_input_is_rejected() {
        // Previously "treated as base58 for pre-2026 clients". There are no
        // pre-2026 clients; nothing shipped.
        let kp = recrypt_ffi::liboqs::pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        let req = Json(SignRequest {
            secret_key: bs58::encode(&kp.secret_key).into_string(),
            message: bs58::encode(b"no prefix").into_string(),
        });
        let (status, _) = sign_ml_dsa(req).await.unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_invalid_b64() {
        let req = Json(SignRequest {
            secret_key: "b64:!!!not-base64".to_string(),
            message: "b64:aGVsbG8=".to_string(),
        });
        let err = sign_ml_dsa(req).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.error.contains("base64 decode failed"));
    }
}
