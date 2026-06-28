//! High-level response verification (§7).

use crate::challenge::{Challenge, MIN_NONCE_LEN, VERSION};
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, Fingerprint, PqPublicKey};
use crate::nonce::NonceStore;
use crate::challenge::Response;
use crate::signer::{verify_classical, verify_pq};

/// How much post-quantum assurance the verifier demands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyPolicy {
    /// Accept classical-only. If a PQ signature is present it MUST still verify.
    PqOptional,
    /// Require a verifiable PQ signature in addition to the classical one.
    PqRequired,
}

/// The authenticated identity produced by a successful verification.
#[derive(Clone, Debug)]
pub struct Verified {
    pub fingerprint: Fingerprint,
    pub public_key: ClassicalPublicKey,
    pub pq_public_key: Option<PqPublicKey>,
}

/// Verify a [`Response`] end-to-end. On success the nonce is consumed (replay-proof)
/// and the authenticated identity is returned.
///
/// - `expected_audience` — the audience this verifier accepts.
/// - `now` — current Unix seconds.
/// - `skew_secs` — tolerated clock skew on the validity window.
pub fn verify_response(
    resp: &Response,
    expected_audience: &str,
    now: u64,
    skew_secs: u64,
    policy: VerifyPolicy,
    nonces: &mut dyn NonceStore,
) -> Result<Verified> {
    let challenge = Challenge::from_bytes(&resp.challenge_bytes)?;

    if challenge.version != VERSION {
        return Err(AuthError::Version(challenge.version));
    }
    if challenge.audience != expected_audience {
        return Err(AuthError::Audience);
    }
    if challenge.nonce.len() < MIN_NONCE_LEN {
        return Err(AuthError::NonceTooShort);
    }
    // Validity window with symmetric skew tolerance.
    if now + skew_secs < challenge.issued_at || now > challenge.expires_at + skew_secs {
        return Err(AuthError::TimeWindow);
    }

    // Classical signature over the domain-separated payload.
    let payload = resp.signing_payload();
    verify_classical(&resp.public_key, &payload, &resp.signature)?;

    // Post-quantum policy. A present PQ signature must always verify (downgrade-proof);
    // PqRequired additionally rejects classical-only.
    let pq_public_key = match &resp.pq {
        Some((pqpub, pqsig)) => {
            verify_pq(pqpub, &payload, pqsig)?;
            Some(pqpub.clone())
        }
        None => {
            if policy == VerifyPolicy::PqRequired {
                return Err(AuthError::PqRequired);
            }
            None
        }
    };

    // All crypto checks passed — now burn the nonce (prevents replay of a valid proof).
    nonces.consume(&challenge.nonce, now)?;

    Ok(Verified {
        fingerprint: resp.public_key.fingerprint(),
        public_key: resp.public_key.clone(),
        pq_public_key,
    })
}
