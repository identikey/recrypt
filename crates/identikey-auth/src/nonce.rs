//! Verifier-issued nonces + replay protection (§6, §7).

use std::collections::HashMap;

use rand_core::RngCore;

use crate::challenge::{Challenge, MIN_NONCE_LEN, VERSION};
use crate::error::{AuthError, Result};

/// Stores the nonces a verifier has issued and consumes them on use, so each challenge
/// is answerable exactly once and only if this verifier issued it.
pub trait NonceStore {
    /// Record a freshly issued nonce and its absolute expiry (Unix seconds).
    fn record_issued(&mut self, nonce: &[u8], expires_at: u64);
    /// Consume a nonce on a successful proof. Errors if the nonce was never issued here,
    /// was already used, or has expired.
    fn consume(&mut self, nonce: &[u8], now: u64) -> Result<()>;
    /// Drop expired entries.
    fn gc(&mut self, now: u64);
}

/// In-memory [`NonceStore`] suitable for a single-process verifier.
#[derive(Default)]
pub struct InMemoryNonceStore {
    /// nonce -> (expires_at, used)
    issued: HashMap<Vec<u8>, (u64, bool)>,
}

impl InMemoryNonceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn record_issued(&mut self, nonce: &[u8], expires_at: u64) {
        self.issued.insert(nonce.to_vec(), (expires_at, false));
    }

    fn consume(&mut self, nonce: &[u8], now: u64) -> Result<()> {
        match self.issued.get_mut(nonce) {
            None => Err(AuthError::NonceReplay),
            Some((expires_at, used)) => {
                if *used {
                    return Err(AuthError::NonceReplay);
                }
                if now > *expires_at {
                    return Err(AuthError::TimeWindow);
                }
                *used = true;
                Ok(())
            }
        }
    }

    fn gc(&mut self, now: u64) {
        self.issued.retain(|_, (expires_at, _)| *expires_at >= now);
    }
}

/// Issues challenges for a fixed audience and records their nonces in a [`NonceStore`].
pub struct ChallengeIssuer {
    audience: String,
    ttl_secs: u64,
}

impl ChallengeIssuer {
    pub fn new(audience: impl Into<String>, ttl_secs: u64) -> Self {
        Self {
            audience: audience.into(),
            ttl_secs,
        }
    }

    /// Issue a fresh challenge at time `now` (Unix seconds), recording its nonce.
    pub fn issue(&self, store: &mut dyn NonceStore, now: u64) -> Challenge {
        let mut nonce = vec![0u8; MIN_NONCE_LEN];
        rand_core::OsRng.fill_bytes(&mut nonce);
        let expires_at = now + self.ttl_secs;
        store.record_issued(&nonce, expires_at);
        Challenge {
            version: VERSION,
            audience: self.audience.clone(),
            nonce,
            issued_at: now,
            expires_at,
        }
    }
}
