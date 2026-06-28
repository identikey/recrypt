//! Self-describing algorithm registry (§3.1 of the protocol spec).

use crate::error::{AuthError, Result};

/// Classical (pre-quantum) signature algorithms. The classical key is the identity's
/// primary key; its fingerprint identifies the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassicalAlg {
    /// Ed25519 (EdDSA, RFC 8032). Software key — not enclave-native on any platform.
    Ed25519,
    /// ECDSA over NIST P-256 (secp256r1). Enclave-native (Apple SE, Windows TPM, Android).
    P256,
}

/// Post-quantum signature algorithms (FIPS 204 / ML-DSA). Optional, always paired with
/// a classical key ("PQ implies classical").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqAlg {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl ClassicalAlg {
    pub fn tag(self) -> &'static str {
        match self {
            ClassicalAlg::Ed25519 => "ed25519",
            ClassicalAlg::P256 => "p256",
        }
    }
    pub fn from_tag(tag: &str) -> Result<Self> {
        match tag {
            "ed25519" => Ok(ClassicalAlg::Ed25519),
            "p256" => Ok(ClassicalAlg::P256),
            other => Err(AuthError::UnknownAlg(other.to_string())),
        }
    }
}

impl PqAlg {
    pub fn tag(self) -> &'static str {
        match self {
            PqAlg::MlDsa44 => "ml-dsa-44",
            PqAlg::MlDsa65 => "ml-dsa-65",
            PqAlg::MlDsa87 => "ml-dsa-87",
        }
    }
    pub fn from_tag(tag: &str) -> Result<Self> {
        match tag {
            "ml-dsa-44" => Ok(PqAlg::MlDsa44),
            "ml-dsa-65" => Ok(PqAlg::MlDsa65),
            "ml-dsa-87" => Ok(PqAlg::MlDsa87),
            other => Err(AuthError::UnknownAlg(other.to_string())),
        }
    }
}
