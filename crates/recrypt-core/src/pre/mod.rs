pub mod backends;
pub mod keys;
pub mod traits;

pub use keys::{Ciphertext, KeyPair, PublicKey, RecryptKey, SecretKey};
pub use traits::PreBackend;

use crate::error::PreError;

/// Identifies which backend produced a ciphertext/key
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum BackendId {
    /// OpenFHE BFV/PRE (post-quantum, lattice-based)
    #[serde(rename = "lattice")]
    Lattice = 0,
    /// IronCore recrypt (classical, BN254 pairing) - future
    #[serde(rename = "ec-pairing")]
    EcPairing = 1,
    /// NuCypher Umbral (classical, secp256k1) - future
    #[serde(rename = "ec-secp256k1")]
    EcSecp256k1 = 2,
    /// Mock backend for testing
    #[serde(rename = "mock")]
    Mock = 255,
}

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendId::Lattice => write!(f, "lattice"),
            BackendId::EcPairing => write!(f, "ec-pairing"),
            BackendId::EcSecp256k1 => write!(f, "ec-secp256k1"),
            BackendId::Mock => write!(f, "mock"),
        }
    }
}

impl std::str::FromStr for BackendId {
    type Err = PreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lattice" | "pq" | "post-quantum" | "openfhe" => Ok(BackendId::Lattice),
            "ec-pairing" | "ecpairing" | "pairing" => Ok(BackendId::EcPairing),
            "ec-secp256k1" | "secp256k1" | "umbral" => Ok(BackendId::EcSecp256k1),
            "mock" | "test" => Ok(BackendId::Mock),
            other => Err(PreError::InvalidKey(format!("Unknown backend: {other}"))),
        }
    }
}

impl TryFrom<u8> for BackendId {
    type Error = PreError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Lattice),
            1 => Ok(Self::EcPairing),
            2 => Ok(Self::EcSecp256k1),
            255 => Ok(Self::Mock),
            other => Err(PreError::InvalidKey(format!("Unknown backend ID: {other}"))),
        }
    }
}
