//! Error type for the IdentiKey-auth protocol.

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("cbor: {0}")]
    Cbor(String),

    #[error("missing field: {0}")]
    MissingField(&'static str),

    #[error("unsupported protocol version: {0}")]
    Version(u64),

    #[error("unknown algorithm tag: {0}")]
    UnknownAlg(String),

    #[error("invalid {0} key bytes")]
    InvalidKey(&'static str),

    #[error("invalid {0} signature bytes")]
    InvalidSig(&'static str),

    #[error("signature verification failed")]
    BadSignature,

    #[error("audience mismatch")]
    Audience,

    #[error("nonce must be at least 16 bytes")]
    NonceTooShort,

    #[error("nonce replayed or not issued by this verifier")]
    NonceReplay,

    #[error("challenge outside its validity window")]
    TimeWindow,

    #[error("post-quantum signature required but absent")]
    PqRequired,

    #[error("post-quantum signature present without a verifiable key")]
    PqDangling,

    #[error("crypto backend: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, AuthError>;
