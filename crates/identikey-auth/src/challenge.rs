//! Challenge + Response wire structures and the domain-separated signing payload
//! (§4 of the protocol spec).

use crate::cbor::{map, Value};
use crate::error::{AuthError, Result};
use crate::key::{ClassicalPublicKey, ClassicalSignature, PqPublicKey, PqSignature};

/// Current protocol version.
pub const VERSION: u64 = 1;
/// Domain-separation context tag — distinguishes IdentiKey-auth signatures from any
/// other use of the same key.
pub const CONTEXT: &str = "identikey-auth/v1";
/// Purpose tag for a login/challenge proof.
pub const PURPOSE_CHALLENGE: &str = "challenge";
/// Minimum verifier-issued nonce length, in bytes.
pub const MIN_NONCE_LEN: usize = 16;

/// A verifier-issued challenge (§4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub version: u64,
    pub audience: String,
    pub nonce: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl Challenge {
    fn to_value(&self) -> Value {
        map(vec![
            ("v", Value::Uint(self.version)),
            ("aud", Value::Text(self.audience.clone())),
            ("nonce", Value::Bytes(self.nonce.clone())),
            ("iat", Value::Uint(self.issued_at)),
            ("exp", Value::Uint(self.expires_at)),
        ])
    }

    /// Canonical dCBOR bytes of this challenge.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_value().to_bytes()
    }

    /// Parse canonical challenge bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let v = Value::from_bytes(data)?;
        let version = v.get("v")?.as_uint()?;
        Ok(Self {
            version,
            audience: v.get("aud")?.as_text()?.to_string(),
            nonce: v.get("nonce")?.as_bytes()?.to_vec(),
            issued_at: v.get("iat")?.as_uint()?,
            expires_at: v.get("exp")?.as_uint()?,
        })
    }
}

/// The domain-separated payload that is actually signed (§4.3):
/// `dcbor([ CONTEXT, PURPOSE_CHALLENGE, chal_bytes ])`.
pub fn signing_payload(chal_bytes: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Text(CONTEXT.to_string()),
        Value::Text(PURPOSE_CHALLENGE.to_string()),
        Value::Bytes(chal_bytes.to_vec()),
    ])
    .to_bytes()
}

/// A claimant's response to a challenge (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Verbatim canonical bytes of the challenge being answered.
    pub challenge_bytes: Vec<u8>,
    pub public_key: ClassicalPublicKey,
    pub signature: ClassicalSignature,
    /// Optional post-quantum public key + signature (both present, or neither).
    pub pq: Option<(PqPublicKey, PqSignature)>,
}

impl Response {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut entries = vec![
            ("chal", Value::Bytes(self.challenge_bytes.clone())),
            ("pub", self.public_key.to_value()),
            ("sig", self.signature.to_value()),
        ];
        if let Some((pqpub, pqsig)) = &self.pq {
            entries.push(("pqpub", pqpub.to_value()));
            entries.push(("pqsig", pqsig.to_value()));
        }
        map(entries).to_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let v = Value::from_bytes(data)?;
        let challenge_bytes = v.get("chal")?.as_bytes()?.to_vec();
        let public_key = ClassicalPublicKey::from_value(v.get("pub")?)?;
        let signature = ClassicalSignature::from_value(v.get("sig")?)?;
        let pqpub = v.get_opt("pqpub")?;
        let pqsig = v.get_opt("pqsig")?;
        let pq = match (pqpub, pqsig) {
            (Some(pk), Some(sig)) => Some((
                PqPublicKey::from_value(pk)?,
                PqSignature::from_value(sig)?,
            )),
            (None, None) => None,
            // A dangling PQ key or signature is malformed.
            _ => return Err(AuthError::PqDangling),
        };
        Ok(Self {
            challenge_bytes,
            public_key,
            signature,
            pq,
        })
    }

    /// The signing payload for this response's embedded challenge.
    pub fn signing_payload(&self) -> Vec<u8> {
        signing_payload(&self.challenge_bytes)
    }
}
