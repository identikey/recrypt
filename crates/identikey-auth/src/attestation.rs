//! IdentiKey → NodeId attestation (Papyrus FR5/FR6; protocol spec §11).
//!
//! A device's identity key signs a transport node identifier (e.g. an iroh `NodeId`),
//! yielding a self-contained, peer-verifiable link from the IdentiKey identity to that
//! node. Verification (FR6) needs only the attestation and the protocol — no server.
//!
//! This reuses the protocol's domain separation: signatures are over
//! `dcbor([CONTEXT, "node-attestation", node_id])`, so a node attestation can never be
//! confused with a login challenge signature ([`crate::challenge`]) or any other context.

use crate::cbor::{map, Value};
use crate::challenge::CONTEXT;
use crate::error::{AuthError, Result};
use crate::key::{
    ClassicalPublicKey, ClassicalSignature, Fingerprint, PqPublicKey, PqSignature,
};
use crate::signer::{verify_classical, verify_pq, Signer};
use crate::verify::VerifyPolicy;

/// Purpose tag distinguishing a node attestation from other signed payloads.
pub const PURPOSE_NODE: &str = "node-attestation";

/// The domain-separated payload signed for a node attestation:
/// `dcbor([ CONTEXT, "node-attestation", node_id ])`.
pub fn node_signing_payload(node_id: &[u8]) -> Vec<u8> {
    Value::Array(vec![
        Value::Text(CONTEXT.to_string()),
        Value::Text(PURPOSE_NODE.to_string()),
        Value::Bytes(node_id.to_vec()),
    ])
    .to_bytes()
}

/// A signed link from a device identity key to a transport `node_id` (FR5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAttestation {
    /// The attested node identifier (e.g. a 32-byte iroh ed25519 NodeId).
    pub node_id: Vec<u8>,
    /// The attesting device's classical public key.
    pub public_key: ClassicalPublicKey,
    /// Classical signature over the domain-separated payload.
    pub signature: ClassicalSignature,
    /// Optional post-quantum public key + signature over the same payload.
    pub pq: Option<(PqPublicKey, PqSignature)>,
}

impl NodeAttestation {
    /// The attesting identity's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.public_key.fingerprint()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut entries = vec![
            ("node", Value::Bytes(self.node_id.clone())),
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
        let node_id = v.get("node")?.as_bytes()?.to_vec();
        let public_key = ClassicalPublicKey::from_value(v.get("pub")?)?;
        let signature = ClassicalSignature::from_value(v.get("sig")?)?;
        let pq = match (v.get_opt("pqpub")?, v.get_opt("pqsig")?) {
            (Some(pk), Some(sig)) => {
                Some((PqPublicKey::from_value(pk)?, PqSignature::from_value(sig)?))
            }
            (None, None) => None,
            _ => return Err(AuthError::PqDangling),
        };
        Ok(Self {
            node_id,
            public_key,
            signature,
            pq,
        })
    }
}

/// FR5: produce an attestation binding this signer's identity to `node_id`.
pub fn attest_node_id(signer: &dyn Signer, node_id: &[u8]) -> Result<NodeAttestation> {
    let payload = node_signing_payload(node_id);
    let signature = signer.sign_classical(&payload)?;
    let pq = match (signer.pq_public_key(), signer.sign_pq(&payload)?) {
        (Some(pk), Some(sig)) => Some((pk, sig)),
        _ => None,
    };
    Ok(NodeAttestation {
        node_id: node_id.to_vec(),
        public_key: signer.classical_public_key(),
        signature,
        pq,
    })
}

/// FR6: verify a peer's attestation over its `node_id`. Stateless; returns the
/// authenticated identity fingerprint on success. Downgrade-proof, like challenge
/// verification: a present PQ signature must verify; `PqRequired` rejects classical-only.
pub fn verify_node_attestation(att: &NodeAttestation, policy: VerifyPolicy) -> Result<Fingerprint> {
    let payload = node_signing_payload(&att.node_id);
    verify_classical(&att.public_key, &payload, &att.signature)?;
    match &att.pq {
        Some((pqpub, pqsig)) => verify_pq(pqpub, &payload, pqsig)?,
        None => {
            if policy == VerifyPolicy::PqRequired {
                return Err(AuthError::PqRequired);
            }
        }
    }
    Ok(att.public_key.fingerprint())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::SoftwareSigner;

    #[test]
    fn attest_verify_roundtrip() {
        let signer = SoftwareSigner::generate_p256();
        let node_id = [3u8; 32];
        let att = attest_node_id(&signer, &node_id).unwrap();
        let fp = verify_node_attestation(&att, VerifyPolicy::PqOptional).unwrap();
        assert_eq!(fp, signer.classical_public_key().fingerprint());
        // wire round-trip
        let decoded = NodeAttestation::from_bytes(&att.to_bytes()).unwrap();
        assert_eq!(decoded, att);
    }

    #[test]
    fn tampered_node_id_fails() {
        let signer = SoftwareSigner::generate_ed25519();
        let mut att = attest_node_id(&signer, &[1u8; 32]).unwrap();
        att.node_id[0] ^= 0xFF;
        assert!(verify_node_attestation(&att, VerifyPolicy::PqOptional).is_err());
    }

    #[test]
    fn hybrid_pq_and_required_policy() {
        let signer = SoftwareSigner::generate_ed25519().with_ml_dsa_65().unwrap();
        let att = attest_node_id(&signer, &[7u8; 32]).unwrap();
        assert!(att.pq.is_some());
        verify_node_attestation(&att, VerifyPolicy::PqRequired).unwrap();
    }

    #[test]
    fn classical_only_rejected_when_pq_required() {
        let signer = SoftwareSigner::generate_p256();
        let att = attest_node_id(&signer, &[7u8; 32]).unwrap();
        assert!(matches!(
            verify_node_attestation(&att, VerifyPolicy::PqRequired),
            Err(AuthError::PqRequired)
        ));
    }

    #[test]
    fn login_and_node_payloads_differ() {
        // Domain separation: same bytes, different purpose tags → different payloads.
        assert_ne!(
            node_signing_payload(&[9u8; 32]),
            crate::challenge::signing_payload(&[9u8; 32])
        );
    }
}
