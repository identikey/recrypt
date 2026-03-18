//! Conversions between recrypt-core types and protobuf types

use crate::error::{ProtoError, ProtoResult};
use crate::proto;
use recrypt_core::hybrid::EncryptedFile;
use recrypt_core::pre::{BackendId, Ciphertext};
use recrypt_core::sign::MultiSig;

// BackendId conversions
impl From<BackendId> for proto::BackendId {
    fn from(id: BackendId) -> proto::BackendId {
        match id {
            BackendId::Lattice => proto::BackendId::BackendLattice,
            BackendId::EcPairing => proto::BackendId::BackendEcPairing,
            BackendId::EcSecp256k1 => proto::BackendId::BackendEcSecp256k1,
            BackendId::Mock => proto::BackendId::BackendMock,
        }
    }
}

impl TryFrom<proto::BackendId> for BackendId {
    type Error = ProtoError;

    fn try_from(v: proto::BackendId) -> ProtoResult<Self> {
        match v {
            proto::BackendId::BackendLattice => Ok(BackendId::Lattice),
            proto::BackendId::BackendEcPairing => Ok(BackendId::EcPairing),
            proto::BackendId::BackendEcSecp256k1 => Ok(BackendId::EcSecp256k1),
            proto::BackendId::BackendMock => Ok(BackendId::Mock),
            proto::BackendId::BackendUnknown => {
                Err(ProtoError::InvalidFormat("Unknown backend ID".into()))
            }
        }
    }
}

// Ciphertext conversions
impl From<&Ciphertext> for proto::CiphertextProto {
    fn from(ct: &Ciphertext) -> Self {
        proto::CiphertextProto {
            backend: proto::BackendId::from(ct.backend()) as i32,
            level: ct.level() as u32,
            data: ct.as_bytes().to_vec(),
        }
    }
}

impl TryFrom<proto::CiphertextProto> for Ciphertext {
    type Error = ProtoError;

    fn try_from(proto: proto::CiphertextProto) -> ProtoResult<Self> {
        let backend = proto::BackendId::try_from(proto.backend).map_err(|_| {
            ProtoError::InvalidFormat(format!("Unknown backend: {}", proto.backend))
        })?;
        let backend = BackendId::try_from(backend)?;
        Ok(Ciphertext::new(backend, proto.level as u8, proto.data))
    }
}

// EncryptedFile conversions
impl From<&EncryptedFile> for proto::EncryptedFileProto {
    fn from(ef: &EncryptedFile) -> Self {
        proto::EncryptedFileProto {
            version: 2,
            wrapped_key: Some(proto::CiphertextProto::from(&ef.wrapped_key)),
            bao_hash: ef.bao_hash.to_vec(),
            bao_outboard: ef.bao_outboard.clone(),
            ciphertext: ef.ciphertext.clone(),
            signature: ef.signature.as_ref().map(proto::MultiSignatureProto::from),
        }
    }
}

impl TryFrom<proto::EncryptedFileProto> for EncryptedFile {
    type Error = ProtoError;

    fn try_from(proto: proto::EncryptedFileProto) -> ProtoResult<Self> {
        let wrapped_key = proto
            .wrapped_key
            .ok_or_else(|| ProtoError::MissingField("wrapped_key".into()))?;

        if proto.bao_hash.len() != 32 {
            return Err(ProtoError::InvalidFormat(format!(
                "bao_hash must be 32 bytes, got {}",
                proto.bao_hash.len()
            )));
        }

        Ok(EncryptedFile {
            wrapped_key: Ciphertext::try_from(wrapped_key)?,
            bao_hash: proto.bao_hash.try_into().unwrap(),
            bao_outboard: proto.bao_outboard,
            ciphertext: proto.ciphertext,
            signature: proto.signature.map(MultiSig::try_from).transpose()?,
        })
    }
}

// MultiSig conversions
impl From<&MultiSig> for proto::MultiSignatureProto {
    fn from(sig: &MultiSig) -> Self {
        proto::MultiSignatureProto {
            ed25519_signature: sig.ed25519_sig.to_bytes().to_vec(),
            pq_signatures: vec![proto::PqSignatureProto {
                algorithm: "ML-DSA-87".into(),
                signature: sig.ml_dsa_sig.clone(),
            }],
        }
    }
}

impl TryFrom<proto::MultiSignatureProto> for MultiSig {
    type Error = ProtoError;

    fn try_from(proto: proto::MultiSignatureProto) -> ProtoResult<Self> {
        use ed25519_dalek::Signature;

        if proto.ed25519_signature.len() != 64 {
            return Err(ProtoError::InvalidFormat(
                "ED25519 signature must be 64 bytes".into(),
            ));
        }

        let ed25519_sig = Signature::from_bytes(&proto.ed25519_signature.try_into().unwrap());

        let ml_dsa_sig = proto
            .pq_signatures
            .into_iter()
            .find(|s| s.algorithm == "ML-DSA-87")
            .ok_or_else(|| ProtoError::MissingField("ML-DSA-87 signature".into()))?
            .signature;

        Ok(MultiSig {
            ed25519_sig,
            ml_dsa_sig,
        })
    }
}
