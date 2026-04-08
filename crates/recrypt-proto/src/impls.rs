//! MultiFormat trait implementations for core types

use crate::armor::{ArmorType, armor_decode, armor_encode};
use crate::error::{ProtoError, ProtoResult};
use crate::format::MultiFormat;
use crate::proto;
use prost::Message;
use recrypt_core::hybrid::EncryptedFile;
use serde::{Deserialize, Serialize};

// EncryptedFile serialization
impl MultiFormat for EncryptedFile {
    fn proto_name() -> &'static str {
        "recrypt.v1.EncryptedFileProto"
    }

    fn to_protobuf(&self) -> ProtoResult<Vec<u8>> {
        let proto = proto::EncryptedFileProto::from(self);
        let mut buf = Vec::with_capacity(proto.encoded_len());
        proto.encode(&mut buf)?;
        Ok(buf)
    }

    fn from_protobuf(bytes: &[u8]) -> ProtoResult<Self> {
        let proto = proto::EncryptedFileProto::decode(bytes)?;
        Self::try_from(proto)
    }

    fn to_json(&self) -> ProtoResult<String> {
        // Use a JSON-friendly representation
        #[derive(Serialize)]
        struct JsonEncryptedFile {
            version: u32,
            wrapped_key: JsonCiphertext,
            bao_hash: String,
            ciphertext: String,
        }

        #[derive(Serialize)]
        struct JsonCiphertext {
            backend: String,
            level: u32,
            data: String,
        }

        let json = JsonEncryptedFile {
            version: 3,
            wrapped_key: JsonCiphertext {
                backend: format!("{:?}", self.wrapped_key.backend()),
                level: self.wrapped_key.level() as u32,
                data: bs58::encode(self.wrapped_key.as_bytes()).into_string(),
            },
            bao_hash: bs58::encode(self.bao_hash).into_string(),
            ciphertext: bs58::encode(&self.ciphertext).into_string(),
        };

        Ok(serde_json::to_string_pretty(&json)?)
    }

    fn from_json(s: &str) -> ProtoResult<Self> {
        // Parse JSON and convert
        #[derive(Deserialize)]
        struct JsonEncryptedFile {
            version: u32,
            wrapped_key: JsonCiphertext,
            bao_hash: String,
            ciphertext: String,
        }

        #[derive(Deserialize)]
        struct JsonCiphertext {
            backend: String,
            level: u32,
            data: String,
        }

        let json: JsonEncryptedFile = serde_json::from_str(s)?;

        if json.version != 3 {
            return Err(ProtoError::VersionMismatch {
                expected: 3,
                actual: json.version,
            });
        }

        let backend = match json.wrapped_key.backend.as_str() {
            "Lattice" => recrypt_core::pre::BackendId::Lattice,
            "Mock" => recrypt_core::pre::BackendId::Mock,
            "EcPairing" => recrypt_core::pre::BackendId::EcPairing,
            "EcSecp256k1" => recrypt_core::pre::BackendId::EcSecp256k1,
            _ => {
                return Err(ProtoError::InvalidFormat(format!(
                    "Unknown backend: {}",
                    json.wrapped_key.backend
                )));
            }
        };

        let bao_hash: [u8; 32] = bs58::decode(&json.bao_hash)
            .into_vec()?
            .try_into()
            .map_err(|_| ProtoError::InvalidFormat("bao_hash must be 32 bytes".into()))?;

        Ok(EncryptedFile {
            wrapped_key: recrypt_core::pre::Ciphertext::new(
                backend,
                json.wrapped_key.level as u8,
                bs58::decode(&json.wrapped_key.data).into_vec()?,
            ),
            bao_hash,
            ciphertext: bs58::decode(&json.ciphertext).into_vec()?,
            signature: None, // JSON format doesn't include signature for now
        })
    }

    fn to_armor(&self, _armor_type: ArmorType) -> ProtoResult<String> {
        let proto_bytes = self.to_protobuf()?;
        let headers = [("Version", "3"), ("Format", "protobuf")];
        Ok(armor_encode(
            ArmorType::EncryptedFile,
            &headers,
            &proto_bytes,
        ))
    }

    fn from_armor(s: &str) -> ProtoResult<Self> {
        let block = armor_decode(s)?;
        if block.armor_type != ArmorType::EncryptedFile {
            return Err(ProtoError::InvalidFormat(format!(
                "Expected ENCRYPTED FILE, got {:?}",
                block.armor_type
            )));
        }
        Self::from_protobuf(&block.payload)
    }
}
