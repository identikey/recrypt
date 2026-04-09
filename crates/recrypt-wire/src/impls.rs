//! MultiFormat trait implementations for core types using Gordian Envelope.

use crate::armor::{ArmorType, armor_decode, armor_encode};
use crate::convert::{encrypted_file_from_envelope, encrypted_file_to_envelope};
use crate::error::{WireError, WireResult};
use crate::format::MultiFormat;
use bc_envelope::prelude::*;
use recrypt_core::hybrid::EncryptedFile;

impl MultiFormat for EncryptedFile {
    fn envelope_type() -> &'static str {
        "recrypt.encrypted-file"
    }

    fn to_envelope(&self) -> WireResult<Vec<u8>> {
        let envelope = encrypted_file_to_envelope(self, None);
        Ok(envelope.to_cbor_data())
    }

    fn from_envelope(bytes: &[u8]) -> WireResult<Self> {
        let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
            .map_err(|e| WireError::Envelope(format!("parse envelope: {e}")))?;
        let (ef, _backend) = encrypted_file_from_envelope(&envelope)?;
        Ok(ef)
    }

    fn to_armor(&self) -> WireResult<String> {
        let envelope_bytes = self.to_envelope()?;
        let headers = [
            ("Version", "3"),
            ("Format", "envelope+cbor"),
        ];
        Ok(armor_encode(
            ArmorType::EncryptedFile,
            &headers,
            &envelope_bytes,
        ))
    }

    fn from_armor(s: &str) -> WireResult<Self> {
        let block = armor_decode(s)?;
        if block.armor_type != ArmorType::EncryptedFile {
            return Err(WireError::InvalidFormat(format!(
                "Expected ENCRYPTED FILE, got {:?}",
                block.armor_type
            )));
        }
        Self::from_envelope(&block.payload)
    }
}
