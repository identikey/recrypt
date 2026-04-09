//! ASCII armor format for human-readable export
//!
//! Format:
//! ```text
//! ----- BEGIN RECRYPT PUBLIC KEY -----
//! Version: 1
//! Algorithm: ED25519+ML-DSA-87+PRE
//! Fingerprint: a3k7x5a_Ab3DeF_Xy9ZmP7q_R2sK1M4V
//! Created: 2024-01-15T10:30:00Z
//!
//! eyJlZDI1NTE5IjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FF...
//! (base64 continues)
//! ----- END RECRYPT PUBLIC KEY -----
//! ```

use crate::error::{WireError, WireResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

/// Types of armored content
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmorType {
    PublicKey,
    SecretKey,
    Message,
    Capability,
    RecryptKey,
    EncryptedFile,
}

impl ArmorType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::PublicKey => "PUBLIC KEY",
            Self::SecretKey => "SECRET KEY",
            Self::Message => "MESSAGE",
            Self::Capability => "CAPABILITY",
            Self::RecryptKey => "RECRYPT KEY",
            Self::EncryptedFile => "ENCRYPTED FILE",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "PUBLIC KEY" => Some(Self::PublicKey),
            "SECRET KEY" => Some(Self::SecretKey),
            "MESSAGE" => Some(Self::Message),
            "CAPABILITY" => Some(Self::Capability),
            "RECRYPT KEY" => Some(Self::RecryptKey),
            "ENCRYPTED FILE" => Some(Self::EncryptedFile),
            _ => None,
        }
    }
}

/// Parsed armor block
#[derive(Debug)]
pub struct ArmorBlock {
    pub armor_type: ArmorType,
    pub headers: HashMap<String, String>,
    pub payload: Vec<u8>,
}

/// Encode data as ASCII armor
pub fn armor_encode(armor_type: ArmorType, headers: &[(&str, &str)], payload: &[u8]) -> String {
    let mut result = String::new();

    // Begin line
    result.push_str(&format!(
        "----- BEGIN RECRYPT {} -----\n",
        armor_type.label()
    ));

    // Headers
    for (key, value) in headers {
        result.push_str(&format!("{key}: {value}\n"));
    }

    // Blank line before payload
    result.push('\n');

    // Base64 payload (wrapped at 64 chars)
    let b64 = BASE64.encode(payload);
    for chunk in b64.as_bytes().chunks(64) {
        result.push_str(std::str::from_utf8(chunk).unwrap());
        result.push('\n');
    }

    // End line
    result.push_str(&format!("----- END RECRYPT {} -----\n", armor_type.label()));

    result
}

/// Decode ASCII armor to bytes
pub fn armor_decode(s: &str) -> WireResult<ArmorBlock> {
    let lines: Vec<&str> = s.lines().collect();

    // Find BEGIN line
    let begin_idx = lines
        .iter()
        .position(|l| l.starts_with("----- BEGIN RECRYPT"))
        .ok_or_else(|| WireError::ArmorParse("Missing BEGIN line".into()))?;

    // Parse armor type from BEGIN line
    let begin_line = lines[begin_idx];
    let type_str = begin_line
        .strip_prefix("----- BEGIN RECRYPT ")
        .and_then(|s| s.strip_suffix(" -----"))
        .ok_or_else(|| WireError::ArmorParse("Invalid BEGIN format".into()))?;

    let armor_type = ArmorType::from_label(type_str)
        .ok_or_else(|| WireError::ArmorParse(format!("Unknown armor type: {type_str}")))?;

    // Find END line
    let end_marker = format!("----- END RECRYPT {} -----", armor_type.label());
    let end_idx = lines
        .iter()
        .position(|l| *l == end_marker)
        .ok_or_else(|| WireError::ArmorParse("Missing END line".into()))?;

    // Parse headers (until blank line)
    let mut headers = HashMap::new();
    let mut payload_start = begin_idx + 1;

    for (i, line) in lines[begin_idx + 1..end_idx].iter().enumerate() {
        if line.is_empty() {
            payload_start = begin_idx + 1 + i + 1;
            break;
        }
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.to_string(), value.to_string());
        }
    }

    // Decode base64 payload
    let payload_b64: String = lines[payload_start..end_idx]
        .iter()
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    let payload = BASE64.decode(&payload_b64)?;

    Ok(ArmorBlock {
        armor_type,
        headers,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_roundtrip() {
        let payload = b"Hello, Recrypt!";
        let headers = [("Version", "1"), ("Algorithm", "ED25519+ML-DSA-87")];

        let armored = armor_encode(ArmorType::PublicKey, &headers, payload);
        let decoded = armor_decode(&armored).unwrap();

        assert_eq!(decoded.armor_type, ArmorType::PublicKey);
        assert_eq!(decoded.headers.get("Version"), Some(&"1".to_string()));
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_armor_long_payload() {
        let payload = vec![0u8; 1024]; // 1 KB
        let armored = armor_encode(ArmorType::Message, &[], &payload);
        let decoded = armor_decode(&armored).unwrap();

        assert_eq!(decoded.payload, payload);
    }
}
