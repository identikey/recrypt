//! Multi-format serialization support (Gordian Envelope + ASCII armor)

use crate::error::{WireError, WireResult};

/// Detected serialization format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Envelope,
    Armor,
}

/// Detect format from raw bytes
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(b"----- BEGIN RECRYPT") {
        Format::Armor
    } else {
        Format::Envelope
    }
}

/// Trait for types that can be serialized to Gordian Envelope + ASCII armor.
pub trait MultiFormat: Sized {
    /// Envelope type name (for debugging and error messages)
    fn envelope_type() -> &'static str;

    /// Serialize to Gordian Envelope (dCBOR bytes)
    fn to_envelope(&self) -> WireResult<Vec<u8>>;

    /// Deserialize from Gordian Envelope (dCBOR bytes)
    fn from_envelope(bytes: &[u8]) -> WireResult<Self>;

    /// Serialize to ASCII armor
    fn to_armor(&self) -> WireResult<String>;

    /// Deserialize from ASCII armor
    fn from_armor(s: &str) -> WireResult<Self>;

    /// Deserialize from any format (auto-detect)
    fn from_any(data: &[u8]) -> WireResult<Self> {
        match detect_format(data) {
            Format::Envelope => Self::from_envelope(data),
            Format::Armor => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| WireError::InvalidFormat(e.to_string()))?;
                Self::from_armor(s)
            }
        }
    }
}
