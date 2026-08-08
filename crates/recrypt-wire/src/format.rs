//! Multi-format serialization: Gordian Envelope bytes, UR, and legacy armor.

use crate::error::{WireError, WireResult};
use bc_envelope::prelude::*;
use std::sync::Once;

static REGISTER_TAGS: Once = Once::new();

/// Ensure the global CBOR tag registry knows the Gordian tags.
///
/// UR encoding looks up a *name* for CBOR tag 200 (envelope) and **panics**
/// with "CBOR tag 200 must have a name. Did you call `register_tags()`?" if the
/// registry is empty. The registry is process-global and idempotent, so a
/// library must not leave this to callers: the failure is a panic, it only
/// appears on the UR path, and a consumer who never calls it gets a crash in
/// what looks like our code.
fn ensure_tags_registered() {
    REGISTER_TAGS.call_once(bc_envelope::register_tags);
}

/// Detected serialization format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Envelope,
    /// `ur:envelope/…` — the canonical text form (encoding-conventions.md §7).
    Ur,
    /// PEM-style armor block. Legacy; readable, never emitted by new code.
    Armor,
}

/// Detect format from raw bytes
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(b"----- BEGIN RECRYPT") {
        Format::Armor
    } else if data.starts_with(b"ur:") || data.starts_with(b"UR:") {
        Format::Ur
    } else {
        Format::Envelope
    }
}

/// Encode raw Gordian Envelope dCBOR bytes as `ur:envelope/<bytewords>`.
///
/// Works on ANY envelope, including a signed (wrap-then-sign) one. That
/// distinction matters: a signed export is a wrapper whose subject is the
/// original envelope, so it does not parse back into the inner type — going
/// through [`MultiFormat::to_ur`] would fail with "the envelope's subject is
/// not a leaf". Use this whenever you already hold envelope bytes and just
/// want them as text.
pub fn ur_from_envelope_bytes(bytes: &[u8]) -> WireResult<String> {
    ensure_tags_registered();
    let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
        .map_err(|e| WireError::Envelope(format!("parse envelope for UR: {e}")))?;
    Ok(envelope.ur_string())
}

/// Decode `ur:envelope/<bytewords>` back to raw Gordian Envelope dCBOR bytes.
pub fn envelope_bytes_from_ur(s: &str) -> WireResult<Vec<u8>> {
    ensure_tags_registered();
    let envelope = Envelope::from_ur_string(s.trim())
        .map_err(|e| WireError::Envelope(format!("parse UR: {e}")))?;
    Ok(envelope.to_cbor_data())
}

/// Trait for types that can be serialized to Gordian Envelope + ASCII armor.
pub trait MultiFormat: Sized {
    /// Envelope type name (for debugging and error messages)
    fn envelope_type() -> &'static str;

    /// Serialize to Gordian Envelope (dCBOR bytes)
    fn to_envelope(&self) -> WireResult<Vec<u8>>;

    /// Deserialize from Gordian Envelope (dCBOR bytes)
    fn from_envelope(bytes: &[u8]) -> WireResult<Self>;

    /// Serialize to a UR — `ur:envelope/<bytewords>`.
    ///
    /// The canonical text form for a whole envelope, per
    /// `encoding-conventions.md` §7 (identikey-protocol). Prefer this over
    /// [`to_armor`](Self::to_armor) everywhere.
    ///
    /// Provided, not required: it is derived from [`to_envelope`](Self::to_envelope),
    /// so every implementor gets it without writing anything. `bc-ur` blanket-
    /// implements `UREncodable` for `CBORTaggedEncodable`, and `Envelope`
    /// implements that — this has been available in every binary linking
    /// `bc-components` all along.
    ///
    /// The UR type is the standard `envelope`, never a per-app type: the
    /// envelope's own subject carries what it is, and a custom UR type would
    /// be unreadable to every tool in the Gordian ecosystem.
    fn to_ur(&self) -> WireResult<String> {
        ensure_tags_registered();
        let bytes = self.to_envelope()?;
        let envelope = Envelope::try_from_cbor_data(bytes)
            .map_err(|e| WireError::Envelope(format!("re-parse for UR: {e}")))?;
        Ok(envelope.ur_string())
    }

    /// Parse a `ur:envelope/…` string.
    fn from_ur(s: &str) -> WireResult<Self> {
        ensure_tags_registered();
        let envelope = Envelope::from_ur_string(s.trim())
            .map_err(|e| WireError::Envelope(format!("parse UR: {e}")))?;
        Self::from_envelope(&envelope.to_cbor_data())
    }

    /// Serialize to ASCII armor.
    ///
    /// **Legacy.** Superseded by [`to_ur`](Self::to_ur) on 2026-08-07; kept so
    /// existing blocks stay readable. See `encoding-conventions.md` §6.
    fn to_armor(&self) -> WireResult<String>;

    /// Deserialize from ASCII armor
    fn from_armor(s: &str) -> WireResult<Self>;

    /// Deserialize from any format (auto-detect)
    fn from_any(data: &[u8]) -> WireResult<Self> {
        match detect_format(data) {
            Format::Envelope => Self::from_envelope(data),
            Format::Ur => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| WireError::InvalidFormat(format!("UR is not utf-8: {e}")))?;
                Self::from_ur(s)
            }
            Format::Armor => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| WireError::InvalidFormat(e.to_string()))?;
                Self::from_armor(s)
            }
        }
    }
}
