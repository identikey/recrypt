//! recrypt-wire: Wire protocol and serialization formats
//!
//! Provides:
//! - Gordian Envelope serialization (primary wire format, dCBOR)
//! - ASCII armor (human-readable export)
//!
//! ## Format Selection
//!
//! | Format          | Use Case                    | Size Overhead |
//! |-----------------|-----------------------------|--------------:|
//! | Envelope (dCBOR)| Wire, storage               |          ~1%  |
//! | ASCII Armor     | Key export, manual backup   |         ~35%  |
//!
//! See docs/wire-protocol.md for the full specification.

pub mod armor;
pub mod convert;
pub mod error;
pub mod format;
pub mod impls;

pub use armor::{ArmorType, armor_decode, armor_encode};
pub use error::{WireError, WireResult};
pub use format::{Format, MultiFormat, detect_format};
