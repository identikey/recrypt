//! recrypt-proto: Wire protocol and serialization formats
//!
//! Provides:
//! - Protobuf serialization (primary wire format)
//! - ASCII armor (human-readable export)
//! - JSON (debugging, API responses)
//!
//! ## Format Selection
//!
//! | Format      | Use Case                    | Size Overhead |
//! |-------------|-----------------------------|--------------:|
//! | Protobuf    | Wire, storage               |        ~0.1%  |
//! | JSON        | Debug, API                  |        ~0.5%  |
//! | ASCII Armor | Key export, manual backup   |         ~35%  |

pub mod armor;
pub mod convert;
pub mod error;
pub mod format;
pub mod impls;

mod generated;

pub use armor::{ArmorType, armor_decode, armor_encode};
pub use error::{ProtoError, ProtoResult};
pub use format::{Format, MultiFormat, detect_format};
pub use generated::recrypt::v1 as proto;
