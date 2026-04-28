//! Generated Rust HTTP client for the recrypt proxy API.
//!
//! The contents of this crate are produced at build time by progenitor
//! from `openapi.json`, which is itself produced by
//! `recrypt-server`'s `dump-openapi` binary. The single source of
//! truth is the utoipa-annotated handlers in `recrypt-server`; see
//! epic recrypt-nj1.
//!
//! To refresh after a server-side schema change:
//!
//! ```sh
//! just openapi-regen
//! ```

include!(concat!(env!("OUT_DIR"), "/codegen.rs"));
