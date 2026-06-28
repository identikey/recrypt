//! Hardware-enclave [`Signer`](crate::signer::Signer) backends (§8 of the protocol spec).
//!
//! Each platform module provides a signer whose private key lives in a hardware element
//! and whose use is gated by a biometric. The protocol's `Signer` trait is the only
//! integration surface, so the wire format and verification are identical to the
//! software signer.
//!
//! Currently implemented: macOS Secure Enclave (P-256) + Touch ID. Windows (TPM/Hello)
//! and Linux (TPM 2.0) backends are tracked separately.

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub use macos::{SecureEnclaveEd25519Signer, SecureEnclaveSigner};
#[cfg(target_os = "windows")]
pub use windows::TpmSigner;
#[cfg(target_os = "linux")]
pub use linux::TpmSigner;
