//! # recrypt-core: Production Cryptography for Proxy Recryption
//!
//! This crate provides production-ready cryptographic operations for the Recrypt
//! proxy recryption system.
//!
//! ## Features
//!
//! - **Pluggable PRE backends**: Lattice (post-quantum) or Mock (testing)
//! - **Hybrid encryption**: KEM-DEM with XChaCha20 + Bao streaming verification
//! - **Multi-signatures**: ED25519 + ML-DSA-87 for classical + post-quantum security
//! - **Metadata confidentiality**: Plaintext hashes encrypted inside wrapped keys
//!
//! ## Example: Basic Encryption
//!
//! ```rust
//! use recrypt_core::{HybridEncryptor, PreBackend, pre::backends::MockBackend};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = MockBackend;
//! let encryptor = HybridEncryptor::new(backend);
//!
//! // Generate keypair
//! let kp = encryptor.backend().generate_keypair()?;
//!
//! // Encrypt
//! let plaintext = b"Hello, Recrypt!";
//! let encrypted = encryptor.encrypt(&kp.public, plaintext)?;
//!
//! // Decrypt
//! let decrypted = encryptor.decrypt(&kp.secret, &encrypted)?;
//! assert_eq!(&decrypted[..], plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ## Example: Proxy Recryption
//!
//! ```rust
//! use recrypt_core::{HybridEncryptor, PreBackend, pre::backends::MockBackend};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = MockBackend;
//! let encryptor = HybridEncryptor::new(backend);
//!
//! // Alice and Bob generate keys
//! let alice = encryptor.backend().generate_keypair()?;
//! let bob = encryptor.backend().generate_keypair()?;
//!
//! // Alice encrypts for herself
//! let plaintext = b"Secret message";
//! let encrypted_alice = encryptor.encrypt(&alice.public, plaintext)?;
//!
//! // Alice generates recryption key for Bob
//! let rk = encryptor.backend().generate_recrypt_key(&alice.secret, &bob.public)?;
//!
//! // Proxy transforms (no access to plaintext!)
//! let encrypted_bob = encryptor.recrypt(&rk, &encrypted_alice)?;
//!
//! // Bob decrypts
//! let decrypted = encryptor.decrypt(&bob.secret, &encrypted_bob)?;
//! assert_eq!(&decrypted[..], plaintext);
//! # Ok(())
//! # }
//! ```
//!
//! ## Non-Determinism
//!
//! Cryptographic operations are intentionally non-deterministic:
//! - Ciphertexts differ on every encryption (randomness)
//! - Serialized keys may differ (OpenFHE non-canonical serialization)
//!
//! **Test semantic correctness**, not byte equality. See `docs/non-determinism.md`.
//!
//! ## Architecture
//!
//! See design documents in `docs/`:
//! - `hybrid-encryption-architecture.md` - KEM-DEM design
//! - `pre-backend-traits.md` - Backend trait hierarchy
//! - `non-determinism.md` - Testing strategy

pub mod error;
pub mod hybrid;
pub mod pre;
pub mod sign;

// Re-exports for convenience
pub use error::{CoreError, CoreResult};
pub use hybrid::{EncryptedFile, HybridEncryptor, KeyMaterial};
pub use pre::{Ciphertext, KeyPair, PreBackend, PublicKey, RecryptKey, SecretKey};
pub use sign::{MultiSig, SigningKeys, VerifyPolicy, VerifyingKeys};
