//! Key material bundle: the 96-byte plaintext that the PRE layer encrypts.
//!
//! # Format
//!
//! KeyMaterial is **not CBOR**. It is a versioned, fixed-size byte layout
//! sized to fit exactly within one OpenFHE BFV plaintext slot (96 bytes —
//! see [`crate::pre::backends::lattice::LatticeBackend::max_plaintext_size`]).
//! Adding CBOR framing would push the encoding past the slot capacity.
//!
//! The first byte is a **version discriminator**. The remaining 95 bytes are
//! interpreted differently per version. Unknown versions MUST be rejected.
//! This is the entire forward-compatibility story for KeyMaterial.
//!
//! ## v1 layout (current, 96 bytes total)
//!
//! ```text
//! [0]      version          = 1   (u8)
//! [1..33]  symmetric_key    = XChaCha20 256-bit key (32 bytes)
//! [33..57] nonce            = XChaCha20 192-bit nonce (24 bytes)
//! [57..89] plaintext_hash   = Blake3 of original plaintext (32 bytes)
//! [89..96] plaintext_size   = u56 little-endian, max 2^56 = 72 PB (7 bytes)
//! ```
//!
//! Total: 96 bytes exactly.
//!
//! ## Why u56 for plaintext_size
//!
//! The full u64 would not fit alongside the version byte. u56 caps the
//! representable plaintext size at 72 petabytes, which is wildly larger
//! than [`MAX_ENCRYPT_FILE_SIZE`](crate::hybrid::MAX_ENCRYPT_FILE_SIZE)
//! (currently 1 TiB). Encoders MUST reject any plaintext size that does
//! not fit in u56 with a clear error; in practice this is unreachable
//! because the streaming encrypt path enforces a much smaller limit.
//!
//! ## Why plaintext_size lives both here and on the file envelope
//!
//! The file envelope carries `plaintext-size` as a salted, elidable
//! assertion (see [wire-protocol.md §3.1](../../../docs/wire-protocol.md)).
//! That copy is for UX and may be elided for privacy.
//!
//! This copy is **inside the PRE encryption** and is never exposed to
//! anyone except the recipient who can decrypt the wrapped key. It exists
//! so the decryption code path can sanity-check the plaintext size after
//! XChaCha20 decryption without depending on any envelope assertion that
//! a malicious proxy might have stripped or tampered with. The
//! plaintext_hash already covers integrity, but the size check fails
//! faster on truncation attacks.
//!
//! ## Why not CBOR
//!
//! We did the math. Even with integer-keyed dCBOR (the most aggressive
//! encoding), the framing overhead pushes the smallest possible encoding
//! past 96 bytes once the three 32-byte fields are accounted for. The
//! version-byte approach is ~15 bytes more efficient than CBOR while
//! preserving the only property we wanted from CBOR (extensibility),
//! and it's simpler to parse: one byte then a match.
//!
//! ## Version evolution
//!
//! To define v2:
//!
//! 1. Choose a new layout for bytes [1..96].
//! 2. Add a `V2` variant to a `KeyMaterialVersion` enum here.
//! 3. Update `from_bytes` to dispatch on the version byte.
//! 4. Bump `recrypt.encrypted-file` envelope `format-version` and document
//!    which KeyMaterial versions are valid for which envelope versions.
//!
//! Old encryptors continue producing v1; old decryptors continue parsing
//! v1; v2 is opt-in for new files. There is no in-place migration.

use crate::error::PreError;

/// Key material bundle: 96-byte fixed plaintext before PRE encryption.
///
/// See module docs for the wire format and version policy.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    /// XChaCha20 symmetric key (256-bit)
    pub symmetric_key: [u8; 32],
    /// XChaCha20 extended nonce (192-bit for birthday-safe random generation)
    pub nonce: [u8; 24],
    /// Blake3 hash of original plaintext (encrypted for confidentiality!)
    pub plaintext_hash: [u8; 32],
    /// Original plaintext size in bytes. Stored as u56 on the wire — values
    /// must satisfy `plaintext_size < 2^56` (~72 PB, wildly larger than
    /// `MAX_ENCRYPT_FILE_SIZE`).
    pub plaintext_size: u64,
}

impl KeyMaterial {
    /// Total serialized size: 1 version byte + 32 + 24 + 32 + 7.
    pub const SERIALIZED_SIZE: usize = 96;

    /// Current format version. Encoders always emit this; decoders accept
    /// only known versions.
    pub const CURRENT_VERSION: u8 = 1;

    /// Maximum representable plaintext size (2^56 - 1 bytes ≈ 72 PB).
    pub const MAX_PLAINTEXT_SIZE: u64 = (1u64 << 56) - 1;

    pub fn to_bytes(&self) -> Result<[u8; Self::SERIALIZED_SIZE], PreError> {
        if self.plaintext_size > Self::MAX_PLAINTEXT_SIZE {
            return Err(PreError::Serialization(format!(
                "plaintext_size {} exceeds u56 max ({})",
                self.plaintext_size,
                Self::MAX_PLAINTEXT_SIZE
            )));
        }
        let mut out = [0u8; Self::SERIALIZED_SIZE];
        out[0] = Self::CURRENT_VERSION;
        out[1..33].copy_from_slice(&self.symmetric_key);
        out[33..57].copy_from_slice(&self.nonce);
        out[57..89].copy_from_slice(&self.plaintext_hash);
        // u56 little-endian: write the low 7 bytes of u64.
        let size_bytes = self.plaintext_size.to_le_bytes();
        out[89..96].copy_from_slice(&size_bytes[0..7]);
        Ok(out)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PreError> {
        if bytes.len() != Self::SERIALIZED_SIZE {
            return Err(PreError::Deserialization(format!(
                "Invalid key material size: {} != {}",
                bytes.len(),
                Self::SERIALIZED_SIZE
            )));
        }
        let version = bytes[0];
        if version != Self::CURRENT_VERSION {
            return Err(PreError::Deserialization(format!(
                "Unknown KeyMaterial version: {} (this build supports {})",
                version,
                Self::CURRENT_VERSION
            )));
        }
        // Reconstruct u56 → u64 by zero-extending the high byte.
        let mut size_bytes = [0u8; 8];
        size_bytes[0..7].copy_from_slice(&bytes[89..96]);
        let plaintext_size = u64::from_le_bytes(size_bytes);

        Ok(Self {
            symmetric_key: bytes[1..33].try_into().unwrap(),
            nonce: bytes[33..57].try_into().unwrap(),
            plaintext_hash: bytes[57..89].try_into().unwrap(),
            plaintext_size,
        })
    }
}
