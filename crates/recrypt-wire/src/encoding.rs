//! Text-boundary encodings, with the O(n²) footgun removed structurally.
//!
//! Implements `encoding-conventions.md` §2 and §5.1 (identikey-protocol,
//! `docs/standards/`). The rule is a size split: base58 for short stable
//! identifiers a human might copy, base64 for anything variable-length.
//!
//! ## Why this module exists rather than calling `bs58` directly
//!
//! Base58 is bignum arithmetic — **O(n²)** in the input length. Recrypt has
//! hit that three times (`recrypt-jtw`, `recrypt-fil`, `recrypt-n1e`, the last
//! being `identity show` hanging on a multi-MB key), and each fix was local to
//! one call site, which is why there was a third one. Documenting "don't
//! base58 large values" does not prevent the next occurrence; refusing to
//! compile one does.
//!
//! [`b58_encode`] and [`b58_decode`] therefore **hard-cap** at
//! [`B58_MAX_BYTES`]. Over that, they return an error naming base64 instead.
//! There is no unchecked variant. If you need to encode something bigger, it
//! is not an identifier and it belongs in base64.

use crate::error::{WireError, WireResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

/// Maximum input length for base58, per `encoding-conventions.md` §2.
///
/// 256 bytes is comfortably above every identifier in the system (32-byte
/// fingerprints, file hashes, keyspace IDs, Ed25519 keys) and far below the
/// sizes where quadratic encoding costs bite (ML-DSA-87 keys at 2.6–4.9 KB,
/// lattice PRE keys in the multi-KB-to-MB range).
pub const B58_MAX_BYTES: usize = 256;

/// Base58-encode a short stable identifier.
///
/// # Errors
///
/// Returns [`WireError::EncodingTooLarge`] if `bytes` exceeds
/// [`B58_MAX_BYTES`]. That is not a limitation to work around — it means the
/// value is not an identifier. Use [`b64_encode`].
pub fn b58_encode(bytes: &[u8]) -> WireResult<String> {
    if bytes.len() > B58_MAX_BYTES {
        return Err(WireError::EncodingTooLarge {
            len: bytes.len(),
            max: B58_MAX_BYTES,
        });
    }
    Ok(bs58::encode(bytes).into_string())
}

/// Base58-decode a short stable identifier.
///
/// The *encoded* length is checked before decoding, so a hostile caller cannot
/// spend our CPU by posting a megabyte of base58 digits. Base58 expands by
/// roughly 1.37×; the bound below is deliberately loose (2×) because rejecting
/// a legitimate identifier matters more than admitting a slightly oversized
/// one that the length check after decoding will catch anyway.
pub fn b58_decode(s: &str) -> WireResult<Vec<u8>> {
    if s.len() > B58_MAX_BYTES * 2 {
        return Err(WireError::EncodingTooLarge {
            len: s.len(),
            max: B58_MAX_BYTES * 2,
        });
    }
    bs58::decode(s)
        .into_vec()
        .map_err(|e| WireError::Encoding(format!("base58 decode failed: {e}")))
}

/// Base64-encode an opaque blob of any size.
pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Base64-decode an opaque blob.
pub fn b64_decode(s: &str) -> WireResult<Vec<u8>> {
    B64.decode(s)
        .map_err(|e| WireError::Encoding(format!("base64 decode failed: {e}")))
}

/// Encode a blob for a JSON/text boundary as `b64:<base64>`, per
/// `encoding-conventions.md` §5.1.
pub fn encode_tagged(bytes: &[u8]) -> String {
    format!("b64:{}", b64_encode(bytes))
}

/// Decode a `b64:<base64>` tagged string.
///
/// **`b64:` is the only accepted form.** The `b58:` tag and the bare
/// unprefixed string (previously "treated as base58 for pre-2026 clients")
/// were removed on 2026-08-07: nothing has shipped to production, so there is
/// no compatibility to preserve, and both were unbounded base58 decode paths
/// reachable from untrusted input with multi-KB payloads — the O(n²) case, on
/// the network edge.
///
/// The error names the required form, because a caller sending the old shape
/// needs to know what to send instead, not merely that it failed.
pub fn decode_tagged(s: &str, label: &str) -> WireResult<Vec<u8>> {
    match s.strip_prefix("b64:") {
        Some(b64) => b64_decode(b64)
            .map_err(|e| WireError::Encoding(format!("{label}: {e}"))),
        None => Err(WireError::Encoding(format!(
            "{label}: expected a `b64:<base64>` tagged string. \
             The `b58:` tag and bare base58 are no longer accepted \
             (encoding-conventions.md §5.1)."
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b58_roundtrips_a_fingerprint() {
        let fp = [7u8; 32];
        let s = b58_encode(&fp).unwrap();
        assert_eq!(b58_decode(&s).unwrap(), fp);
    }

    #[test]
    fn b58_accepts_exactly_the_cap() {
        let bytes = vec![1u8; B58_MAX_BYTES];
        assert!(b58_encode(&bytes).is_ok());
    }

    #[test]
    fn b58_refuses_an_ml_dsa_secret_key() {
        // 4896 B. The exact shape of recrypt-n1e: this used to encode, slowly.
        let key = vec![0xABu8; 4896];
        let err = b58_encode(&key).unwrap_err();
        assert!(
            matches!(err, WireError::EncodingTooLarge { .. }),
            "expected EncodingTooLarge, got {err:?}"
        );
    }

    #[test]
    fn b58_decode_refuses_an_oversized_string() {
        let huge = "1".repeat(B58_MAX_BYTES * 2 + 1);
        assert!(matches!(
            b58_decode(&huge).unwrap_err(),
            WireError::EncodingTooLarge { .. }
        ));
    }

    #[test]
    fn tagged_roundtrips_a_multi_kb_blob() {
        let blob = vec![0x5Au8; 4896];
        let s = encode_tagged(&blob);
        assert!(s.starts_with("b64:"));
        assert_eq!(decode_tagged(&s, "blob").unwrap(), blob);
    }

    #[test]
    fn tagged_rejects_the_removed_b58_form() {
        let s = format!("b58:{}", bs58::encode([1u8; 32]).into_string());
        let err = decode_tagged(&s, "key").unwrap_err();
        assert!(
            err.to_string().contains("b64:<base64>"),
            "error must name the required form, got: {err}"
        );
    }

    #[test]
    fn tagged_rejects_bare_strings() {
        let s = bs58::encode([1u8; 32]).into_string();
        assert!(decode_tagged(&s, "key").is_err());
    }
}
