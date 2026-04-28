//! Coefficient conversion utilities for PRE
//!
//! BFV with `plaintext_modulus = 65537` packs slots in the signed centered
//! range `[-(p-1)/2, (p-1)/2] = [-32768, 32768]`. Encoding byte pairs as
//! unsigned `u16` (range `0..=65535`) overflows that window: any coefficient
//! `V > 32768` is folded to `V - 65537` on decryption, which surfaces as an
//! off-by-one bit corruption when reinterpreted as `u16`. Encoding as signed
//! `i16` keeps every value inside the slot range, so the full 16 bits per
//! coefficient round-trip exactly. (See recrypt-fwg.)

/// Convert bytes to BFV coefficients.
///
/// Each pair of bytes becomes one signed coefficient via `i16::from_le_bytes`.
/// A trailing odd byte is encoded as a single positive value in `0..=255`.
pub fn bytes_to_coefficients(data: &[u8]) -> Vec<i64> {
    data.chunks(2)
        .map(|chunk| {
            if chunk.len() == 2 {
                i16::from_le_bytes([chunk[0], chunk[1]]) as i64
            } else {
                chunk[0] as i64
            }
        })
        .collect()
}

/// Convert coefficients back to bytes.
///
/// Each coefficient is truncated to its low 16 bits via `as i16` and emitted
/// as two little-endian bytes. The result is truncated to `original_len`.
pub fn coefficients_to_bytes(coeffs: &[i64], original_len: usize) -> Vec<u8> {
    let bytes: Vec<u8> = coeffs
        .iter()
        .flat_map(|&c| (c as i16).to_le_bytes())
        .collect();

    bytes.into_iter().take(original_len).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_even() {
        let original = b"Hello!";
        let coeffs = bytes_to_coefficients(original);
        let recovered = coefficients_to_bytes(&coeffs, original.len());
        assert_eq!(&recovered, original);
    }

    #[test]
    fn test_roundtrip_odd() {
        let original = b"Hello";
        let coeffs = bytes_to_coefficients(original);
        let recovered = coefficients_to_bytes(&coeffs, original.len());
        assert_eq!(&recovered, original);
    }

    #[test]
    fn test_roundtrip_high_bytes() {
        // Bytes that produce coefficients above (p-1)/2 = 32768 used to
        // come back off-by-one through the unsigned u16 path. With signed
        // i16 encoding every byte must round-trip exactly.
        let original: Vec<u8> = (0u8..=255u8).collect();
        let coeffs = bytes_to_coefficients(&original);
        let recovered = coefficients_to_bytes(&coeffs, original.len());
        assert_eq!(recovered, original);
    }
}
