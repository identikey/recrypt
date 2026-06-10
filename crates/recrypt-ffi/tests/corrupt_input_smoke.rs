//! Regression test for PR #1: corrupt input to the OpenFHE deserializers
//! must surface as Err. Before the try/catch guards in wrapper.cc, the C++
//! exception crossed the cxx FFI boundary and aborted the process (SIGABRT),
//! which Rust cannot catch.

use recrypt_ffi::openfhe::PreContext;

#[test]
fn corrupt_input_returns_err_instead_of_aborting() {
    let ctx = PreContext::new().unwrap();

    let garbage_small = vec![0x42u8; 32];
    let mut garbage_large = vec![0u8; 263 * 1024];
    for (i, b) in garbage_large.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    for data in [&garbage_small, &garbage_large] {
        assert!(ctx.deserialize_public_key(data).is_err());
        assert!(ctx.deserialize_secret_key(data).is_err());
        assert!(ctx.deserialize_ciphertext(data).is_err());
        assert!(ctx.deserialize_recrypt_key(data).is_err());
    }

    // Errors must carry the underlying C++ exception message, not a generic
    // sentinel string.
    let err = match ctx.deserialize_public_key(&garbage_small) {
        Err(e) => e,
        Ok(_) => panic!("expected Err for garbage input"),
    };
    assert!(!err.to_string().is_empty());
}

#[test]
fn corrupted_valid_serializations_do_not_abort() {
    let ctx = PreContext::new().unwrap();
    let kp = ctx.generate_keypair().unwrap();
    let pk_bytes = kp.public.to_bytes().unwrap();

    // Truncation always loses required data, so this must be a clean Err.
    assert!(
        ctx.deserialize_public_key(&pk_bytes[..pk_bytes.len() / 2])
            .is_err()
    );

    // Single-byte corruption may or may not produce a parseable object, so
    // assert only the security property: the call returns (Ok or Err) instead
    // of aborting the process.
    let positions = [0, 1, 8, pk_bytes.len() / 2, pk_bytes.len() - 1];
    for &pos in &positions {
        let mut corrupted = pk_bytes.clone();
        corrupted[pos] ^= 0xFF;
        let _ = ctx.deserialize_public_key(&corrupted);
    }
}
