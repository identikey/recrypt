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
}
