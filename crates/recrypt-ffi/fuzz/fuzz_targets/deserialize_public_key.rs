//! Fuzz OpenFHE public key deserialization: any input must return Ok/Err,
//! never abort the process.

#![no_main]

use libfuzzer_sys::fuzz_target;
use recrypt_ffi::openfhe::PreContext;
use std::sync::OnceLock;

static CTX: OnceLock<PreContext> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let ctx = CTX.get_or_init(|| PreContext::new().expect("create PreContext"));
    let _ = ctx.deserialize_public_key(data);
});
