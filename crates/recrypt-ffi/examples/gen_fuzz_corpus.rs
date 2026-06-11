//! Generate seed corpus for the fuzz targets in fuzz/.
//!
//! Writes one valid serialization per deserialize_* target so the fuzzer
//! mutates from structurally-valid inputs instead of discovering the cereal
//! framing from scratch. Run via `just fuzz-corpus`.

use recrypt_ffi::openfhe::PreContext;
use std::fs;
use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");

    let ctx = PreContext::new().expect("create PreContext");
    let alice = ctx.generate_keypair().expect("keygen");
    let bob = ctx.generate_keypair().expect("keygen");
    let ct = ctx
        .encrypt(&alice.public, b"seed corpus plaintext")
        .expect("encrypt");
    let rk = ctx
        .generate_recrypt_key(&alice.secret, &bob.public)
        .expect("recrypt keygen");

    let seeds: [(&str, Vec<u8>); 4] = [
        ("deserialize_public_key", alice.public.to_bytes().expect("ser")),
        ("deserialize_private_key", alice.secret.to_bytes().expect("ser")),
        ("deserialize_ciphertext", ct[0].to_bytes().expect("ser")),
        ("deserialize_recrypt_key", rk.to_bytes().expect("ser")),
    ];

    for (target, bytes) in seeds {
        let dir = root.join(target);
        fs::create_dir_all(&dir).expect("create corpus dir");
        fs::write(dir.join("valid"), &bytes).expect("write seed");
        println!("wrote {target}/valid ({} bytes)", bytes.len());
    }
}
