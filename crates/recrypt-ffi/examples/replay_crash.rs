//! Replay a fuzz crash artifact through deserialize_public_key in a normal
//! (non-sanitized) build to observe production behavior. Usage:
//!   cargo run -p recrypt-ffi --example replay_crash -- /path/to/crash.bin

use recrypt_ffi::openfhe::PreContext;
use std::env;
use std::fs;

fn main() {
    let path = env::args().nth(1).expect("usage: replay_crash <file>");
    let data = fs::read(&path).expect("read crash file");
    let ctx = PreContext::new().expect("create PreContext");
    println!("input: {} bytes", data.len());
    match ctx.deserialize_public_key(&data) {
        Ok(_) => println!("RESULT: Ok (parsed)"),
        Err(e) => println!("RESULT: Err({e})"),
    }
    println!("survived: process did not abort");
}
