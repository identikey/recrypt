//! Generate the recrypt HTTP client from the OpenAPI snapshot.
//!
//! Reads `openapi.json` (committed alongside this crate, refreshed
//! via `just openapi-regen`) and writes the generated client to
//! `$OUT_DIR/codegen.rs`, which `lib.rs` includes.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let spec_path = manifest_dir.join("openapi.json");

    println!("cargo:rerun-if-changed=openapi.json");
    println!("cargo:rerun-if-changed=build.rs");

    let spec_bytes = fs::read(&spec_path).unwrap_or_else(|e| {
        panic!(
            "failed to read OpenAPI snapshot at {}: {e}\n\
             Run `just openapi-regen` from the workspace root.",
            spec_path.display()
        )
    });

    let spec: openapiv3::OpenAPI = serde_json::from_slice(&spec_bytes)
        .expect("openapi.json is not a valid OpenAPI 3.x document");

    let mut generator = progenitor::Generator::default();
    let tokens = generator
        .generate_tokens(&spec)
        .expect("progenitor codegen failed");

    let ast: syn::File = syn::parse2(tokens).expect("progenitor produced invalid Rust");
    let formatted = prettyplease::unparse(&ast);

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    fs::write(out_dir.join("codegen.rs"), formatted).expect("write codegen.rs");
}
