//! Dump the recrypt OpenAPI document to a file.
//!
//! Used to refresh the snapshot consumed by `crates/recrypt-client`'s
//! build script. Output path defaults to `crates/recrypt-client/openapi.json`
//! relative to the workspace root; pass `--out <path>` to override.
//!
//! Run via `just openapi-regen`.

use std::path::PathBuf;

use recrypt_server::openapi::ApiDoc;
use utoipa::OpenApi;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut out: Option<PathBuf> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            other => return Err(format!("unknown arg: {other}").into()),
        }
    }

    let out = out.unwrap_or_else(|| {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .parent()
            .expect("workspace root")
            .join("crates/recrypt-client/openapi.json")
    });

    let spec = ApiDoc::openapi();
    // utoipa 5 emits OpenAPI 3.1.0, but progenitor 0.10 currently parses
    // via openapiv3 (3.0.x). Downgrade the declared version so the
    // generated client compiles. Tracked as a follow-up under epic
    // recrypt-nj1; revisit once progenitor supports 3.1 or once we
    // start using 3.1-only features (e.g. tuple types, pattern
    // properties) that the empty/early specs do not.
    let mut spec_json: serde_json::Value = serde_json::to_value(&spec)?;
    if let Some(obj) = spec_json.as_object_mut() {
        obj.insert(
            "openapi".to_string(),
            serde_json::Value::String("3.0.3".to_string()),
        );
    }
    let json = serde_json::to_string_pretty(&spec_json)? + "\n";

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, json)?;
    eprintln!("wrote OpenAPI spec to {}", out.display());
    Ok(())
}
