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
    // via openapiv3 (3.0.x). Downgrade the declared version *and* rewrite
    // the 3.1-only constructs that show up at our scale:
    //   "type": ["X", "null"]  →  "type": "X", "nullable": true
    // Tracked under recrypt-gym; replace with a real transformer (or wait
    // for progenitor 3.1) when we hit other 3.1-only features.
    let mut spec_json: serde_json::Value = serde_json::to_value(&spec)?;
    if let Some(obj) = spec_json.as_object_mut() {
        obj.insert(
            "openapi".to_string(),
            serde_json::Value::String("3.0.3".to_string()),
        );
    }
    rewrite_nullable_arrays(&mut spec_json);
    let json = serde_json::to_string_pretty(&spec_json)? + "\n";

    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, json)?;
    eprintln!("wrote OpenAPI spec to {}", out.display());
    Ok(())
}

/// Walk the spec and convert OpenAPI 3.1 `"type": ["X", "null"]` arrays
/// into 3.0's `"type": "X", "nullable": true` shape. Operates in place.
fn rewrite_nullable_arrays(value: &mut serde_json::Value) {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            // First, transform the local `type` field if it's the nullable-array form.
            if let Some(Value::Array(arr)) = map.get("type").cloned() {
                let strs: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                if strs.len() == 2 && strs.iter().any(|s| s == "null") {
                    let primary = strs.into_iter().find(|s| s != "null").unwrap();
                    map.insert("type".into(), Value::String(primary));
                    map.insert("nullable".into(), Value::Bool(true));
                }
            }
            for (_, v) in map.iter_mut() {
                rewrite_nullable_arrays(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                rewrite_nullable_arrays(v);
            }
        }
        _ => {}
    }
}
