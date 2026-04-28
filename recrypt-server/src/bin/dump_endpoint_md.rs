//! Render a single OpenAPI endpoint as a Markdown chunk and splice it
//! into a target document between marker comments.
//!
//! Usage:
//!
//! ```sh
//! dump_endpoint_md \
//!     --spec crates/recrypt-client/openapi.json \
//!     --doc  docs/http-api-reference.md \
//!     --path /accounts \
//!     --method POST
//! ```
//!
//! The target document MUST contain a marker pair like:
//!
//! ```text
//! <!-- BEGIN GENERATED: POST /accounts -->
//! ...anything in here is replaced...
//! <!-- END GENERATED: POST /accounts -->
//! ```
//!
//! Used by `just openapi-regen`.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

#[derive(Default)]
struct Args {
    spec: Option<PathBuf>,
    doc: Option<PathBuf>,
    path: Option<String>,
    method: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--spec" => args.spec = it.next().map(PathBuf::from),
            "--doc" => args.doc = it.next().map(PathBuf::from),
            "--path" => args.path = it.next(),
            "--method" => args.method = it.next().map(|s| s.to_uppercase()),
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(args)
}

fn render(spec: &Value, path: &str, method: &str) -> Result<String, String> {
    let op = spec
        .pointer(&format!("/paths/{}/{}", path.replace('/', "~1"), method.to_lowercase()))
        .ok_or_else(|| format!("operation {method} {path} not found in spec"))?;

    let summary = op.get("summary").and_then(Value::as_str).unwrap_or("");
    let description = op.get("description").and_then(Value::as_str).unwrap_or("");

    let mut out = String::new();
    out.push_str(&format!("#### `{method} {path}` — {summary}\n\n"));
    if !description.is_empty() {
        out.push_str(description);
        out.push_str("\n\n");
    }

    if let Some(body) = op.get("requestBody") {
        out.push_str("**Request body** (`application/json`):\n\n");
        let schema_ref = body
            .pointer("/content/application~1json/schema/$ref")
            .and_then(Value::as_str);
        if let Some(r) = schema_ref {
            out.push_str(&render_schema_table(spec, r)?);
            out.push('\n');
        }
    }

    if let Some(responses) = op.get("responses").and_then(Value::as_object) {
        out.push_str("**Responses:**\n\n");
        out.push_str("| Status | Description | Body |\n|---|---|---|\n");
        // BTreeMap to keep status codes sorted.
        let sorted: BTreeMap<_, _> = responses.iter().collect();
        for (status, resp) in sorted {
            let desc = resp.get("description").and_then(Value::as_str).unwrap_or("");
            let body = resp
                .pointer("/content/application~1json/schema/$ref")
                .and_then(Value::as_str)
                .map(|r| format!("`{}`", r.rsplit('/').next().unwrap_or(r)))
                .unwrap_or_else(|| "—".to_string());
            out.push_str(&format!("| {status} | {desc} | {body} |\n"));
        }
        out.push('\n');
    }

    out.push_str("> Generated from `openapi.json` — do not edit by hand. Run `just openapi-regen`.\n");
    Ok(out)
}

fn render_schema_table(spec: &Value, schema_ref: &str) -> Result<String, String> {
    let name = schema_ref
        .strip_prefix("#/components/schemas/")
        .ok_or_else(|| format!("unsupported schema ref: {schema_ref}"))?;
    let schema = spec
        .pointer(&format!("/components/schemas/{name}"))
        .ok_or_else(|| format!("schema {name} not found"))?;

    let required: std::collections::BTreeSet<String> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    let mut out = String::new();
    out.push_str(&format!("Schema: `{name}`\n\n"));
    out.push_str("| Field | Type | Required | Description |\n|---|---|---|---|\n");
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("schema {name} has no properties"))?;
    let sorted: BTreeMap<_, _> = props.iter().collect();
    for (field, prop) in sorted {
        let ty = prop.get("type").and_then(Value::as_str).unwrap_or("?");
        let desc = prop
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("")
            .replace('\n', " ");
        let req = if required.contains(field) { "yes" } else { "no" };
        out.push_str(&format!("| `{field}` | {ty} | {req} | {desc} |\n"));
    }
    Ok(out)
}

fn splice(doc: &str, method: &str, path: &str, generated: &str) -> Result<String, String> {
    let begin = format!("<!-- BEGIN GENERATED: {method} {path} -->");
    let end = format!("<!-- END GENERATED: {method} {path} -->");
    let begin_idx = doc
        .find(&begin)
        .ok_or_else(|| format!("missing marker `{begin}` in doc"))?;
    let end_idx = doc
        .find(&end)
        .ok_or_else(|| format!("missing marker `{end}` in doc"))?;
    if end_idx < begin_idx {
        return Err(format!("end marker precedes begin marker for {method} {path}"));
    }

    let prefix_end = begin_idx + begin.len();
    let mut out = String::with_capacity(doc.len() + generated.len());
    out.push_str(&doc[..prefix_end]);
    out.push('\n');
    out.push_str(generated);
    out.push_str(&doc[end_idx..]);
    Ok(out)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;
    let spec_path = args.spec.ok_or("--spec is required")?;
    let doc_path = args.doc.ok_or("--doc is required")?;
    let path = args.path.ok_or("--path is required")?;
    let method = args.method.ok_or("--method is required")?;

    let spec: Value = serde_json::from_slice(&fs::read(&spec_path)?)?;
    let generated = render(&spec, &path, &method)?;

    let doc = fs::read_to_string(&doc_path)?;
    let new_doc = splice(&doc, &method, &path, &generated)?;
    fs::write(&doc_path, new_doc)?;
    eprintln!(
        "rewrote `{method} {path}` section in {}",
        doc_path.display()
    );
    Ok(())
}
