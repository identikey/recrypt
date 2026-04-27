use anyhow::{Context as _, Result};
use base64::Engine;
use clap::{Subcommand, ValueEnum};
use colored::Colorize;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, instrument};

use recrypt_core::pre::PreBackend;
use recrypt_ffi::ed25519;
use recrypt_ffi::liboqs::{pq_keygen, PqAlgorithm};

use super::Context;
use crate::config::Config;
use crate::output::{print_info, print_json, print_success};
use crate::wallet::{write_secret_file, Identity, KeyPair, Wallet};

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum ExportFormat {
    #[default]
    Envelope,
    Json,
}

#[derive(Subcommand)]
pub enum IdentityCommand {
    /// Create a new identity
    New {
        /// Name for the identity
        #[arg(long)]
        name: Option<String>,
    },
    /// List all identities
    List,
    /// Show identity details
    Show {
        /// Identity name
        #[arg(long)]
        name: Option<String>,
    },
    /// Set active identity
    Use {
        /// Identity name
        name: String,
    },
    /// Delete an identity
    Delete {
        /// Identity name
        name: String,
    },
    /// Export an identity
    Export {
        /// Identity name
        name: String,
        /// Output file
        #[arg(long)]
        output: String,
        /// Output format: envelope (default) or json
        #[arg(long, value_enum, default_value = "envelope")]
        format: ExportFormat,
    },
    /// Import an identity
    Import {
        /// Input file
        file: String,
        /// Name for imported identity
        #[arg(long)]
        name: Option<String>,
    },
}

pub async fn run(action: IdentityCommand, ctx: &Context) -> Result<()> {
    match action {
        IdentityCommand::New { name } => new_identity(name, ctx).await,
        IdentityCommand::List => list_identities(ctx).await,
        IdentityCommand::Show { name } => show_identity(name, ctx).await,
        IdentityCommand::Use { name } => use_identity(name, ctx).await,
        IdentityCommand::Delete { name } => delete_identity(name, ctx).await,
        IdentityCommand::Export { name, output, format } => export_identity(name, output, format, ctx).await,
        IdentityCommand::Import { file, name } => import_identity(file, name, ctx).await,
    }
}

#[instrument(skip(ctx))]
async fn new_identity(name: Option<String>, ctx: &Context) -> Result<()> {
    debug!("Starting identity creation");
    
    let mut wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    debug!("Wallet loaded");
    
    let is_new_wallet = wallet.is_new();

    // Determine identity name
    let identity_name = match name {
        Some(n) => n,
        None => {
            // Auto-generate name like "identity-1"
            let mut i = 1;
            loop {
                let candidate = format!("identity-{i}");
                if !wallet.data.identities.contains_key(&candidate) {
                    break candidate;
                }
                i += 1;
            }
        }
    };

    if wallet.data.identities.contains_key(&identity_name) {
        anyhow::bail!("Identity '{identity_name}' already exists");
    }

    if ctx.verbose {
        print_info("Generating ED25519 keypair...");
    }
    debug!("Generating ED25519 keypair");
    let ed25519_kp = ed25519::ed25519_keygen();

    if ctx.verbose {
        print_info("Generating ML-DSA-87 keypair...");
    }
    debug!("Generating ML-DSA-87 keypair");
    let ml_dsa_kp =
        pq_keygen(PqAlgorithm::MlDsa87).context("Failed to generate ML-DSA-87 keypair")?;

    // Resolve which PRE backend to use
    debug!("Resolving PRE backend");
    let backend_id = ctx.resolve_backend_id()?;
    let backend = super::create_backend_from_id(backend_id)?;
    debug!("Backend initialized: {}", backend.name());

    if ctx.verbose {
        print_info(format!("Generating PRE keypair ({})...", backend.name()));
    }
    debug!("Generating PRE keypair");
    let pre_kp = backend
        .generate_keypair()
        .context("Failed to generate PRE keypair")?;

    // Compute fingerprint: blake3(ed25519_pk) — raw bytes inside the wallet,
    // base58 only at display/wire boundaries.
    debug!("Computing fingerprint");
    let fingerprint: [u8; 32] = *blake3::hash(ed25519_kp.verifying_key.as_bytes()).as_bytes();
    let fingerprint_b58 = bs58::encode(fingerprint).into_string();

    debug!("Creating identity struct");
    let identity = Identity {
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        fingerprint,
        ed25519: KeyPair {
            public: ed25519_kp.verifying_key.as_bytes().to_vec(),
            secret: ed25519_kp.signing_key.as_bytes().to_vec(),
        },
        ml_dsa: KeyPair {
            public: ml_dsa_kp.public_key.clone(),
            secret: ml_dsa_kp.secret_key.clone(),
        },
        pre: KeyPair {
            public: pre_kp.public.as_bytes().to_vec(),
            secret: pre_kp.secret.as_bytes().to_vec(),
        },
        pre_backend: backend_id,
    };

    debug!("Inserting identity into wallet");
    wallet
        .data
        .identities
        .insert(identity_name.clone(), identity);

    // Set as active if first identity
    if wallet.data.active_identity.is_none() {
        wallet.data.active_identity = Some(identity_name.clone());
    }

    debug!("Saving wallet");
    wallet.save(is_new_wallet)?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            name: String,
            fingerprint: String,
        }
        print_json(&Output {
            name: identity_name,
            fingerprint: fingerprint_b58,
        })?;
    } else {
        print_success(format!("Created identity '{}'", identity_name.bold()));
        println!("  {}: {}", "Fingerprint".dimmed(), fingerprint_b58);
        println!("  {}: {}", "Wallet".dimmed(), wallet.path().display());
    }

    info!("Identity created successfully");
    Ok(())
}

async fn list_identities(ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    let active_identity = wallet.data.active_identity.as_ref();

    if wallet.data.identities.is_empty() {
        if !ctx.json_output {
            print_info("No identities yet. Create one with: recrypt identity new");
        }
        return Ok(());
    }

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            name: String,
            fingerprint: String,
            is_active: bool,
        }
        let list: Vec<Output> = wallet
            .data
            .identities
            .iter()
            .map(|(name, identity)| Output {
                name: name.clone(),
                fingerprint: bs58::encode(identity.fingerprint).into_string(),
                is_active: active_identity == Some(name),
            })
            .collect();
        print_json(&list)?;
    } else {
        println!("{}", "Identities:".bold());
        for (name, identity) in &wallet.data.identities {
            let marker = if active_identity == Some(name) {
                "★".yellow()
            } else {
                " ".normal()
            };
            println!(
                "  {} {} ({})",
                marker,
                name.bold(),
                bs58::encode(identity.fingerprint).into_string().dimmed()
            );
        }
    }

    Ok(())
}

async fn show_identity(name: Option<String>, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    let identity_name = resolve_identity_name(name, &wallet, ctx)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            name: String,
            fingerprint: String,
            created_at: u64,
            ed25519_public: String,
            ml_dsa_public: String,
            pre_public: String,
            pre_backend: String,
        }
        let ed25519_enc = encode_key_display(&identity.ed25519.public);
        let ml_dsa_enc = encode_key_display(&identity.ml_dsa.public);
        let pre_enc = encode_key_display(&identity.pre.public);

        print_json(&Output {
            name: identity_name,
            fingerprint: bs58::encode(identity.fingerprint).into_string(),
            created_at: identity.created_at,
            ed25519_public: ed25519_enc,
            ml_dsa_public: ml_dsa_enc,
            pre_public: pre_enc,
            pre_backend: identity.pre_backend.to_string(),
        })?;
    } else {
        let ed25519_enc = encode_key_display(&identity.ed25519.public);
        let ml_dsa_enc = encode_key_display(&identity.ml_dsa.public);
        let pre_enc = encode_key_display(&identity.pre.public);

        println!("{}", format!("Identity: {identity_name}").bold());
        println!("  {}: {}", "Fingerprint".dimmed(), bs58::encode(identity.fingerprint).into_string());
        println!(
            "  {}: {}",
            "Created".dimmed(),
            format_timestamp(identity.created_at)
        );
        println!("  {}: {}", "PRE Backend".dimmed(), identity.pre_backend);
        println!("  {}:", "Public Keys".dimmed());
        println!(
            "    {}: {}",
            "ED25519".dimmed(),
            truncate(&ed25519_enc, 32)
        );
        println!(
            "    {}: {}",
            "ML-DSA-87".dimmed(),
            truncate(&ml_dsa_enc, 32)
        );
        println!(
            "    {}: {}",
            "PRE".dimmed(),
            truncate(&pre_enc, 32)
        );
    }

    Ok(())
}

async fn use_identity(name: String, ctx: &Context) -> Result<()> {
    let mut wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    if !wallet.data.identities.contains_key(&name) {
        anyhow::bail!("Identity '{name}' not found");
    }

    wallet.data.active_identity = Some(name.clone());
    wallet.save(false)?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            active_identity: String,
        }
        print_json(&Output {
            active_identity: name,
        })?;
    } else {
        print_success(format!("Active identity set to '{}'", name.bold()));
    }

    Ok(())
}

async fn delete_identity(name: String, ctx: &Context) -> Result<()> {
    let mut wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    if !wallet.data.identities.contains_key(&name) {
        anyhow::bail!("Identity '{name}' not found");
    }

    wallet.data.identities.remove(&name);

    // Clear active identity if it was this one
    if wallet.data.active_identity.as_ref() == Some(&name) {
        wallet.data.active_identity = wallet.data.identities.keys().next().cloned();
    }
    wallet.save(false)?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            deleted: String,
        }
        print_json(&Output { deleted: name })?;
    } else {
        print_success(format!("Deleted identity '{}'", name.bold()));
    }

    Ok(())
}

async fn export_identity(name: String, output: String, format: ExportFormat, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    let identity = wallet
        .data
        .identities
        .get(&name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{name}' not found"))?;

    let output_path = std::path::Path::new(&output);
    match format {
        ExportFormat::Json => {
            let json = serde_json::to_string_pretty(identity)?;
            write_secret_file(output_path, json.as_bytes())
                .with_context(|| format!("Failed to write {output}"))?;
        }
        ExportFormat::Envelope => {
            let wire_id = wire_identity_from_wallet(&name, identity)?;
            let bytes = wire_id
                .to_envelope_bytes()
                .map_err(|e| anyhow::anyhow!("Failed to serialize envelope: {e}"))?;
            write_secret_file(output_path, &bytes)
                .with_context(|| format!("Failed to write {output}"))?;
        }
    }

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            name: String,
            file: String,
        }
        print_json(&Output { name, file: output })?;
    } else {
        print_success(format!("Exported '{}' to {}", name.bold(), output));
    }

    Ok(())
}

async fn import_identity(file: String, name: Option<String>, ctx: &Context) -> Result<()> {
    let mut wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    let bytes = std::fs::read(&file).with_context(|| format!("Failed to read {file}"))?;

    // Detect format. CBOR envelopes start with the dCBOR tag-200 prefix
    // (0xd8 0xc8). JSON may have leading whitespace or a UTF-8 BOM, so skip
    // those before checking for an opening brace.
    let identity = if bytes.starts_with(&[0xd8, 0xc8]) {
        let wire_id = recrypt_wire::Identity::from_envelope_bytes(&bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse identity envelope: {e}"))?;
        wallet_identity_from_wire(&wire_id)?
    } else {
        let probe = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
        let first_non_ws = probe.iter().find(|b| !b.is_ascii_whitespace()).copied();
        if first_non_ws == Some(b'{') {
            serde_json::from_slice(&bytes).context("Invalid JSON identity file")?
        } else {
            anyhow::bail!(
                "Unrecognized identity file format (expected CBOR envelope starting with 0xd8 0xc8, or JSON starting with '{{')"
            );
        }
    };

    let identity_name = name.unwrap_or_else(|| {
        let mut i = 1;
        loop {
            let candidate = format!("imported-{i}");
            if !wallet.data.identities.contains_key(&candidate) {
                break candidate;
            }
            i += 1;
        }
    });

    if wallet.data.identities.contains_key(&identity_name) {
        anyhow::bail!("Identity '{identity_name}' already exists");
    }

    wallet
        .data
        .identities
        .insert(identity_name.clone(), identity);
    wallet.save(false)?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            name: String,
        }
        print_json(&Output {
            name: identity_name,
        })?;
    } else {
        print_success(format!("Imported identity as '{}'", identity_name.bold()));
    }

    Ok(())
}

// Conversion helpers between wallet Identity and wire Identity

fn wire_identity_from_wallet(name: &str, id: &Identity) -> Result<recrypt_wire::Identity> {
    let ed25519_public: [u8; 32] = id.ed25519.public.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "ed25519 public key in wallet is {} bytes, expected 32",
            id.ed25519.public.len()
        )
    })?;
    let ed25519_secret: Option<[u8; 32]> = id.ed25519.secret.as_slice().try_into().ok();

    // The wallet's stored fingerprint is informational; recompute the
    // canonical fingerprint from the ed25519 public key. If the stored
    // value disagrees, treat it as wallet corruption rather than silently
    // healing — surface the error so the operator can investigate.
    let computed: [u8; 32] = *blake3::hash(&ed25519_public).as_bytes();
    if id.fingerprint != computed {
        anyhow::bail!(
            "wallet corruption: stored fingerprint for '{name}' does not match Blake3(ed25519_public)"
        );
    }

    Ok(recrypt_wire::Identity {
        fingerprint: computed,
        ed25519_public,
        ed25519_secret,
        name: Some(name.to_string()),
        created: Some(id.created_at),
        ml_dsa: Some(recrypt_wire::MlDsaKeyPair {
            public: id.ml_dsa.public.clone(),
            secret: Some(id.ml_dsa.secret.clone()),
        }),
        pre: Some(recrypt_wire::PreKeyMaterial {
            backend: id.pre_backend.to_string(),
            public: id.pre.public.clone(),
            secret: Some(id.pre.secret.clone()),
        }),
        unknown_assertions: vec![],
    })
}

fn wallet_identity_from_wire(wi: &recrypt_wire::Identity) -> Result<Identity> {
    let ml_dsa = wi.ml_dsa.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Identity envelope is missing ml-dsa keys — only full identities (with all key material) can be imported into a wallet"
        )
    })?;
    let ml_dsa_secret = ml_dsa.secret.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Identity envelope has ml-dsa public key but no secret key — only full identities can be imported into a wallet"
        )
    })?;

    let pre = wi.pre.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Identity envelope is missing PRE keys — only full identities (with all key material) can be imported into a wallet"
        )
    })?;
    let pre_secret = pre.secret.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Identity envelope has PRE public key but no secret key — only full identities can be imported into a wallet"
        )
    })?;

    let ed25519_secret = wi.ed25519_secret.ok_or_else(|| {
        anyhow::anyhow!(
            "Identity envelope is missing ed25519 secret key — only full identities can be imported into a wallet"
        )
    })?;

    let backend_id: recrypt_core::pre::BackendId = pre.backend.parse()
        .map_err(|_| anyhow::anyhow!("Unknown PRE backend: '{}'", pre.backend))?;

    let created_at = wi.created.unwrap_or_else(|| {
        tracing::debug!(
            "imported envelope has no 'created' assertion; falling back to current time"
        );
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    Ok(Identity {
        created_at,
        fingerprint: wi.fingerprint,
        ed25519: KeyPair {
            public: wi.ed25519_public.to_vec(),
            secret: ed25519_secret.to_vec(),
        },
        ml_dsa: KeyPair {
            public: ml_dsa.public.clone(),
            secret: ml_dsa_secret.clone(),
        },
        pre: KeyPair {
            public: pre.public.clone(),
            secret: pre_secret.clone(),
        },
        pre_backend: backend_id,
    })
}

// Helper functions

fn resolve_identity_name(
    explicit: Option<String>,
    wallet: &Wallet,
    ctx: &Context,
) -> Result<String> {
    if let Some(name) = explicit {
        return Ok(name);
    }

    if let Some(ref name) = ctx.identity_override {
        return Ok(name.clone());
    }

    if let Some(ref name) = wallet.data.active_identity {
        if wallet.data.identities.contains_key(name) {
            return Ok(name.clone());
        }
    }

    anyhow::bail!(
        "No identity specified. Use --identity <name> or set with: recrypt identity use <name>"
    )
}

fn format_timestamp(ts: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(ts as i64, 0).unwrap_or_else(Utc::now);
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

/// Encode a key for display per docs/standards/encoding-conventions.md §4:
/// short stable IDs (≤256 B) → base58; multi-KB blobs → base64. base58 is
/// O(n²); never feed it ML-DSA or lattice-PRE keys.
fn encode_key_display(bytes: &[u8]) -> String {
    if bytes.len() <= 256 {
        bs58::encode(bytes).into_string()
    } else {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
