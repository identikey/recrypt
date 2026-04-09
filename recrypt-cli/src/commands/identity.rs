use anyhow::{Context as _, Result};
use base64::Engine;
use clap::Subcommand;
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
use crate::wallet::{Identity, KeyPair, Wallet};

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
        IdentityCommand::Export { name, output } => export_identity(name, output, ctx).await,
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

    // Compute fingerprint: base58(blake3(ed25519_pk))
    debug!("Computing fingerprint");
    let fingerprint =
        bs58::encode(blake3::hash(ed25519_kp.verifying_key.as_bytes()).as_bytes()).into_string();

    debug!("Creating identity struct");
    let identity = Identity {
        created_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        fingerprint: fingerprint.clone(),
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
            fingerprint,
        })?;
    } else {
        print_success(format!("Created identity '{}'", identity_name.bold()));
        println!("  {}: {}", "Fingerprint".dimmed(), fingerprint);
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
                fingerprint: identity.fingerprint.clone(),
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
                identity.fingerprint.dimmed()
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
        let ed25519_b58 = bs58::encode(&identity.ed25519.public).into_string();
        let ml_dsa_b58 = bs58::encode(&identity.ml_dsa.public).into_string();
        let pre_b58 = bs58::encode(&identity.pre.public).into_string();

        print_json(&Output {
            name: identity_name,
            fingerprint: identity.fingerprint.clone(),
            created_at: identity.created_at,
            ed25519_public: ed25519_b58,
            ml_dsa_public: ml_dsa_b58,
            pre_public: pre_b58,
            pre_backend: identity.pre_backend.to_string(),
        })?;
    } else {
        let ed25519_b58 = bs58::encode(&identity.ed25519.public).into_string();
        let ml_dsa_b58 = bs58::encode(&identity.ml_dsa.public).into_string();
        let pre_b58 = bs58::encode(&identity.pre.public).into_string();

        println!("{}", format!("Identity: {identity_name}").bold());
        println!("  {}: {}", "Fingerprint".dimmed(), identity.fingerprint);
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
            truncate(&ed25519_b58, 32)
        );
        println!(
            "    {}: {}",
            "ML-DSA-87".dimmed(),
            truncate(&ml_dsa_b58, 32)
        );
        println!(
            "    {}: {}",
            "PRE".dimmed(),
            truncate(&pre_b58, 32)
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

async fn export_identity(name: String, output: String, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    let identity = wallet
        .data
        .identities
        .get(&name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{name}' not found"))?;

    let json = serde_json::to_string_pretty(identity)?;
    std::fs::write(&output, json)?;

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

    let json = std::fs::read_to_string(&file).with_context(|| format!("Failed to read {file}"))?;
    let identity: Identity = serde_json::from_str(&json).context("Invalid identity file format")?;

    let identity_name = name.unwrap_or_else(|| {
        // Auto-generate name
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
