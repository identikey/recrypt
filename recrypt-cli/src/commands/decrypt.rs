use anyhow::{Context as AnyhowContext, Result};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::io::Cursor;
use tokio::fs;

use recrypt_core::HybridEncryptor;
use recrypt_wire::MultiFormat;

use super::Context;
use crate::config::Config;
use crate::output::{print_json, print_success};
use crate::wallet::Wallet;

#[derive(Args)]
pub struct DecryptArgs {
    /// File to decrypt
    pub file: String,
    /// Output file
    #[arg(long)]
    pub output: Option<String>,
}

pub async fn run(args: DecryptArgs, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    // Determine which identity to use
    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    // PRE keys are stored as raw bytes in the wallet
    let pre_sk_bytes = identity.pre.secret.clone();

    let backend_id = identity.pre_backend;
    let pre_sk = recrypt_core::pre::SecretKey::new(backend_id, pre_sk_bytes);

    // Read encrypted file (protobuf envelope with ciphertext inline)
    let encrypted_bytes = fs::read(&args.file)
        .await
        .with_context(|| format!("Failed to read {}", args.file))?;

    // Deserialize envelope
    let encrypted = recrypt_core::EncryptedFile::from_envelope(&encrypted_bytes)
        .context("Failed to parse encrypted file (invalid format?)")?;

    // Load outboard sibling if present (file > 16 KiB case)
    let outboard_path = format!("{}.obao", args.file);
    let outboard_bytes = match fs::read(&outboard_path).await {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to read outboard {outboard_path}"));
        }
    };

    // Create backend matching the identity
    let backend = super::create_backend_from_id(backend_id)?;
    let encryptor = HybridEncryptor::new(backend);

    let pb = if !ctx.json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner());
        pb.set_message("Decrypting...");
        Some(pb)
    } else {
        None
    };

    // Decrypt using streaming API
    let mut plaintext_buf: Vec<u8> = Vec::new();
    encryptor
        .decrypt_streaming(
            &pre_sk,
            &encrypted.wrapped_key,
            &encrypted.bao_hash,
            Cursor::new(&encrypted.ciphertext),
            Cursor::new(&outboard_bytes),
            &mut plaintext_buf,
        )
        .await
        .context("Decryption failed (wrong key or corrupted file?)")?;

    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    // Determine output path
    let output_path = args.output.unwrap_or_else(|| {
        if args.file.ends_with(".enc") {
            args.file.trim_end_matches(".enc").to_string()
        } else {
            format!("{}.decrypted", args.file)
        }
    });

    let plaintext_len = plaintext_buf.len();
    fs::write(&output_path, &plaintext_buf)
        .await
        .with_context(|| format!("Failed to write {output_path}"))?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            input: String,
            output: String,
            size: usize,
        }
        print_json(&Output {
            input: args.file,
            output: output_path,
            size: plaintext_len,
        })?;
    } else {
        print_success(format!(
            "Decrypted {} → {} ({} bytes)",
            args.file, output_path, plaintext_len
        ));
    }

    Ok(())
}

fn resolve_identity(ctx: &Context, wallet: &Wallet) -> Result<String> {
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
