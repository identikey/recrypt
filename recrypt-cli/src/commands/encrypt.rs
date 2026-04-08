use anyhow::{Context as AnyhowContext, Result};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tokio::fs;

use recrypt_core::{HybridEncryptor, hybrid::EncryptedFile};
use recrypt_proto::MultiFormat;

use super::Context;
use crate::output::{print_json, print_success};
use crate::wallet::Wallet;

#[derive(Args)]
pub struct EncryptArgs {
    /// File to encrypt
    pub file: String,
    /// Recipient fingerprint or identity name
    #[arg(long)]
    pub r#for: String,
    /// Output file
    #[arg(long)]
    pub output: Option<String>,
}

pub async fn run(args: EncryptArgs, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    // Resolve recipient
    let recipient_identity = wallet.data.identities.get(&args.r#for).ok_or_else(|| {
        anyhow::anyhow!(
            "Recipient '{}' not found in wallet. To encrypt for external recipients, \
             they must first be imported or you must use their fingerprint (not yet implemented).",
            args.r#for
        )
    })?;

    // Parse recipient's PRE public key using their stored backend
    let recipient_pre_pk_bytes = bs58::decode(&recipient_identity.pre.public)
        .into_vec()
        .context("Failed to decode recipient PRE public key")?;

    let recipient_backend_id = recipient_identity.pre_backend;
    let recipient_pre_pk =
        recrypt_core::pre::PublicKey::new(recipient_backend_id, recipient_pre_pk_bytes);

    // Create backend matching the recipient's identity
    let backend = super::create_backend_from_id(recipient_backend_id)?;
    let encryptor = HybridEncryptor::new(backend);

    // Determine output paths
    let output_path = args.output.unwrap_or_else(|| format!("{}.enc", args.file));
    let outboard_path = format!("{output_path}.obao");

    let pb = if !ctx.json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner());
        pb.set_message("Encrypting...");
        Some(pb)
    } else {
        None
    };

    // Open plaintext file for streaming read
    let plaintext_file = fs::File::open(&args.file)
        .await
        .with_context(|| format!("Failed to open {}", args.file))?;

    // Collect ciphertext into a buffer (encrypt_streaming writes to AsyncWrite)
    let mut ciphertext_buf: Vec<u8> = Vec::new();
    let result = encryptor
        .encrypt_streaming(&recipient_pre_pk, plaintext_file, &mut ciphertext_buf)
        .await
        .context("Encryption failed")?;

    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    // Build EncryptedFile envelope from streaming result
    let encrypted = EncryptedFile {
        wrapped_key: result.wrapped_key,
        bao_hash: result.bao_hash,
        ciphertext: ciphertext_buf,
        signature: None,
    };

    let ciphertext_len = encrypted.ciphertext.len();

    // Serialize envelope (includes ciphertext) to protobuf
    let serialized = encrypted.to_protobuf()?;
    fs::write(&output_path, &serialized)
        .await
        .with_context(|| format!("Failed to write {output_path}"))?;

    // Write outboard sibling if non-empty (file > 16 KiB)
    if !result.outboard.is_empty() {
        fs::write(&outboard_path, &result.outboard)
            .await
            .with_context(|| format!("Failed to write outboard {outboard_path}"))?;
    }

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            input: String,
            output: String,
            outboard: Option<String>,
            size: usize,
        }
        print_json(&Output {
            input: args.file,
            output: output_path,
            outboard: if result.outboard.is_empty() {
                None
            } else {
                Some(outboard_path)
            },
            size: ciphertext_len,
        })?;
    } else {
        let outboard_note = if result.outboard.is_empty() {
            String::new()
        } else {
            format!(" + {outboard_path}")
        };
        print_success(format!(
            "Encrypted {} → {}{} ({} bytes)",
            args.file, output_path, outboard_note, ciphertext_len
        ));
    }

    Ok(())
}
