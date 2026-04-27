use anyhow::{Context as AnyhowContext, Result};
use clap::Subcommand;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::fs;

use super::helpers::{resolve_identity, resolve_server_url};
use super::Context;
use crate::client::ApiClient;
use crate::config::Config;
use crate::output::{print_json, print_success};
use crate::wallet::Wallet;

#[derive(Subcommand)]
pub enum FileCommand {
    /// Upload a file
    Upload {
        /// File to upload
        file: String,
    },
    /// Download a file
    Download {
        /// File hash
        hash: String,
        /// Output file
        #[arg(long)]
        output: Option<String>,
    },
    /// List files
    List,
    /// Delete a file
    Delete {
        /// File hash
        hash: String,
    },
}

pub async fn run(action: FileCommand, ctx: &Context) -> Result<()> {
    match action {
        FileCommand::Upload { file } => upload(file, ctx).await,
        FileCommand::Download { hash, output } => download(hash, output, ctx).await,
        FileCommand::List => list(ctx).await,
        FileCommand::Delete { hash } => delete(hash, ctx).await,
    }
}

async fn upload(file_path: String, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;

    // Read file
    let file_data = fs::read(&file_path).with_context(|| format!("Failed to read {file_path}"))?;

    let pb = if !ctx.json_output {
        let pb = ProgressBar::new(file_data.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes}")
                .unwrap(),
        );
        Some(pb)
    } else {
        None
    };

    // Upload
    let client = ApiClient::new(server_url);
    let response = client.upload_file(identity, file_data).await?;

    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    if ctx.json_output {
        print_json(&response)?;
    } else {
        print_success(format!("Uploaded {file_path}"));
        println!("  {}: {}", "Hash".dimmed(), response.hash);
    }

    Ok(())
}

async fn download(hash: String, output_override: Option<String>, ctx: &Context) -> Result<()> {
    let config = Config::load()?;
    let server_url = resolve_server_url(ctx, &config)?;

    let pb = if !ctx.json_output {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner());
        pb.set_message("Downloading...");
        Some(pb)
    } else {
        None
    };

    // Download
    let client = ApiClient::new(server_url);
    let file_data = client.download_file(&hash).await?;

    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    // Determine output path
    let output_path = output_override.unwrap_or_else(|| format!("{hash}.bin"));

    fs::write(&output_path, &file_data)
        .with_context(|| format!("Failed to write {output_path}"))?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            hash: String,
            output: String,
            size: usize,
        }
        print_json(&Output {
            hash,
            output: output_path,
            size: file_data.len(),
        })?;
    } else {
        print_success(format!(
            "Downloaded to {} ({} bytes)",
            output_path,
            file_data.len()
        ));
    }

    Ok(())
}

async fn list(ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;

    let client = ApiClient::new(server_url);
    let fingerprint_b58 = bs58::encode(identity.fingerprint).into_string();
    let files = client.list_files(&fingerprint_b58).await?;

    if ctx.json_output {
        print_json(&files)?;
    } else if files.is_empty() {
        println!("{}", "No files found.".dimmed());
    } else {
        println!("{}", "Files:".bold());
        for file in &files {
            println!("  {}", file.hash.bright_cyan());
        }
        println!();
        println!("{} file(s)", files.len());
    }

    Ok(())
}

async fn delete(hash: String, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;

    let client = ApiClient::new(server_url);
    client.delete_file(identity, &hash).await?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            deleted: String,
        }
        print_json(&Output { deleted: hash })?;
    } else {
        print_success(format!("Deleted file {hash}"));
    }

    Ok(())
}
