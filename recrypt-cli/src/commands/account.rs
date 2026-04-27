use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;

use super::helpers::{format_timestamp, resolve_identity, resolve_server_url, truncate};
use super::Context;
use crate::client::ApiClient;
use crate::config::Config;
use crate::output::{print_json, print_success};
use crate::wallet::Wallet;

#[derive(Subcommand)]
pub enum AccountCommand {
    /// Register account on server
    Register,
    /// Show account details
    Show {
        /// Account fingerprint (optional, uses current identity if not provided)
        fingerprint: Option<String>,
    },
}

pub async fn run(action: AccountCommand, ctx: &Context) -> Result<()> {
    match action {
        AccountCommand::Register => register(ctx).await,
        AccountCommand::Show { fingerprint } => show(fingerprint, ctx).await,
    }
}

async fn register(ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    // Resolve identity
    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    // Resolve server URL
    let server_url = resolve_server_url(ctx, &config)?;

    // Register
    let client = ApiClient::new(server_url.clone());
    let response = client.register_account(identity).await?;

    if ctx.json_output {
        print_json(&response)?;
    } else {
        print_success(format!("Registered account on {server_url}"));
        println!("  {}: {}", "Fingerprint".dimmed(), response.fingerprint);
    }

    Ok(())
}

async fn show(fingerprint_override: Option<String>, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    // Resolve fingerprint
    let fingerprint = match fingerprint_override {
        Some(fp) => fp,
        None => {
            let identity_name = resolve_identity(ctx, &wallet)?;
            let identity = wallet
                .data
                .identities
                .get(&identity_name)
                .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;
            bs58::encode(identity.fingerprint).into_string()
        }
    };

    // Resolve server URL
    let server_url = resolve_server_url(ctx, &config)?;

    // Get account
    let client = ApiClient::new(server_url);
    let account = client.get_account(&fingerprint).await?;

    if ctx.json_output {
        print_json(&account)?;
    } else {
        println!("{}", format!("Account: {fingerprint}").bold());
        println!(
            "  {}: {}",
            "ED25519 Key".dimmed(),
            truncate(&account.ed25519_pk, 32)
        );
        println!(
            "  {}: {}",
            "ML-DSA Key".dimmed(),
            truncate(&account.ml_dsa_pk, 32)
        );
        println!(
            "  {}: {}",
            "Created".dimmed(),
            format_timestamp(account.created_at)
        );
    }

    Ok(())
}
