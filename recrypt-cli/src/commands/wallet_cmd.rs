use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;
use serde::Serialize;

use super::Context;
use crate::output::{print_info, print_json, print_success};
use crate::wallet::credential::default_provider_for;
use crate::wallet::Wallet;

#[derive(Subcommand)]
pub enum WalletCommand {
    /// Unlock wallet and cache decryption key
    Unlock,
    /// Clear cached decryption key
    Lock,
    /// Show wallet status
    Status,
    /// Show wallet path
    Path,
}

pub async fn run(action: WalletCommand, ctx: &Context) -> Result<()> {
    match action {
        WalletCommand::Unlock => unlock(ctx).await,
        WalletCommand::Lock => lock(ctx).await,
        WalletCommand::Status => status(ctx).await,
        WalletCommand::Path => path(ctx).await,
    }
}

fn resolve_wallet_path(ctx: &Context) -> Result<std::path::PathBuf> {
    use directories::ProjectDirs;
    match &ctx.wallet_override {
        Some(p) => Ok(std::path::PathBuf::from(p)),
        None => {
            let dirs = ProjectDirs::from("io", "identikey", "recrypt")
                .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
            Ok(dirs.data_dir().join("wallet.ikeyw"))
        }
    }
}

async fn unlock(ctx: &Context) -> Result<()> {
    let wallet_path = resolve_wallet_path(ctx)?;
    let provider = default_provider_for(&wallet_path);

    // Check if already unlocked
    if provider.get_key()?.is_some() {
        if ctx.json_output {
            #[derive(Serialize)]
            struct Output {
                already_unlocked: bool,
            }
            print_json(&Output {
                already_unlocked: true,
            })?;
        } else {
            print_info("Wallet already unlocked");
        }
        return Ok(());
    }

    // Load wallet (will prompt for password and cache key)
    let _ = Wallet::load_with_provider(ctx.wallet_override.as_deref(), provider.as_ref())?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            unlocked: bool,
            provider: String,
        }
        print_json(&Output {
            unlocked: true,
            provider: provider.name().to_string(),
        })?;
    } else {
        print_success(format!("Wallet unlocked (cached in {})", provider.name()));
    }

    Ok(())
}

async fn lock(ctx: &Context) -> Result<()> {
    let wallet_path = resolve_wallet_path(ctx)?;
    let provider = default_provider_for(&wallet_path);
    provider.clear_key()?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            locked: bool,
        }
        print_json(&Output { locked: true })?;
    } else {
        print_success("Wallet locked");
    }

    Ok(())
}

async fn status(ctx: &Context) -> Result<()> {
    let wallet_path = resolve_wallet_path(ctx)?;
    let provider = default_provider_for(&wallet_path);
    let is_unlocked = provider.get_key()?.is_some();
    let wallet_path_str = wallet_path.display().to_string();

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            unlocked: bool,
            provider: String,
            wallet_path: String,
        }
        print_json(&Output {
            unlocked: is_unlocked,
            provider: provider.name().to_string(),
            wallet_path: wallet_path_str,
        })?;
    } else {
        let status_text = if is_unlocked {
            "Unlocked".green()
        } else {
            "Locked".red()
        };
        println!("{}: {}", "Wallet Status".bold(), status_text);
        println!("  {}: {}", "Provider".dimmed(), provider.name());
        println!("  {}: {}", "Path".dimmed(), wallet_path_str);
    }

    Ok(())
}

async fn path(ctx: &Context) -> Result<()> {
    let path = resolve_wallet_path(ctx)?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            path: String,
            exists: bool,
        }
        print_json(&Output {
            path: path.display().to_string(),
            exists: path.exists(),
        })?;
    } else {
        println!("{}", path.display());
    }

    Ok(())
}
