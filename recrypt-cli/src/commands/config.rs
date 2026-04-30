use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;

use super::Context;
use crate::config::Config;
use crate::output::print_success;
use crate::wallet::Wallet;

#[derive(Subcommand)]
pub enum ConfigCommand {
    /// Show current configuration
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
}

pub async fn run(action: ConfigCommand, _ctx: &Context) -> Result<()> {
    match action {
        ConfigCommand::Show => show().await,
        ConfigCommand::Set { key, value } => set(key, value).await,
    }
}

async fn show() -> Result<()> {
    let config = Config::load()?;

    println!("{}", "Configuration:".bold());
    println!(
        "  {}: {}",
        "default_server".dimmed(),
        config.default_server.as_deref().unwrap_or("(not set)")
    );
    println!("    {}", "Example: http://localhost:7222".bright_black());

    println!(
        "  {}: {}",
        "output_format".dimmed(),
        config.output_format.as_deref().unwrap_or("pretty")
    );
    println!("    {}", "Valid: pretty, json".bright_black());

    let default_wallet = Wallet::default_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(unavailable)".to_string());
    let wallet_display = config
        .wallet_path
        .clone()
        .unwrap_or_else(|| format!("{default_wallet} (default)"));
    println!("  {}: {}", "wallet_path".dimmed(), wallet_display);
    println!(
        "    {}",
        "Example: /path/to/custom/wallet.ikeyw".bright_black()
    );

    println!();
    println!("{}", "To set a value:".dimmed());
    println!("  recrypt config set <key> <value>");

    Ok(())
}

async fn set(key: String, value: String) -> Result<()> {
    let mut config = Config::load()?;

    match key.as_str() {
        "default_server" => {
            config.default_server = Some(value.clone());
        }
        "output_format" => {
            if value != "pretty" && value != "json" {
                anyhow::bail!("Invalid output_format '{value}'. Valid values: pretty, json");
            }
            config.output_format = Some(value.clone());
        }
        "wallet_path" => {
            config.wallet_path = Some(value.clone());
        }
        _ => {
            anyhow::bail!(
                "Unknown config key '{key}'.\n\n\
                Valid keys:\n  \
                  default_server      (e.g., http://localhost:7222)\n  \
                  output_format       (pretty or json)\n  \
                  wallet_path         (e.g., /path/to/wallet.ikeyw)\n\n\
                Note: active identity is managed with: recrypt identity use <name>"
            );
        }
    }

    config.save()?;

    print_success(format!("Set {key} = {value}"));

    Ok(())
}
