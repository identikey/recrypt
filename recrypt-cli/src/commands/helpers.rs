// Common helper functions

use super::Context;
use crate::config::Config;
use crate::wallet::Wallet;
use anyhow::Result;

pub fn resolve_identity(ctx: &Context, wallet: &Wallet) -> Result<String> {
    // Priority: --identity flag / $RECRYPT_IDENTITY env > wallet.active_identity
    // No global config fallback — wallet is the single source of truth.
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

pub fn resolve_server_url(ctx: &Context, config: &Config) -> Result<String> {
    // Priority: --server flag > $RECRYPT_SERVER env > config.default_server
    if let Some(ref server) = ctx.server_override {
        return Ok(server.clone());
    }

    if let Some(ref server) = config.default_server {
        return Ok(server.clone());
    }

    anyhow::bail!("No server URL specified. Use --server <url> or set default in config")
}

pub fn format_timestamp(ts: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(ts as i64, 0).unwrap_or_else(Utc::now);
    dt.format("%Y-%m-%d %H:%M UTC").to_string()
}

pub fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}
