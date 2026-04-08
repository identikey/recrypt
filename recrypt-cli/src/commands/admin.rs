//! Admin subcommands for operator use.
//!
//! Currently exposes:
//!   recrypt admin gc [--dry-run] [--max-age <DURATION>] [--bucket <NAME>] [--prefix <PREFIX>]

use anyhow::Result;
use async_trait::async_trait;
use clap::Subcommand;
use colored::Colorize;
use std::time::Duration;

use recrypt_storage::gc::{GcOptions, GcReport, MetadataIndex};
use recrypt_storage::{InMemoryStorage, StorageResult};

use super::Context;

// ── Subcommand definitions ────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum AdminCommand {
    /// Garbage-collect orphaned storage objects.
    ///
    /// An object is an orphan when it has no associated metadata record (e.g.
    /// a client uploaded ciphertext but the metadata POST never landed).
    ///
    /// Run with --dry-run first to inspect what would be deleted.
    Gc(GcArgs),
}

#[derive(clap::Args)]
pub struct GcArgs {
    /// Scan and report orphans without deleting anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Orphans younger than this are kept so in-flight uploads can finish.
    /// Accepts human-readable durations: "30m", "2h", "7d", "1h30m".
    /// Default: 24h.
    #[arg(long, default_value = "24h")]
    pub max_age: String,

    /// S3 bucket name. Default: from config / environment.
    #[arg(long)]
    pub bucket: Option<String>,

    /// Storage key prefix to scan. Default: "chunks/b3/".
    #[arg(long, default_value = "chunks/b3/")]
    pub prefix: String,
}

pub async fn run(action: AdminCommand, _ctx: &Context) -> Result<()> {
    match action {
        AdminCommand::Gc(args) => run_gc(args).await,
    }
}

// ── GC implementation ─────────────────────────────────────────────────────────

/// Stub `MetadataIndex` that always returns `false` (treats every object as an
/// orphan). Used when no real metadata service client is wired up.
///
/// SAFETY: This stub is intentionally blocked from running non-dry-run deletes
/// via `StubMetadataIndex::is_stub()`. See `run_gc` below.
struct StubMetadataIndex;

#[async_trait]
impl MetadataIndex for StubMetadataIndex {
    async fn has_metadata(&self, _hash: &[u8; 32]) -> StorageResult<bool> {
        // Stub: no real metadata service is available. Returning `false` means
        // every object looks like an orphan — only safe in dry-run mode.
        Ok(false)
    }
}

async fn run_gc(args: GcArgs) -> Result<()> {
    // Parse max-age duration.
    let max_upload_lifetime = humantime::parse_duration(&args.max_age)
        .map_err(|e| anyhow::anyhow!("Invalid --max-age '{}': {e}", args.max_age))?;

    // Safety guard: refuse to delete real data with the stub metadata index.
    // A real metadata service client would be constructed here (future work).
    if !args.dry_run {
        anyhow::bail!(
            "Non-dry-run GC requires a real metadata service client, which is not yet \
             implemented.\n\
             \n\
             Run with --dry-run to inspect orphans safely:\n\
             \n  recrypt admin gc --dry-run [--max-age <DURATION>]\n\
             \n\
             Tracking issue: wire up MetadataIndex against the auth service HTTP API."
        );
    }

    let opts = GcOptions {
        max_upload_lifetime,
        dry_run: args.dry_run,
    };

    // NOTE: We use InMemoryStorage here as a placeholder. In production this
    // would be S3Storage constructed from config + bucket/prefix args.
    // That wiring is deferred until the auth-service MetadataIndex client
    // exists (so we never accidentally delete real data with a stub index).
    let storage = InMemoryStorage::new();
    let metadata = StubMetadataIndex;

    let report = storage.gc_orphans(&metadata, opts).await
        .map_err(|e| anyhow::anyhow!("GC sweep failed: {e}"))?;

    print_report(&report, args.dry_run, &max_upload_lifetime);
    Ok(())
}

fn print_report(report: &GcReport, dry_run: bool, max_age: &Duration) {
    if dry_run {
        println!("{}", "[DRY RUN] No data was deleted.".yellow().bold());
        println!();
    }

    println!(
        "{}: {} objects  (max-age filter: {})",
        "Scanned".bold(),
        report.scanned,
        humantime::format_duration(*max_age),
    );
    println!("{}: {}", "Orphans found".bold(), report.orphans_found);
    println!(
        "{}: {}",
        "Bytes reclaimed".bold(),
        format_bytes(report.bytes_reclaimed)
    );

    if report.deleted_keys.is_empty() {
        if dry_run {
            println!("{}", "No orphan keys found.".dimmed());
        } else {
            println!("{}", "Nothing to delete.".dimmed());
        }
    } else {
        let label = if dry_run {
            "Would delete keys"
        } else {
            "Deleted keys"
        };
        println!("{}:", label.bold());
        for key in &report.deleted_keys {
            println!("  - {}", key.bright_cyan());
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const MB: u64 = 1_000_000;
    const KB: u64 = 1_000;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse GC args and verify GcOptions fields are set correctly.
    #[test]
    fn test_gc_args_parse_max_age() {
        // 30 minutes
        let duration = humantime::parse_duration("30m").unwrap();
        assert_eq!(duration, Duration::from_secs(30 * 60));

        // 2 hours
        let duration = humantime::parse_duration("2h").unwrap();
        assert_eq!(duration, Duration::from_secs(2 * 60 * 60));

        // 7 days
        let duration = humantime::parse_duration("7d").unwrap();
        assert_eq!(duration, Duration::from_secs(7 * 24 * 60 * 60));
    }

    #[test]
    fn test_gc_options_dry_run_default() {
        let opts = GcOptions {
            max_upload_lifetime: Duration::from_secs(24 * 60 * 60),
            dry_run: true,
        };
        assert!(opts.dry_run);
        assert_eq!(opts.max_upload_lifetime, Duration::from_secs(86400));
    }

    #[test]
    fn test_gc_options_default() {
        let opts = GcOptions::default();
        assert!(!opts.dry_run);
        assert_eq!(opts.max_upload_lifetime, Duration::from_secs(24 * 60 * 60));
    }

    /// Verify that non-dry-run is rejected (safety guard).
    #[tokio::test]
    async fn test_gc_non_dry_run_is_rejected() {
        let args = GcArgs {
            dry_run: false,
            max_age: "24h".to_string(),
            bucket: None,
            prefix: "chunks/b3/".to_string(),
        };
        let result = run_gc(args).await;
        assert!(result.is_err(), "non-dry-run must be rejected without real metadata client");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not yet implemented"), "error should mention follow-up: {msg}");
    }

    /// Verify dry-run succeeds against empty in-memory storage.
    #[tokio::test]
    async fn test_gc_dry_run_succeeds_on_empty_storage() {
        let args = GcArgs {
            dry_run: true,
            max_age: "24h".to_string(),
            bucket: None,
            prefix: "chunks/b3/".to_string(),
        };
        let result = run_gc(args).await;
        assert!(result.is_ok(), "dry-run against empty storage must succeed: {result:?}");
    }
}
