use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, EnvFilter};

mod client;
mod commands;
mod config;
mod output;
mod wallet;

#[derive(Parser)]
#[command(name = "recrypt")]
#[command(about = "Quantum-resistant proxy recryption CLI")]
#[command(version)]
struct Cli {
    /// Output format
    #[arg(long, global = true)]
    json: bool,

    /// Identity to use
    #[arg(long, global = true, env = "RECRYPT_IDENTITY")]
    identity: Option<String>,

    /// Server URL
    #[arg(long, global = true, env = "RECRYPT_SERVER")]
    server: Option<String>,

    /// Wallet path
    #[arg(long, global = true, env = "RECRYPT_WALLET")]
    wallet: Option<String>,

    /// PRE backend: "lattice" (post-quantum, default), "mock" (testing only)
    #[arg(long, global = true, env = "RECRYPT_BACKEND")]
    backend: Option<String>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable debug instrumentation (timing, detailed logs)
    #[arg(long, global = true, env = "RECRYPT_DEBUG")]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage identities
    Identity {
        #[command(subcommand)]
        action: commands::identity::IdentityCommand,
    },
    /// Encrypt a file locally
    Encrypt(commands::encrypt::EncryptArgs),
    /// Decrypt a file locally
    Decrypt(commands::decrypt::DecryptArgs),
    /// Manage server account
    Account {
        #[command(subcommand)]
        action: commands::account::AccountCommand,
    },
    /// Manage files on server
    File {
        #[command(subcommand)]
        action: commands::files::FileCommand,
    },
    /// Manage file shares
    Share {
        #[command(subcommand)]
        action: commands::share::ShareCommand,
    },
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: commands::config::ConfigCommand,
    },
    /// Manage wallet (unlock/lock)
    Wallet {
        #[command(subcommand)]
        action: commands::wallet_cmd::WalletCommand,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.debug {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("recrypt_cli=debug"))
    } else {
        EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("recrypt_cli=warn"))
    };

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_timer(fmt::time::uptime())
        .init();

    let ctx = commands::Context {
        json_output: cli.json,
        identity_override: cli.identity,
        server_override: cli.server,
        wallet_override: cli.wallet,
        backend_override: cli.backend,
        verbose: cli.verbose,
        debug: cli.debug,
    };

    match cli.command {
        Commands::Identity { action } => commands::identity::run(action, &ctx).await,
        Commands::Encrypt(args) => commands::encrypt::run(args, &ctx).await,
        Commands::Decrypt(args) => commands::decrypt::run(args, &ctx).await,
        Commands::Account { action } => commands::account::run(action, &ctx).await,
        Commands::File { action } => commands::files::run(action, &ctx).await,
        Commands::Share { action } => commands::share::run(action, &ctx).await,
        Commands::Config { action } => commands::config::run(action, &ctx).await,
        Commands::Wallet { action } => commands::wallet_cmd::run(action, &ctx).await,
    }
}
