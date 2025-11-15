//! # SilverBitcoin CLI
//!
//! Command-line interface for interacting with the SilverBitcoin blockchain.

mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};
use silver_core::SignatureScheme;
use std::path::PathBuf;

use commands::{CallCommand, CodegenCommand, DevNetCommand, KeygenCommand, QueryCommand, SimulateCommand, TransferCommand};

#[derive(Parser)]
#[command(name = "silver")]
#[command(about = "SilverBitcoin blockchain CLI - Fast, Secure, Accessible", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Key management commands
    #[command(subcommand)]
    Keygen(KeygenCommands),
    
    /// Transfer tokens to an address
    Transfer {
        /// Recipient address (hex)
        to: String,
        /// Amount to transfer (in MIST, 1 SBTC = 1,000,000,000 MIST)
        amount: u64,
        /// Sender address or key file (optional, uses default if not specified)
        #[arg(short, long)]
        from: Option<String>,
        /// Fuel budget for transaction
        #[arg(short, long)]
        fuel_budget: Option<u64>,
        /// RPC endpoint URL
        #[arg(short, long, default_value = "http://localhost:9545")]
        rpc_url: String,
    },
    
    /// Query blockchain data
    #[command(subcommand)]
    Query(QueryCommands),
    
    /// Call a Quantum smart contract function
    Call {
        /// Package ID
        package: String,
        /// Module name
        module: String,
        /// Function name
        function: String,
        /// Function arguments (JSON array)
        #[arg(short, long)]
        args: Vec<String>,
        /// Type arguments
        #[arg(short, long)]
        type_args: Vec<String>,
        /// Fuel budget for transaction
        #[arg(short, long)]
        fuel_budget: Option<u64>,
        /// RPC endpoint URL
        #[arg(short, long, default_value = "http://localhost:9545")]
        rpc_url: String,
    },
    
    /// Development network commands
    #[command(subcommand)]
    DevNet(DevNetCommands),
    
    /// Generate Rust bindings from Quantum modules
    Codegen {
        /// Path to Quantum source file
        #[arg(short, long)]
        source: Option<PathBuf>,
        /// Path to compiled bytecode file
        #[arg(short, long)]
        bytecode: Option<PathBuf>,
        /// Output file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Simulate transaction execution without submitting to network
    Simulate {
        /// Transaction type: transfer, call
        #[arg(short, long)]
        tx_type: String,
        /// Transaction parameters (JSON)
        #[arg(short, long)]
        params: String,
        /// Sender address or key file
        #[arg(short, long)]
        sender: Option<String>,
        /// RPC endpoint URL
        #[arg(short, long, default_value = "http://localhost:9545")]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
enum KeygenCommands {
    /// Generate a new keypair
    Generate {
        /// Output format (hex, base64, json)
        #[arg(short, long, default_value = "hex")]
        format: String,
        /// Signature scheme (sphincs-plus, dilithium3, secp512r1, hybrid)
        #[arg(short, long)]
        scheme: Option<String>,
        /// Output file path (if not specified, prints to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Encrypt the private key with a password
        #[arg(short, long)]
        encrypt: bool,
    },
    
    /// Generate a mnemonic phrase
    Mnemonic {
        /// Number of words (12, 15, 18, 21, 24)
        #[arg(short, long, default_value = "24")]
        words: usize,
        /// Output file path (if not specified, prints to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Derive keypair from mnemonic phrase
    FromMnemonic {
        /// Mnemonic phrase (if not provided, will prompt)
        #[arg(short, long)]
        phrase: Option<String>,
        /// Signature scheme
        #[arg(short, long)]
        scheme: Option<String>,
        /// Derivation path (e.g., m/44'/0'/0'/0/0)
        #[arg(short, long)]
        path: Option<String>,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Import a keypair from file
    Import {
        /// Input file path
        input: PathBuf,
        /// Input format (hex, base64, json)
        #[arg(short, long, default_value = "hex")]
        format: String,
        /// Whether the key is encrypted
        #[arg(short, long)]
        encrypted: bool,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Export a keypair to different format
    Export {
        /// Input file path
        input: PathBuf,
        /// Output format (hex, base64, json)
        #[arg(short, long, default_value = "json")]
        format: String,
        /// Output file path
        output: PathBuf,
        /// Encrypt the output
        #[arg(short, long)]
        encrypt: bool,
    },
    
    /// Show address from public key
    Address {
        /// Public key (hex)
        public_key: String,
    },
}

#[derive(Subcommand)]
enum QueryCommands {
    /// Query object by ID
    Object {
        /// Object ID (hex)
        object_id: String,
        /// RPC endpoint URL
        #[arg(short, long, default_value = "http://localhost:9545")]
        rpc_url: String,
    },
    
    /// Query transaction status
    Transaction {
        /// Transaction digest (hex)
        tx_digest: String,
        /// RPC endpoint URL
        #[arg(short, long, default_value = "http://localhost:9545")]
        rpc_url: String,
    },
    
    /// Query objects owned by an address
    Objects {
        /// Owner address (hex)
        owner: String,
        /// RPC endpoint URL
        #[arg(short, long, default_value = "http://localhost:9545")]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
enum DevNetCommands {
    /// Start local development network
    Start {
        /// Number of validators
        #[arg(short, long, default_value = "1")]
        validators: usize,
        /// Data directory
        #[arg(short, long)]
        data_dir: Option<String>,
    },
    
    /// Stop local development network
    Stop,
    
    /// Request test tokens from faucet
    Faucet {
        /// Recipient address (hex)
        address: String,
        /// Amount to request (default: 1,000,000 SBTC)
        #[arg(short, long)]
        amount: Option<u64>,
    },
}

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen(cmd) => handle_keygen(cmd),
        Commands::Transfer { to, amount, from, fuel_budget, rpc_url: _ } => {
            TransferCommand::transfer(&to, amount, from, fuel_budget)
        }
        Commands::Query(cmd) => handle_query(cmd),
        Commands::Call { package, module, function, args, type_args, fuel_budget, rpc_url: _ } => {
            CallCommand::call(&package, &module, &function, args, type_args, fuel_budget)
        }
        Commands::DevNet(cmd) => handle_devnet(cmd),
        Commands::Codegen { source, bytecode, output } => {
            let cmd = CodegenCommand {
                source,
                bytecode,
                output,
                module_helper: true,
            };
            cmd.execute()
        }
        Commands::Simulate { tx_type, params, sender, rpc_url } => {
            SimulateCommand::simulate(&tx_type, &params, sender, &rpc_url)
        }
    }
}

fn handle_keygen(cmd: KeygenCommands) -> Result<()> {
    match cmd {
        KeygenCommands::Generate { format, scheme, output, encrypt } => {
            let sig_scheme = parse_signature_scheme(scheme)?;
            KeygenCommand::generate(&format, sig_scheme, output, encrypt)
        }
        KeygenCommands::Mnemonic { words, output } => {
            KeygenCommand::generate_mnemonic(words, output)
        }
        KeygenCommands::FromMnemonic { phrase, scheme, path, output } => {
            let sig_scheme = parse_signature_scheme(scheme)?;
            KeygenCommand::from_mnemonic(phrase, sig_scheme, path, output)
        }
        KeygenCommands::Import { input, format, encrypted, output } => {
            KeygenCommand::import(input, &format, encrypted, output)
        }
        KeygenCommands::Export { input, format, output, encrypt } => {
            KeygenCommand::export(input, &format, output, encrypt)
        }
        KeygenCommands::Address { public_key } => {
            KeygenCommand::show_address(&public_key)
        }
    }
}

fn handle_query(cmd: QueryCommands) -> Result<()> {
    match cmd {
        QueryCommands::Object { object_id, rpc_url } => {
            QueryCommand::query_object(&object_id, Some(rpc_url))
        }
        QueryCommands::Transaction { tx_digest, rpc_url } => {
            QueryCommand::query_transaction(&tx_digest, Some(rpc_url))
        }
        QueryCommands::Objects { owner, rpc_url } => {
            QueryCommand::query_objects_by_owner(&owner, Some(rpc_url))
        }
    }
}

fn handle_devnet(cmd: DevNetCommands) -> Result<()> {
    match cmd {
        DevNetCommands::Start { validators, data_dir } => {
            DevNetCommand::start(validators, data_dir)
        }
        DevNetCommands::Stop => {
            DevNetCommand::stop()
        }
        DevNetCommands::Faucet { address, amount } => {
            DevNetCommand::faucet(&address, amount)
        }
    }
}

fn parse_signature_scheme(scheme: Option<String>) -> Result<Option<SignatureScheme>> {
    Ok(match scheme.as_deref() {
        Some("sphincs-plus") | Some("sphincs") => Some(SignatureScheme::SphincsPlus),
        Some("dilithium3") | Some("dilithium") => Some(SignatureScheme::Dilithium3),
        Some("secp512r1") | Some("secp") => Some(SignatureScheme::Secp512r1),
        Some("hybrid") => Some(SignatureScheme::Hybrid),
        Some(s) => anyhow::bail!("Unknown signature scheme: {}", s),
        None => None,
    })
}
