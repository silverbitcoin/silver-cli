//! # SilverBitcoin CLI
//!
//! Command-line interface for interacting with the SilverBitcoin blockchain.

mod commands;
mod deployer;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use commands::{
    CallCommand, CodegenCommand, DevNetCommand, KeygenCommand, QueryCommand, SimulateCommand,
    TransferCommand,
};

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
    /// 
    /// Sender determination:
    /// - Default: Uses keypair from ~/.silver/keypair.json
    /// - Custom: Use --from <path> to specify different keypair file
    /// 
    /// Amount is in SBTC (automatically converted to MIST)
    /// Example: silver transfer <recipient> 1 (sends 1 SBTC)
    Transfer {
        /// Recipient address (64-byte hex)
        to: String,
        /// Amount to transfer in SBTC (automatically converted to MIST)
        /// Example: 1 = 1 SBTC = 1,000,000,000 MIST
        amount: u64,
        /// Path to sender's keypair file (optional)
        /// Default: ~/.silver/keypair.json
        /// The sender address is derived from this keypair
        #[arg(short = 'f', long, value_name = "PATH")]
        from: Option<String>,
        /// Fuel budget for transaction (optional)
        #[arg(short = 'b', long)]
        fuel_budget: Option<u64>,
        /// RPC endpoint URL
        #[arg(short = 'r', long, default_value = "http://localhost:9545")]
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

    /// Deployer account management
    #[command(subcommand)]
    Deployer(DeployerCommands),
}

#[derive(Subcommand)]
enum DeployerCommands {
    /// Generate a new deployer account
    Generate {
        /// Output directory for keys
        #[arg(short, long, default_value = "./deployer")]
        output: PathBuf,
        /// Network name
        #[arg(short, long, default_value = "silverbitcoin")]
        network: String,
        /// RPC URL
        #[arg(short, long, default_value = "https://rpc.silverbitcoin.org")]
        rpc_url: String,
    },

    /// Show deployer account information
    Show {
        /// Deployer directory
        #[arg(short, long, default_value = "./deployer")]
        dir: PathBuf,
    },

    /// Deploy tokens using deployer account
    Deploy {
        /// Deployer directory
        #[arg(short, long, default_value = "./deployer")]
        dir: PathBuf,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
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

#[tokio::main]
async fn main() -> Result<()> {
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
        Commands::Transfer {
            to,
            amount,
            from,
            fuel_budget,
            rpc_url,
        } => TransferCommand::transfer(&to, amount, from, fuel_budget, &rpc_url).await,
        Commands::Query(cmd) => handle_query(cmd),
        Commands::Call {
            package,
            module,
            function,
            args,
            type_args,
            fuel_budget,
            rpc_url: _,
        } => CallCommand::call(&package, &module, &function, args, type_args, fuel_budget).await,
        Commands::DevNet(cmd) => handle_devnet(cmd),
        Commands::Codegen {
            source,
            bytecode,
            output,
        } => {
            let cmd = CodegenCommand {
                source,
                bytecode,
                output,
                module_helper: true,
            };
            cmd.execute()
        }
        Commands::Simulate {
            tx_type,
            params,
            sender,
            rpc_url,
        } => SimulateCommand::simulate(&tx_type, &params, sender, &rpc_url),
        Commands::Deployer(cmd) => handle_deployer(cmd),
    }
}

fn handle_deployer(cmd: DeployerCommands) -> Result<()> {
    use crate::deployer::DeployerKeypair;

    match cmd {
        DeployerCommands::Generate {
            output,
            network,
            rpc_url,
        } => {
            println!("Generating deployer account...");
            let keypair = match DeployerKeypair::generate() {
                Ok(kp) => kp,
                Err(crate::deployer::DeployerError::KeypairGenerationFailed(msg)) => {
                    anyhow::bail!("Keypair generation failed: {}", msg);
                }
                Err(crate::deployer::DeployerError::AddressDerivationFailed(msg)) => {
                    anyhow::bail!("Address derivation failed: {}", msg);
                }
                Err(e) => {
                    anyhow::bail!("Failed to generate keypair: {}", e);
                }
            };
            let paths = keypair.save(&output)?;

            println!("\n✅ Deployer account created successfully!\n");
            println!("Address: {}", keypair.address_hex());
            println!("Network: {}", network);
            println!("RPC URL: {}\n", rpc_url);
            println!("Files saved to: {}\n", output.display());
            println!("  - Private Key: {}", paths.private_key.display());
            println!("  - Public Key: {}", paths.public_key.display());
            println!("  - Address: {}", paths.address.display());
            println!("  - Config: {}\n", paths.config.display());
            println!("⚠️  Keep the private key file secure!\n");
            
            // Verify by loading the keypair back
            match DeployerKeypair::load(&paths.private_key, &paths.public_key) {
                Ok(loaded_keypair) => {
                    if loaded_keypair.address_hex() == keypair.address_hex() {
                        println!("✅ Keypair verification: PASSED");
                        println!("   Loaded address matches generated address\n");
                    } else {
                        eprintln!("❌ Keypair verification: FAILED");
                        eprintln!("   Address mismatch!\n");
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  Could not verify keypair: {}\n", e);
                }
            }

            Ok(())
        }
        DeployerCommands::Show { dir } => {
            let config_path = dir.join("deployer.env");
            if !config_path.exists() {
                anyhow::bail!("Deployer config not found at {}", config_path.display());
            }

            let config = crate::deployer::DeployerConfig::load(&config_path)?;
            println!("\n📋 Deployer Account Information\n");
            println!("Address: {}", config.deployer_address);
            println!("Network: {}", config.network);
            println!("RPC URL: {}", config.rpc_url);
            println!("Creation Fee: {}", config.creation_fee);
            println!("Token Owner: {}\n", config.token_owner);
            
            // Get current balance
            match config.get_balance() {
                Ok(balance) => {
                    println!("💰 Current Balance: {} satoshis", balance);
                    println!("   ({} BTC)\n", balance as f64 / 100_000_000.0);
                }
                Err(e) => {
                    eprintln!("⚠️  Could not retrieve balance: {}\n", e);
                }
            }
            
            // Verify configuration is valid and save it back (for persistence)
            let backup_path = dir.join("deployer.env.backup");
            if let Err(e) = config.save(&backup_path) {
                eprintln!("⚠️  Could not create backup: {}", e);
            } else {
                println!("✅ Configuration backup saved to: {}", backup_path.display());
            }

            Ok(())
        }
        DeployerCommands::Deploy { dir, verbose } => {
            let config_path = dir.join("deployer.env");
            if !config_path.exists() {
                anyhow::bail!("Deployer config not found at {}", config_path.display());
            }

            let config = crate::deployer::DeployerConfig::load(&config_path)?;
            
            if verbose {
                println!("\n🚀 Deploying tokens with deployer account (VERBOSE MODE)...\n");
                println!("Config file: {}", config_path.display());
            } else {
                println!("\n🚀 Deploying tokens with deployer account...\n");
            }
            
            println!("Address: {}", config.deployer_address);
            println!("Network: {}", config.network);
            println!("RPC URL: {}\n", config.rpc_url);
            
            if verbose {
                println!("Private Key: {}", config.deployer_private_key);
                println!("Public Key: {}", config.deployer_public_key);
                println!("Creation Fee: {}", config.creation_fee);
                println!("Token Owner: {}\n", config.token_owner);
            }

            // Verify deployer is funded
            let min_balance = config.creation_fee.parse::<u128>()
                .unwrap_or(1_000_000);
            
            match config.verify_funded(min_balance) {
                Ok(balance) => {
                    if verbose {
                        println!("✅ Deployer account is funded!");
                        println!("   Balance: {} satoshis\n", balance);
                    }
                }
                Err(crate::deployer::DeployerError::DeployerNotFunded) => {
                    eprintln!("❌ Deployer account is not funded");
                    anyhow::bail!("Deployer not funded");
                }
                Err(crate::deployer::DeployerError::InsufficientBalance { required, available }) => {
                    eprintln!("❌ Insufficient balance");
                    eprintln!("   Required: {} satoshis", required);
                    eprintln!("   Available: {} satoshis\n", available);
                    anyhow::bail!("Insufficient balance");
                }
                Err(e) => {
                    eprintln!("❌ Deployer account verification failed: {}", e);
                    anyhow::bail!("Verification failed");
                }
            }

            // Deploy sample tokens
            let tokens = vec![
                ("SilverBitcoin", "SBTC", 21_000_000u128),
                ("SilverToken", "SILVER", 1_000_000_000u128),
            ];

            let mut deployed_tokens = Vec::new();
            for (name, symbol, supply) in tokens {
                match config.deploy_token(name, symbol, supply) {
                    Ok(tx_hash) => {
                        deployed_tokens.push((symbol, tx_hash.clone()));
                        println!("✅ Deployed {}: {}", symbol, tx_hash);
                        if verbose {
                            println!("   Name: {}", name);
                            println!("   Supply: {}\n", supply);
                        }
                    }
                    Err(crate::deployer::DeployerError::DeploymentFailed(msg)) => {
                        eprintln!("❌ Deployment failed for {}: {}", symbol, msg);
                    }
                    Err(crate::deployer::DeployerError::TransactionFailed(msg)) => {
                        eprintln!("❌ Transaction failed for {}: {}", symbol, msg);
                    }
                    Err(crate::deployer::DeployerError::RpcConnectionFailed(msg)) => {
                        eprintln!("❌ RPC connection failed for {}: {}", symbol, msg);
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to deploy {}: {}", symbol, e);
                    }
                }
            }

            // Save deployment results
            let results_path = dir.join("deployment_results.txt");
            let mut results = String::from("=== Token Deployment Results ===\n\n");
            results.push_str(&format!("Deployer: {}\n", config.deployer_address));
            results.push_str(&format!("Network: {}\n", config.network));
            results.push_str(&format!("RPC URL: {}\n\n", config.rpc_url));
            results.push_str("Deployed Tokens:\n");
            
            for (symbol, tx_hash) in &deployed_tokens {
                results.push_str(&format!("  {} - {}\n", symbol, tx_hash));
            }

            std::fs::write(&results_path, results)
                .map_err(|e| anyhow::anyhow!("Failed to save results: {}", e))?;

            println!("\n✅ Deployment complete!");
            println!("Results saved to: {}", results_path.display());
            println!("Deployed {} tokens", deployed_tokens.len());

            Ok(())
        }
    }
}

fn handle_keygen(cmd: KeygenCommands) -> Result<()> {
    match cmd {
        KeygenCommands::Generate {
            format,
            scheme,
            output,
            encrypt,
        } => {
            KeygenCommand::generate(&format, scheme, output, encrypt)?;
            Ok(())
        }
        KeygenCommands::Mnemonic { words, output } => {
            KeygenCommand::generate_mnemonic(words, output)
        }
        KeygenCommands::FromMnemonic {
            phrase,
            scheme,
            path,
            output,
        } => {
            KeygenCommand::from_mnemonic(phrase, scheme, path, output)
        }
        KeygenCommands::Import {
            input,
            format,
            encrypted,
            output,
        } => KeygenCommand::import(input, &format, encrypted, output),
        KeygenCommands::Export {
            input,
            format,
            output,
            encrypt,
        } => KeygenCommand::export(input, &format, output, encrypt),
        KeygenCommands::Address { public_key } => KeygenCommand::show_address(&public_key),
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
        DevNetCommands::Start {
            validators,
            data_dir,
        } => DevNetCommand::start(validators, data_dir),
        DevNetCommands::Stop => DevNetCommand::stop(),
        DevNetCommands::Faucet { address, amount } => DevNetCommand::faucet(&address, amount),
    }
}
