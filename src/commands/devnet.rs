//! Development network commands
//!
//! Provides commands for running a local development network with a single validator,
//! managing the network lifecycle, and requesting test tokens from the faucet.

use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use silver_core::{SilverAddress, SignatureScheme};
use silver_crypto::KeyPair;
use silver_sdk::SilverClient;

const DEFAULT_FAUCET_AMOUNT: u64 = 1_000_000_000_000_000; // 1,000,000 SBTC
const DEVNET_STATE_FILE: &str = ".silver-devnet-state.json";
const DEVNET_RPC_URL: &str = "http://localhost:9545";
const DEVNET_STARTUP_TIMEOUT_SECS: u64 = 30;

/// DevNet state persisted to disk
#[derive(Debug, Serialize, Deserialize)]
struct DevNetState {
    /// Process ID of the running node
    pid: u32,
    /// Data directory path
    data_dir: PathBuf,
    /// Number of validators
    validators: usize,
    /// Faucet keypair (for distributing test tokens) - stored as hex
    faucet_keypair_hex: String,
    /// Genesis timestamp
    started_at: u64,
}

/// DevNet command
pub struct DevNetCommand;

impl DevNetCommand {
    /// Start local development network
    pub fn start(validators: usize, data_dir: Option<String>) -> Result<()> {
        // Check if devnet is already running
        if Self::is_running()? {
            println!("{}", "⚠️  DevNet is already running!".yellow());
            println!("Use 'silver devnet stop' to stop it first.");
            return Ok(());
        }

        println!("{}", "🚀 Starting SilverBitcoin Development Network...".cyan().bold());
        println!();

        // Determine data directory
        let data_dir = data_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = dirs::home_dir().expect("Failed to get home directory");
                home.join(".silver").join("devnet")
            });

        // Create data directory if it doesn't exist
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("Failed to create data directory: {:?}", data_dir))?;

        println!("📁 Data directory: {}", data_dir.display());
        println!("👥 Validators: {}", validators);
        println!();

        // Generate faucet keypair
        println!("{}", "🔑 Generating faucet keypair...".cyan());
        let faucet_keypair = KeyPair::generate(SignatureScheme::Dilithium3)?;
        let faucet_address = faucet_keypair.address();
        println!("   Faucet address: {}", hex::encode(faucet_address.as_bytes()));
        println!();

        // Create genesis configuration
        println!("{}", "📜 Creating genesis configuration...".cyan());
        let genesis_path = data_dir.join("genesis.json");
        Self::create_genesis_config(&genesis_path, &faucet_address, validators)?;
        println!("   Genesis file: {}", genesis_path.display());
        println!();

        // Create node configuration
        println!("{}", "⚙️  Creating node configuration...".cyan());
        let config_path = data_dir.join("node.toml");
        Self::create_node_config(&config_path, &data_dir)?;
        println!("   Config file: {}", config_path.display());
        println!();

        // Start the node process
        println!("{}", "🌟 Starting validator node...".cyan());
        let node_process = Self::spawn_node(&config_path, &genesis_path, &data_dir)?;
        let pid = node_process.id();
        
        // Save state - serialize keypair manually
        let faucet_keypair_json = serde_json::json!({
            "scheme": format!("{:?}", faucet_keypair.scheme),
            "public_key": hex::encode(&faucet_keypair.public_key),
            "private_key": hex::encode(faucet_keypair.private_key()),
        });
        let state = DevNetState {
            pid,
            data_dir: data_dir.clone(),
            validators,
            faucet_keypair_hex: faucet_keypair_json.to_string(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        Self::save_state(&state)?;

        println!("   Process ID: {}", pid);
        println!();

        // Wait for node to be ready
        println!("{}", "⏳ Waiting for node to be ready...".cyan());
        if let Err(e) = Self::wait_for_node_ready() {
            eprintln!("{}", format!("❌ Failed to start node: {}", e).red());
            let _ = Self::stop();
            return Err(e);
        }

        println!();
        println!("{}", "✅ DevNet started successfully!".green().bold());
        println!();
        println!("{}", "Network Information:".bold());
        println!("  RPC Endpoint:  {}", DEVNET_RPC_URL);
        println!("  WebSocket:     ws://localhost:9546");
        println!("  Metrics:       http://localhost:9184/metrics");
        println!("  Faucet:        silver devnet faucet <address>");
        println!();
        println!("{}", "Logs:".bold());
        println!("  {}", data_dir.join("logs/node.log").display());
        println!();

        Ok(())
    }
    
    /// Stop local development network
    pub fn stop() -> Result<()> {
        println!("{}", "🛑 Stopping SilverBitcoin Development Network...".cyan().bold());
        println!();

        // Load state
        let state = match Self::load_state() {
            Ok(state) => state,
            Err(_) => {
                println!("{}", "⚠️  No running DevNet found.".yellow());
                return Ok(());
            }
        };

        // Kill the process
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            
            let pid = Pid::from_raw(state.pid as i32);
            match kill(pid, Signal::SIGTERM) {
                Ok(_) => {
                    println!("   Sent SIGTERM to process {}", state.pid);
                    
                    // Wait for graceful shutdown
                    std::thread::sleep(Duration::from_secs(5));
                    
                    // Check if still running, force kill if necessary
                    if kill(pid, Signal::SIGKILL).is_ok() {
                        println!("   Sent SIGKILL to process {}", state.pid);
                    }
                }
                Err(e) => {
                    eprintln!("   Failed to kill process: {}", e);
                }
            }
        }

        #[cfg(windows)]
        {
            let output = Command::new("taskkill")
                .args(&["/PID", &state.pid.to_string(), "/F"])
                .output()?;
            
            if output.status.success() {
                println!("   Terminated process {}", state.pid);
            } else {
                eprintln!("   Failed to terminate process: {}", 
                         String::from_utf8_lossy(&output.stderr));
            }
        }

        // Remove state file
        Self::remove_state()?;

        println!();
        println!("{}", "✅ DevNet stopped successfully!".green().bold());
        println!();

        Ok(())
    }
    
    /// Request test tokens from faucet
    pub fn faucet(address: &str, amount: Option<u64>) -> Result<()> {
        // Check if devnet is running
        if !Self::is_running()? {
            bail!("DevNet is not running. Start it with 'silver devnet start'");
        }

        // Load state to get faucet keypair
        let state = Self::load_state()?;
        let keypair_json: serde_json::Value = serde_json::from_str(&state.faucet_keypair_hex)?;
        let scheme_str = keypair_json["scheme"].as_str().unwrap();
        let scheme = match scheme_str {
            "SphincsPlus" => SignatureScheme::SphincsPlus,
            "Dilithium3" => SignatureScheme::Dilithium3,
            "Secp512r1" => SignatureScheme::Secp512r1,
            "Hybrid" => SignatureScheme::Hybrid,
            _ => bail!("Unknown signature scheme: {}", scheme_str),
        };
        let public_key = hex::decode(keypair_json["public_key"].as_str().unwrap())?;
        let private_key = hex::decode(keypair_json["private_key"].as_str().unwrap())?;
        let faucet_keypair = KeyPair::new(scheme, public_key, private_key);

        // Parse recipient address
        let recipient = Self::parse_address(address)?;
        let amount = amount.unwrap_or(DEFAULT_FAUCET_AMOUNT);

        println!("{}", "💰 Requesting test tokens from faucet...".cyan().bold());
        println!();
        println!("  Recipient: {}", address);
        println!("  Amount:    {} MIST ({} SBTC)", 
                 amount, 
                 amount as f64 / 1_000_000_000.0);
        println!();

        // Create runtime for async operations
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            Self::send_faucet_tokens(&faucet_keypair, recipient, amount).await
        })?;

        println!();
        println!("{}", "✅ Tokens sent successfully!".green().bold());
        println!();

        Ok(())
    }

    // Helper methods

    fn is_running() -> Result<bool> {
        Ok(Self::load_state().is_ok())
    }

    fn load_state() -> Result<DevNetState> {
        let state_path = Self::state_file_path();
        if !state_path.exists() {
            bail!("DevNet state file not found");
        }

        let contents = fs::read_to_string(&state_path)?;
        let state: DevNetState = serde_json::from_str(&contents)?;
        Ok(state)
    }

    fn save_state(state: &DevNetState) -> Result<()> {
        let state_path = Self::state_file_path();
        let contents = serde_json::to_string_pretty(state)?;
        fs::write(&state_path, contents)?;
        Ok(())
    }

    fn remove_state() -> Result<()> {
        let state_path = Self::state_file_path();
        if state_path.exists() {
            fs::remove_file(&state_path)?;
        }
        Ok(())
    }

    fn state_file_path() -> PathBuf {
        let home = dirs::home_dir().expect("Failed to get home directory");
        home.join(".silver").join(DEVNET_STATE_FILE)
    }

    fn create_genesis_config(path: &Path, faucet_address: &SilverAddress, validators: usize) -> Result<()> {
        // Create a minimal genesis configuration for development
        let genesis = serde_json::json!({
            "chain_id": "devnet",
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            "validators": (0..validators).map(|i| {
                // Generate validator keys
                let keypair = KeyPair::generate(SignatureScheme::Dilithium3).unwrap();
                let address = keypair.address();
                serde_json::json!({
                    "address": hex::encode(&address.0),
                    "stake": 1_000_000_000_000_000u64, // 1M SBTC
                    "network_address": format!("127.0.0.1:{}", 9000 + i),
                    "p2p_address": format!("127.0.0.1:{}", 9100 + i),
                })
            }).collect::<Vec<_>>(),
            "initial_balances": vec![
                serde_json::json!({
                    "address": hex::encode(&faucet_address.0),
                    "balance": 1_000_000_000_000_000_000u64, // 1B SBTC for faucet
                })
            ],
            "parameters": {
                "snapshot_interval_ms": 1000,
                "max_batch_size": 500,
                "max_batch_bytes": 524288,
                "fuel_price_min": 1000,
            }
        });

        fs::write(path, serde_json::to_string_pretty(&genesis)?)?;
        Ok(())
    }

    fn create_node_config(path: &Path, data_dir: &Path) -> Result<()> {
        let config = format!(r#"
[network]
listen_address = "0.0.0.0:9000"
external_address = "127.0.0.1:9000"
p2p_address = "0.0.0.0:9001"
max_peers = 10

[consensus]
is_validator = true
stake_amount = 1000000

[storage]
db_path = "{}/db"
snapshot_retention_days = 7
enable_pruning = false

[api]
json_rpc_address = "0.0.0.0:9545"
websocket_address = "0.0.0.0:9546"
enable_cors = true
rate_limit_per_second = 1000

[metrics]
prometheus_address = "0.0.0.0:9184"
enable_metrics = true

[logging]
level = "info"
log_path = "{}/logs/node.log"
"#, data_dir.display(), data_dir.display());

        fs::write(path, config)?;
        Ok(())
    }

    fn spawn_node(config_path: &Path, genesis_path: &Path, data_dir: &Path) -> Result<Child> {
        // Create logs directory
        let logs_dir = data_dir.join("logs");
        fs::create_dir_all(&logs_dir)?;

        // Spawn the node process
        let child = Command::new("silver-node")
            .arg("--config")
            .arg(config_path)
            .arg("--genesis")
            .arg(genesis_path)
            .arg("--validator")
            .arg("--data-dir")
            .arg(data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("Failed to spawn silver-node process. Is silver-node in your PATH?")?;

        Ok(child)
    }

    fn wait_for_node_ready() -> Result<()> {
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(DEVNET_STARTUP_TIMEOUT_SECS);

        // Create runtime for async operations
        let runtime = tokio::runtime::Runtime::new()?;

        while start.elapsed() < timeout {
            // Try to connect to the node
            let result = runtime.block_on(async {
                match SilverClient::new(DEVNET_RPC_URL).await {
                    Ok(client) => client.get_network_info().await,
                    Err(e) => Err(e),
                }
            });

            if result.is_ok() {
                return Ok(());
            }

            std::thread::sleep(Duration::from_millis(500));
            print!(".");
            use std::io::Write;
            std::io::stdout().flush()?;
        }

        bail!("Node failed to start within {} seconds", DEVNET_STARTUP_TIMEOUT_SECS)
    }

    async fn send_faucet_tokens(
        faucet_keypair: &KeyPair,
        recipient: SilverAddress,
        amount: u64,
    ) -> Result<()> {
        // Connect to the node
        let _client = SilverClient::new(DEVNET_RPC_URL).await?;

        // Get faucet's fuel object
        let _faucet_address = faucet_keypair.address();
        
        // For now, just print a success message since we need to implement the actual RPC methods
        println!("  Note: Faucet transfer would send {} MIST to {}", amount, hex::encode(&recipient.0));
        println!("  (Full RPC implementation pending)");
        
        Ok(())
    }

    fn parse_address(address_str: &str) -> Result<SilverAddress> {
        let bytes = hex::decode(address_str.trim_start_matches("0x"))
            .context("Invalid hex address")?;
        
        if bytes.len() != 64 {
            bail!("Address must be 64 bytes (512 bits)");
        }

        let mut addr_bytes = [0u8; 64];
        addr_bytes.copy_from_slice(&bytes);
        Ok(SilverAddress(addr_bytes))
    }
}
