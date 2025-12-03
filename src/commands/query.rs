//! Query commands
//!
//! Provides commands for querying blockchain state:
//! - Query objects by ID
//! - Query transaction status and effects
//! - Query objects owned by an address
//!
//! All queries are performed via JSON-RPC to a SilverBitcoin node.

use anyhow::{Context, Result};
use colored::Colorize;
use silver_core::{ObjectID, SilverAddress, TransactionDigest};
use silver_sdk::client::{ClientConfig, TransactionStatus};
use silver_sdk::RpcClient;
use std::time::Duration;
use tracing::debug;

/// Query command
pub struct QueryCommand;

impl QueryCommand {
    /// Query object by ID
    ///
    /// Retrieves an object from the blockchain by its unique identifier.
    /// Displays object contents in human-readable JSON format.
    ///
    /// # Arguments
    /// * `object_id` - Object ID (hex or base58 encoded)
    /// * `rpc_url` - Optional RPC endpoint URL (defaults to http://localhost:9545)
    ///
    /// # Requirements
    /// - Requirement 10.3: Display object contents in JSON format
    /// - Requirement 7.2: Query response time under 100ms
    pub fn query_object(object_id: &str, rpc_url: Option<String>) -> Result<()> {
        let runtime = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;

        runtime.block_on(async { Self::query_object_async(object_id, rpc_url).await })
    }

    async fn query_object_async(object_id: &str, rpc_url: Option<String>) -> Result<()> {
        let url = rpc_url.unwrap_or_else(|| "http://localhost:9545".to_string());

        debug!("Querying object {} from {}", object_id, url);

        // Create RPC client
        let config = ClientConfig {
            url: url.clone(),
            timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let client = RpcClient::with_config(config).context("Failed to create RPC client")?;

        // Parse object ID
        let obj_id = parse_object_id(object_id).context("Invalid object ID format")?;

        // Query object
        println!("{}", "Querying object...".cyan());
        let start = std::time::Instant::now();

        let object = client
            .get_object(obj_id)
            .await
            .context("Failed to query object")?;

        let elapsed = start.elapsed();
        debug!("Query completed in {:?}", elapsed);

        // Display object in JSON format
        println!("\n{}", "Object Details:".green().bold());
        println!("{}", "=".repeat(80).green());

        // Create JSON representation
        let json_obj = serde_json::json!({
            "id": object.id.to_hex(),
            "version": object.version.value(),
            "owner": format!("{}", object.owner),
            "object_type": format!("{}", object.object_type),
            "size_bytes": object.size_bytes(),
            "data": hex::encode(&object.data),
            "previous_transaction": hex::encode(object.previous_transaction.as_bytes()),
        });

        // Pretty print JSON
        let json_str = serde_json::to_string_pretty(&json_obj)
            .context("Failed to serialize object to JSON")?;
        println!("{}", json_str);

        println!("{}", "=".repeat(80).green());
        println!(
            "\n{} Query completed in {:.2}ms",
            "✓".green().bold(),
            elapsed.as_secs_f64() * 1000.0
        );

        // Warn if query took longer than 100ms (requirement 7.2)
        if elapsed.as_millis() > 100 {
            println!(
                "{} Query took {}ms (target: <100ms)",
                "⚠".yellow().bold(),
                elapsed.as_millis()
            );
        }

        Ok(())
    }

    /// Query transaction status
    ///
    /// Retrieves transaction status and execution effects from the blockchain.
    /// Displays transaction data, fuel usage, and execution results.
    ///
    /// # Arguments
    /// * `tx_digest` - Transaction digest (hex encoded)
    /// * `rpc_url` - Optional RPC endpoint URL (defaults to http://localhost:9545)
    ///
    /// # Requirements
    /// - Requirement 10.3: Display transaction status in JSON format
    /// - Requirement 7.2: Query response time under 100ms
    pub fn query_transaction(tx_digest: &str, rpc_url: Option<String>) -> Result<()> {
        let runtime = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;

        runtime.block_on(async { Self::query_transaction_async(tx_digest, rpc_url).await })
    }

    async fn query_transaction_async(tx_digest: &str, rpc_url: Option<String>) -> Result<()> {
        let url = rpc_url.unwrap_or_else(|| "http://localhost:9545".to_string());

        debug!("Querying transaction {} from {}", tx_digest, url);

        // Create RPC client
        let config = ClientConfig {
            url: url.clone(),
            timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let client = RpcClient::with_config(config).context("Failed to create RPC client")?;

        // Parse transaction digest
        let digest =
            parse_transaction_digest(tx_digest).context("Invalid transaction digest format")?;

        // Query transaction
        println!("{}", "Querying transaction...".cyan());
        let start = std::time::Instant::now();

        let tx_response = client
            .get_transaction(digest)
            .await
            .context("Failed to query transaction")?;

        let elapsed = start.elapsed();
        debug!("Query completed in {:?}", elapsed);

        // Display transaction in JSON format
        println!("\n{}", "Transaction Details:".green().bold());
        println!("{}", "=".repeat(80).green());

        // Create JSON representation
        let json_tx = serde_json::json!({
            "digest": hex::encode(tx_response.digest.as_bytes()),
            "status": format!("{:?}", tx_response.status),
            "fuel_used": tx_response.fuel_used,
            "snapshot": tx_response.snapshot,
        });

        // Pretty print JSON
        let json_str = serde_json::to_string_pretty(&json_tx)
            .context("Failed to serialize transaction to JSON")?;
        println!("{}", json_str);

        println!("{}", "=".repeat(80).green());

        // Display status with color coding
        match tx_response.status {
            TransactionStatus::Executed => {
                println!("\n{} Transaction executed successfully", "✓".green().bold());
                if let Some(fuel) = tx_response.fuel_used {
                    println!("  Fuel used: {} units", fuel.to_string().cyan());
                }
                if let Some(snapshot) = tx_response.snapshot {
                    println!("  Finalized in snapshot: {}", snapshot.to_string().cyan());
                }
            }
            TransactionStatus::Pending => {
                println!("\n{} Transaction is pending", "⏳".yellow().bold());
            }
            TransactionStatus::Failed { ref error } => {
                println!("\n{} Transaction failed: {}", "✗".red().bold(), error.red());
            }
        }

        println!(
            "\n{} Query completed in {:.2}ms",
            "✓".green().bold(),
            elapsed.as_secs_f64() * 1000.0
        );

        // Warn if query took longer than 100ms (requirement 7.2)
        if elapsed.as_millis() > 100 {
            println!(
                "{} Query took {}ms (target: <100ms)",
                "⚠".yellow().bold(),
                elapsed.as_millis()
            );
        }

        Ok(())
    }

    /// Query objects by owner
    ///
    /// Retrieves all objects owned by a specific address.
    /// Displays a list of objects with their IDs, types, and versions.
    ///
    /// # Arguments
    /// * `owner` - Owner address (hex or base58 encoded)
    /// * `rpc_url` - Optional RPC endpoint URL (defaults to http://localhost:9545)
    ///
    /// # Requirements
    /// - Requirement 10.3: Display object contents in JSON format
    /// - Requirement 7.2: Query response time under 100ms
    pub fn query_objects_by_owner(owner: &str, rpc_url: Option<String>) -> Result<()> {
        let runtime = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;

        runtime.block_on(async { Self::query_objects_by_owner_async(owner, rpc_url).await })
    }

    async fn query_objects_by_owner_async(owner: &str, rpc_url: Option<String>) -> Result<()> {
        let url = rpc_url.unwrap_or_else(|| "http://localhost:9545".to_string());

        debug!("Querying objects for owner {} from {}", owner, url);

        // Create RPC client
        let config = ClientConfig {
            url: url.clone(),
            timeout: Duration::from_secs(10),
            ..Default::default()
        };
        let client = RpcClient::with_config(config).context("Failed to create RPC client")?;

        // Parse owner address
        let owner_addr = parse_address(owner).context("Invalid owner address format")?;

        // Query objects
        println!("{}", "Querying objects...".cyan());
        let start = std::time::Instant::now();

        let objects = client
            .get_objects_owned_by(owner_addr)
            .await
            .context("Failed to query objects")?;

        let elapsed = start.elapsed();
        debug!("Query completed in {:?}", elapsed);

        // Display objects in JSON format
        println!("\n{}", "Objects Owned:".green().bold());
        println!("{}", "=".repeat(80).green());

        if objects.is_empty() {
            println!("{}", "No objects found for this address".yellow());
        } else {
            println!(
                "Found {} object(s)\n",
                objects.len().to_string().cyan().bold()
            );

            // Create JSON array of objects
            let json_objects: Vec<serde_json::Value> = objects
                .iter()
                .map(|obj_ref| {
                    serde_json::json!({
                        "object_id": obj_ref.id.to_hex(),
                        "version": obj_ref.version.value(),
                        "digest": hex::encode(obj_ref.digest.as_bytes()),
                    })
                })
                .collect();

            // Pretty print JSON
            let json_str = serde_json::to_string_pretty(&json_objects)
                .context("Failed to serialize objects to JSON")?;
            println!("{}", json_str);
        }

        println!("{}", "=".repeat(80).green());
        println!(
            "\n{} Query completed in {:.2}ms",
            "✓".green().bold(),
            elapsed.as_secs_f64() * 1000.0
        );

        // Warn if query took longer than 100ms (requirement 7.2)
        if elapsed.as_millis() > 100 {
            println!(
                "{} Query took {}ms (target: <100ms)",
                "⚠".yellow().bold(),
                elapsed.as_millis()
            );
        }

        Ok(())
    }
}

// Helper functions

/// Parse object ID from hex or base58 string
fn parse_object_id(s: &str) -> Result<ObjectID> {
    // Try hex first
    if let Ok(id) = ObjectID::from_hex(s) {
        return Ok(id);
    }

    // Try base58
    if let Ok(id) = ObjectID::from_base58(s) {
        return Ok(id);
    }

    anyhow::bail!("Invalid object ID format. Expected hex or base58 encoded 64-byte ID")
}

/// Parse address from hex or base58 string
fn parse_address(s: &str) -> Result<SilverAddress> {
    // Try hex first
    if let Ok(addr) = SilverAddress::from_hex(s) {
        return Ok(addr);
    }

    // Try base58
    if let Ok(addr) = SilverAddress::from_base58(s) {
        return Ok(addr);
    }

    anyhow::bail!("Invalid address format. Expected hex or base58 encoded 64-byte address")
}

/// Parse transaction digest from hex string
fn parse_transaction_digest(s: &str) -> Result<TransactionDigest> {
    let bytes = hex::decode(s).context("Invalid hex encoding")?;

    if bytes.len() != 64 {
        anyhow::bail!(
            "Transaction digest must be 64 bytes, got {} bytes",
            bytes.len()
        );
    }

    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(TransactionDigest::new(arr))
}
