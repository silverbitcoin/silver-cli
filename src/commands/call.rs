//! Quantum function call commands

use anyhow::{Context, Result};
use colored::Colorize;
use silver_core::transaction::TypeTag;
use silver_core::{ObjectID, ObjectRef, SequenceNumber, TransactionDigest};
use silver_crypto::KeyPair;
use silver_sdk::{CallArgBuilder, TransactionBuilder, TypeTagBuilder};
use std::fs;
use std::path::PathBuf;
use reqwest;

/// Call command
pub struct CallCommand;

impl CallCommand {
    /// Call a Quantum function
    pub async fn call(
        package: &str,
        module: &str,
        function: &str,
        args: Vec<String>,
        type_args: Vec<String>,
        fuel_budget: Option<u64>,
    ) -> Result<()> {
        println!("{}", "🔮 Preparing Quantum function call...".cyan().bold());

        // Parse package ID
        let package_bytes = hex::decode(package).context("Invalid package ID (must be hex)")?;

        if package_bytes.len() != 64 {
            anyhow::bail!("Package ID must be 64 bytes (128 hex characters)");
        }

        let mut package_array = [0u8; 64];
        package_array.copy_from_slice(&package_bytes);
        let package_id = ObjectID::new(package_array);

        println!("Package: {}", package);
        println!("Module: {}", module);
        println!("Function: {}", function);
        println!("Arguments: {:?}", args);
        println!("Type arguments: {:?}", type_args);

        // Parse type arguments
        let type_arguments = Self::parse_type_args(&type_args)?;

        // Parse function arguments
        let arguments = Self::parse_call_args(&args)?;

        // Load sender keypair
        let keypair = Self::load_default_keypair()?;
        let sender = keypair.address();

        println!("\nSender: {}", hex::encode(sender.as_bytes()));

        // Get fuel payment object from RPC
        println!("\n{}", "Querying owned objects from RPC...".cyan());
        
        let fuel_payment = match Self::query_fuel_payment_from_rpc(&sender).await {
            Ok(payment) => {
                println!("Found fuel payment object: {}", hex::encode(payment.id.as_bytes()));
                payment
            }
            Err(e) => {
                eprintln!("Failed to query fuel payment from RPC: {}", e);
                println!("Falling back to manual input...");
                Self::prompt_fuel_payment()?
            }
        };

        // Build transaction
        let fuel_budget = fuel_budget.unwrap_or(50_000); // Higher default for contract calls
        let fuel_price = 1000;

        println!("\n{}", "Building transaction...".cyan());
        println!("Fuel budget: {} units", fuel_budget);
        println!("Fuel price: {} MIST/unit", fuel_price);

        let transaction = TransactionBuilder::new()
            .sender(sender)
            .fuel_payment(fuel_payment)
            .fuel_budget(fuel_budget)
            .fuel_price(fuel_price)
            .call(package_id, module, function, type_arguments, arguments)?
            .build_and_sign(&keypair)
            .context("Failed to build and sign transaction")?;

        println!("\n{}", "✓ Transaction built and signed!".green().bold());

        // Display transaction details
        println!("\n{}", "Transaction Details:".yellow().bold());
        println!("Digest: {}", hex::encode(transaction.digest().as_bytes()));
        println!("Sender: {}", hex::encode(transaction.sender().as_bytes()));
        println!("Fuel budget: {}", transaction.fuel_budget());

        // Serialize and save
        let tx_bytes =
            bincode::serialize(&transaction).context("Failed to serialize transaction")?;

        let tx_file = PathBuf::from("call_transaction.bin");
        fs::write(&tx_file, &tx_bytes).context("Failed to write transaction to file")?;

        println!(
            "\n{}",
            format!("✓ Transaction saved to: {}", tx_file.display()).green()
        );
        println!(
            "\n{}",
            "Submit with: silver submit call_transaction.bin".cyan()
        );

        Ok(())
    }

    /// Parse type arguments from strings
    fn parse_type_args(type_args: &[String]) -> Result<Vec<TypeTag>> {
        let mut result = Vec::new();

        for arg in type_args {
            let type_tag = match arg.as_str() {
                "bool" => TypeTagBuilder::bool(),
                "u8" => TypeTagBuilder::u8(),
                "u64" => TypeTagBuilder::u64(),
                "u128" => TypeTagBuilder::u128(),
                "address" => TypeTagBuilder::address(),
                s if s.starts_with("vector<") && s.ends_with('>') => {
                    let inner = &s[7..s.len() - 1];
                    let inner_type = Self::parse_type_args(&[inner.to_string()])?;
                    if inner_type.len() != 1 {
                        anyhow::bail!("Invalid vector type: {}", s);
                    }
                    TypeTagBuilder::vector(inner_type[0].clone())
                }
                _ => anyhow::bail!("Unsupported type argument: {}", arg),
            };
            result.push(type_tag);
        }

        Ok(result)
    }

    /// Parse call arguments from strings
    fn parse_call_args(args: &[String]) -> Result<Vec<silver_core::transaction::CallArg>> {
        let mut result = Vec::new();

        for arg in args {
            // Try to parse as JSON
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(arg) {
                // Serialize the JSON value as pure bytes
                let bytes =
                    bincode::serialize(&json_value).context("Failed to serialize argument")?;
                result.push(CallArgBuilder::pure(bytes));
            } else {
                // Try as hex-encoded bytes
                if let Ok(bytes) = hex::decode(arg) {
                    result.push(CallArgBuilder::pure(bytes));
                } else {
                    anyhow::bail!("Invalid argument format: {}", arg);
                }
            }
        }

        Ok(result)
    }

    /// Load default keypair
    fn load_default_keypair() -> Result<KeyPair> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let key_path = format!("{}/.silver/keypair", home);

        if !std::path::Path::new(&key_path).exists() {
            anyhow::bail!(
                "Keypair file not found: {}\n\
                 Generate a keypair with: silver keygen generate --output {}",
                key_path,
                key_path
            );
        }

        // Load keypair from file
        let key_data = std::fs::read_to_string(&key_path)
            .context(format!("Failed to read keypair file: {}", key_path))?;

        // Parse keypair from JSON or binary format
        let keypair = if key_path.ends_with(".json") {
            let json: serde_json::Value =
                serde_json::from_str(&key_data).context("Failed to parse keypair JSON")?;

            let scheme_str = json
                .get("scheme")
                .and_then(|s| s.as_str())
                .context("Missing 'scheme' field in keypair")?;

            let scheme = match scheme_str {
                "sphincs_plus" => silver_core::SignatureScheme::SphincsPlus,
                "dilithium3" => silver_core::SignatureScheme::Dilithium3,
                "secp512r1" => silver_core::SignatureScheme::Secp512r1,
                "hybrid" => silver_core::SignatureScheme::Hybrid,
                _ => anyhow::bail!("Unknown signature scheme: {}", scheme_str),
            };

            let private_key_hex = json
                .get("private_key")
                .and_then(|k| k.as_str())
                .context("Missing 'private_key' field in keypair")?;

            let private_key =
                hex::decode(private_key_hex).context("Failed to decode private key hex")?;

            // Extract public key
            let public_key_hex = json
                .get("public_key")
                .and_then(|v| v.as_str())
                .context("Missing 'public_key' field in keypair")?;

            let public_key =
                hex::decode(public_key_hex).context("Failed to decode public key hex")?;

            // Use the provided keys
            KeyPair::new(scheme, public_key, private_key)
        } else {
            // Binary format - assume it's a complete keypair serialization
            let key_bytes = hex::decode(&key_data).context("Failed to decode keypair hex")?;

            // For binary format, we need to deserialize properly
            if key_bytes.len() < 32 {
                return Err(anyhow::anyhow!("Invalid keypair binary format"));
            }

            // Split into public and private key parts
            let split_point = key_bytes.len() / 2;
            let public_key = key_bytes[..split_point].to_vec();
            let private_key = key_bytes[split_point..].to_vec();

            KeyPair::new(
                silver_core::SignatureScheme::Dilithium3,
                public_key,
                private_key,
            )
        };

        Ok(keypair)
    }

    /// Query fuel payment object from RPC
    async fn query_fuel_payment_from_rpc(sender: &silver_core::SilverAddress) -> Result<ObjectRef> {
        // Query RPC endpoint for owned objects
        let rpc_url = std::env::var("SILVER_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:9000".to_string());

        let client = reqwest::Client::new();
        
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "silver_getObjectsByOwner",
            "params": [{
                "owner": hex::encode(sender.as_bytes())
            }]
        });

        let response = client
            .post(&rpc_url)
            .json(&request)
            .send()
            .await
            .context("Failed to query RPC endpoint")?;

        let result: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse RPC response")?;

        // Extract first object as fuel payment
        let objects = result
            .get("result")
            .and_then(|r| r.as_array())
            .context("Invalid RPC response format")?;

        if objects.is_empty() {
            anyhow::bail!("No objects found for sender address");
        }

        // Use first object as fuel payment
        let obj = &objects[0];
        let object_id_str = obj
            .get("id")
            .and_then(|id| id.as_str())
            .context("Missing object ID in RPC response")?;

        let object_id_bytes = hex::decode(object_id_str)
            .context("Failed to decode object ID")?;

        if object_id_bytes.len() != 64 {
            anyhow::bail!("Invalid object ID length");
        }

        let mut object_id_array = [0u8; 64];
        object_id_array.copy_from_slice(&object_id_bytes);

        let sequence = obj
            .get("version")
            .and_then(|v| v.as_u64())
            .context("Missing version in RPC response")? as u32;

        let digest_str = obj
            .get("digest")
            .and_then(|d| d.as_str())
            .context("Missing digest in RPC response")?;

        let digest_bytes = hex::decode(digest_str)
            .context("Failed to decode digest")?;

        if digest_bytes.len() != 64 {
            anyhow::bail!("Invalid digest length: expected 64 bytes, got {}", digest_bytes.len());
        }

        let mut digest_array = [0u8; 64];
        digest_array.copy_from_slice(&digest_bytes);

        Ok(ObjectRef::new(
            ObjectID::new(object_id_array),
            SequenceNumber::new(sequence as u64),
            TransactionDigest::new(digest_array),
        ))
    }

    /// Prompt for fuel payment object
    fn prompt_fuel_payment() -> Result<ObjectRef> {
        println!("\n{}", "Fuel Payment Object:".yellow().bold());

        let object_id = dialoguer::Input::<String>::new()
            .with_prompt("Object ID (hex)")
            .interact_text()
            .context("Failed to read object ID")?;

        let version = dialoguer::Input::<u64>::new()
            .with_prompt("Object version")
            .default(0)
            .interact_text()
            .context("Failed to read version")?;

        let digest = dialoguer::Input::<String>::new()
            .with_prompt("Object digest (hex)")
            .interact_text()
            .context("Failed to read digest")?;

        let object_id_bytes = hex::decode(&object_id).context("Invalid object ID hex")?;
        let digest_bytes = hex::decode(&digest).context("Invalid digest hex")?;

        if object_id_bytes.len() != 64 || digest_bytes.len() != 64 {
            anyhow::bail!("Object ID and digest must be 64 bytes each");
        }

        let mut oid_array = [0u8; 64];
        oid_array.copy_from_slice(&object_id_bytes);

        let mut digest_array = [0u8; 64];
        digest_array.copy_from_slice(&digest_bytes);

        Ok(ObjectRef::new(
            ObjectID::new(oid_array),
            SequenceNumber::new(version),
            TransactionDigest::new(digest_array),
        ))
    }
}
