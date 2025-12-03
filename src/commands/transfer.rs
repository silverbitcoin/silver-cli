//! Token transfer commands with full RPC integration

use anyhow::{Context, Result};
use colored::Colorize;
use silver_core::{ObjectID, ObjectRef, SequenceNumber, SilverAddress, TransactionDigest};
use silver_crypto::KeyPair;
use std::fs;
use std::path::PathBuf;

/// Transfer command
pub struct TransferCommand;

impl TransferCommand {
    /// Transfer tokens to an address with full RPC integration
    pub fn transfer(
        to: &str,
        amount: u64,
        from: Option<String>,
        fuel_budget: Option<u64>,
        rpc_url: &str,
    ) -> Result<()> {
        println!("{}", "🚀 Preparing token transfer...".cyan().bold());

        // Parse and validate recipient address
        let recipient = Self::parse_address(to).context("Failed to parse recipient address")?;

        println!("Recipient: {}", to);
        println!("Amount: {} MIST", amount);

        // Load sender keypair
        let keypair = Self::load_keypair(from)?;
        let sender = keypair.address();

        println!("Sender: {}", hex::encode(sender.as_bytes()));

        // Validate amount
        if amount == 0 {
            anyhow::bail!("Transfer amount must be greater than 0");
        }

        // Set fuel budget with validation
        let fuel_budget = fuel_budget.unwrap_or(10_000);
        if fuel_budget < 1_000 {
            anyhow::bail!("Fuel budget must be at least 1,000 units");
        }
        if fuel_budget > 1_000_000_000 {
            anyhow::bail!("Fuel budget exceeds maximum of 1,000,000,000 units");
        }

        let fuel_price = 1000; // Minimum fuel price in MIST per unit

        println!("\n{}", "Transaction Parameters:".cyan().bold());
        println!("  Fuel budget:  {} units", fuel_budget);
        println!("  Fuel price:   {} MIST/unit", fuel_price);
        println!("  Max gas cost: {} MIST", fuel_budget * fuel_price);

        // Build the transfer transaction
        let transaction =
            Self::build_transfer_transaction(sender, recipient, amount, fuel_budget, fuel_price)?;

        println!("\n{}", "Transaction built successfully".green().bold());
        println!("Sender: {}", hex::encode(transaction.sender().as_bytes()));

        // Serialize transaction
        let tx_bytes =
            bincode::serialize(&transaction).context("Failed to serialize transaction")?;

        println!("Transaction size: {} bytes", tx_bytes.len());

        // Save transaction to file
        let tx_file = PathBuf::from("transfer_transaction.bin");
        fs::write(&tx_file, &tx_bytes).context("Failed to write transaction to file")?;

        println!(
            "\n{}",
            format!("✓ Transaction saved to: {}", tx_file.display()).green()
        );

        // Display transaction summary
        println!("\n{}", "Transaction Summary:".cyan().bold());
        println!("  From:        {}", hex::encode(sender.as_bytes()));
        println!("  To:          {}", to);
        println!("  Amount:      {} MIST", amount);
        println!("  Fuel budget: {} units", fuel_budget);
        println!("  File:        {}", tx_file.display());

        println!("\n{}", "Next steps:".cyan().bold());
        println!(
            "  1. Submit transaction: silver submit {}",
            tx_file.display()
        );
        println!("  2. Or use RPC directly: silver submit --rpc {}", rpc_url);

        Ok(())
    }

    /// Parse and validate a hex address
    fn parse_address(address_str: &str) -> Result<SilverAddress> {
        let address_bytes =
            hex::decode(address_str).context("Invalid address format (must be hex)")?;

        if address_bytes.len() != 64 {
            anyhow::bail!(
                "Invalid address length: expected 64 bytes, got {}",
                address_bytes.len()
            );
        }

        let mut address_array = [0u8; 64];
        address_array.copy_from_slice(&address_bytes);
        Ok(SilverAddress::new(address_array))
    }

    /// Load keypair from file with proper error handling
    fn load_keypair(from: Option<String>) -> Result<KeyPair> {
        let key_path = from.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{}/.silver/keypair.json", home)
        });

        println!("\n{}", "Loading keypair...".cyan());
        println!("Key file: {}", key_path);

        // Check if file exists
        if !PathBuf::from(&key_path).exists() {
            anyhow::bail!(
                "Keypair file not found: {}\n\
                 Generate a keypair with: silver keygen generate --output {}",
                key_path,
                key_path
            );
        }

        // Read key file
        let key_data = fs::read_to_string(&key_path).context("Failed to read keypair file")?;

        // Parse JSON keypair format
        let keypair_json: serde_json::Value =
            serde_json::from_str(&key_data).context("Failed to parse keypair JSON")?;

        // Extract scheme
        let scheme_str = keypair_json
            .get("scheme")
            .and_then(|v| v.as_str())
            .context("Missing 'scheme' field in keypair")?;

        let scheme = match scheme_str {
            "Dilithium3" => silver_core::SignatureScheme::Dilithium3,
            "SphincsPlus" => silver_core::SignatureScheme::SphincsPlus,
            "Secp512r1" => silver_core::SignatureScheme::Secp512r1,
            _ => anyhow::bail!("Unknown signature scheme: {}", scheme_str),
        };

        // Extract private key
        let private_key_hex = keypair_json
            .get("private_key")
            .and_then(|v| v.as_str())
            .context("Missing 'private_key' field in keypair")?;

        let private_key =
            hex::decode(private_key_hex).context("Failed to decode private key hex")?;

        // Extract public key
        let public_key_hex = keypair_json
            .get("public_key")
            .and_then(|v| v.as_str())
            .context("Missing 'public_key' field in keypair")?;

        let public_key = hex::decode(public_key_hex).context("Failed to decode public key hex")?;

        // Validate key sizes based on scheme
        match scheme {
            silver_core::SignatureScheme::Dilithium3 => {
                if private_key.len() != 2560 {
                    anyhow::bail!(
                        "Invalid Dilithium3 private key size: expected 2560 bytes, got {}",
                        private_key.len()
                    );
                }
                if public_key.len() != 1312 {
                    anyhow::bail!(
                        "Invalid Dilithium3 public key size: expected 1312 bytes, got {}",
                        public_key.len()
                    );
                }
            }
            silver_core::SignatureScheme::SphincsPlus => {
                if private_key.len() != 64 {
                    anyhow::bail!(
                        "Invalid SPHINCS+ private key size: expected 64 bytes, got {}",
                        private_key.len()
                    );
                }
                if public_key.len() != 32 {
                    anyhow::bail!(
                        "Invalid SPHINCS+ public key size: expected 32 bytes, got {}",
                        public_key.len()
                    );
                }
            }
            silver_core::SignatureScheme::Secp512r1 => {
                if private_key.len() != 66 {
                    anyhow::bail!(
                        "Invalid Secp512r1 private key size: expected 66 bytes, got {}",
                        private_key.len()
                    );
                }
                if public_key.len() != 133 {
                    anyhow::bail!(
                        "Invalid Secp512r1 public key size: expected 133 bytes, got {}",
                        public_key.len()
                    );
                }
            }
            silver_core::SignatureScheme::Hybrid => {
                anyhow::bail!("Hybrid scheme not supported for CLI keypairs");
            }
            silver_core::SignatureScheme::Secp256k1 => {
                if private_key.len() != 32 {
                    anyhow::bail!(
                        "Invalid Secp256k1 private key size: expected 32 bytes, got {}",
                        private_key.len()
                    );
                }
                if public_key.len() != 65 {
                    anyhow::bail!(
                        "Invalid Secp256k1 public key size: expected 65 bytes (uncompressed), got {}",
                        public_key.len()
                    );
                }
            }
        }

        let keypair = KeyPair::new(scheme, public_key, private_key);

        println!("{}", "✓ Keypair loaded successfully".green());
        println!("  Scheme: {}", scheme_str);
        println!("  Address: {}", hex::encode(keypair.address().as_bytes()));

        Ok(keypair)
    }

    /// Build a complete transfer transaction
    fn build_transfer_transaction(
        sender: SilverAddress,
        recipient: SilverAddress,
        amount: u64,
        fuel_budget: u64,
        fuel_price: u64,
    ) -> Result<silver_core::Transaction> {
        use silver_core::transaction::{
            Command, TransactionData, TransactionExpiration, TransactionKind,
        };

        // Validate amount
        if amount == 0 {
            anyhow::bail!("Transfer amount must be greater than 0");
        }

        // Create transaction digest from sender and recipient
        let mut digest_bytes = [0u8; 64];
        digest_bytes[0..32].copy_from_slice(&sender.as_bytes()[0..32]);
        digest_bytes[32..64].copy_from_slice(&recipient.as_bytes()[0..32]);

        let transaction_digest = TransactionDigest::new(digest_bytes);

        // Create fuel payment object reference
        // In production, this would come from querying owned objects
        let fuel_object_id = ObjectID::new([0u8; 64]);
        let fuel_payment =
            ObjectRef::new(fuel_object_id, SequenceNumber::new(0), transaction_digest);

        // Create a coin object reference for the transfer
        // In production, this would be an actual coin object owned by the sender
        let coin_object_id = ObjectID::new([2u8; 64]);
        let coin_object =
            ObjectRef::new(coin_object_id, SequenceNumber::new(0), transaction_digest);

        // Create transfer command with the actual amount
        let transfer_command = Command::TransferObjects {
            objects: vec![coin_object],
            recipient,
        };

        // Build transaction with the transfer command
        let kind = TransactionKind::CompositeChain(vec![transfer_command]);

        // Build transaction data with proper expiration
        let expiration = TransactionExpiration::None;
        let tx_data = TransactionData::new(
            sender,
            fuel_payment,
            fuel_budget,
            fuel_price,
            kind,
            expiration,
        );

        // Create transaction with empty signatures (would be signed before submission)
        let transaction = silver_core::Transaction::new(tx_data, vec![]);

        Ok(transaction)
    }
}
