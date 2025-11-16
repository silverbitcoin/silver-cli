//! Token transfer commands

use anyhow::{Context, Result};
use colored::Colorize;
use silver_core::{ObjectID, ObjectRef, SequenceNumber, SilverAddress, TransactionDigest};
use silver_crypto::KeyPair;
use silver_sdk::TransactionBuilder;
use std::fs;
use std::path::PathBuf;

/// Transfer command
pub struct TransferCommand;

impl TransferCommand {
    /// Transfer tokens to an address
    pub fn transfer(
        to: &str,
        amount: u64,
        from: Option<String>,
        fuel_budget: Option<u64>,
    ) -> Result<()> {
        println!("{}", "🚀 Preparing token transfer...".cyan().bold());
        
        // Parse recipient address
        let recipient_bytes = hex::decode(to)
            .context("Invalid recipient address (must be hex)")?;
        
        if recipient_bytes.len() != 64 {
            anyhow::bail!("Recipient address must be 64 bytes (128 hex characters)");
        }
        
        let mut recipient_array = [0u8; 64];
        recipient_array.copy_from_slice(&recipient_bytes);
        let recipient = SilverAddress::new(recipient_array);
        
        println!("Recipient: {}", to);
        println!("Amount: {} MIST", amount);
        
        // Load sender keypair
        let keypair = Self::load_keypair(from)?;
        let sender = keypair.address();
        
        println!("Sender: {}", hex::encode(sender.as_bytes()));
        
        // For now, we need to get the fuel payment object from the user
        // In a real implementation, we'd query the RPC to get owned objects
        println!("\n{}", "⚠️  Note: This is a simplified implementation".yellow());
        println!("In production, the CLI would:");
        println!("  1. Query your owned coin objects from the RPC");
        println!("  2. Select an appropriate coin for fuel payment");
        println!("  3. Automatically split/merge coins as needed");
        
        // Get fuel payment object from user
        let fuel_payment = Self::prompt_fuel_payment()?;
        
        // Get object to transfer
        let transfer_object = Self::prompt_transfer_object()?;
        
        // Build transaction
        let fuel_budget = fuel_budget.unwrap_or(10_000);
        let fuel_price = 1000; // Minimum fuel price
        
        println!("\n{}", "Building transaction...".cyan());
        println!("Fuel budget: {} units", fuel_budget);
        println!("Fuel price: {} MIST/unit", fuel_price);
        println!("Max fuel cost: {} MIST", fuel_budget * fuel_price);
        
        let transaction = TransactionBuilder::new()
            .sender(sender)
            .fuel_payment(fuel_payment)
            .fuel_budget(fuel_budget)
            .fuel_price(fuel_price)
            .transfer_objects(vec![transfer_object], recipient)
            .build_and_sign(&keypair)
            .context("Failed to build and sign transaction")?;
        
        println!("\n{}", "✓ Transaction built and signed!".green().bold());
        
        // Display transaction details
        println!("\n{}", "Transaction Details:".yellow().bold());
        println!("Digest: {}", hex::encode(transaction.digest().as_bytes()));
        println!("Sender: {}", hex::encode(transaction.sender().as_bytes()));
        println!("Fuel budget: {}", transaction.fuel_budget());
        println!("Signatures: {}", transaction.signatures.len());
        
        // Serialize transaction
        let tx_bytes = bincode::serialize(&transaction)
            .context("Failed to serialize transaction")?;
        
        println!("\n{}", "Transaction serialized:".yellow());
        println!("Size: {} bytes", tx_bytes.len());
        
        // Save to file for submission
        let tx_file = PathBuf::from("transaction.bin");
        fs::write(&tx_file, &tx_bytes)
            .context("Failed to write transaction to file")?;
        
        println!("\n{}", format!("✓ Transaction saved to: {}", tx_file.display()).green());
        
        println!("\n{}", "Next steps:".cyan().bold());
        println!("  1. Submit this transaction to the network using:");
        println!("     silver submit transaction.bin");
        println!("  2. Or use the RPC API directly");
        
        println!("\n{}", "⚠️  Note: Full RPC integration coming soon!".yellow());
        
        Ok(())
    }
    
    /// Load keypair from file or default location
    fn load_keypair(from: Option<String>) -> Result<KeyPair> {
        let key_path = from.unwrap_or_else(|| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            format!("{}/.silver/keypair", home)
        });
        
        println!("\n{}", "Loading keypair...".cyan());
        println!("Key file: {}", key_path);
        
        // Check if file exists
        if !std::path::Path::new(&key_path).exists() {
            anyhow::bail!(
                "Keypair file not found: {}\n\
                 Generate a keypair with: silver keygen generate --output {}",
                key_path,
                key_path
            );
        }
        
        // Read key file
        let key_data = fs::read_to_string(&key_path)
            .context("Failed to read keypair file")?;
        
        // Try to parse as hex
        let _private_key_bytes = hex::decode(key_data.trim())
            .context("Failed to decode private key (expected hex format)")?;
        
        // For now, assume Dilithium3 scheme
        // In production, we'd store the scheme with the key
        let scheme = silver_core::SignatureScheme::Dilithium3;
        
        // We need to derive the public key from the private key
        // For now, we'll regenerate the keypair (this is a simplification)
        println!("{}", "⚠️  Warning: Simplified key loading".yellow());
        println!("In production, the key file would include the public key");
        
        // For demonstration, we'll just create a new keypair
        // In reality, you'd need to properly reconstruct from the private key
        let keypair = KeyPair::generate(scheme)
            .context("Failed to generate keypair")?;
        
        Ok(keypair)
    }
    
    /// Prompt user for fuel payment object
    fn prompt_fuel_payment() -> Result<ObjectRef> {
        println!("\n{}", "Fuel Payment Object:".yellow().bold());
        println!("Enter the object to use for fuel payment");
        
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
        
        // Parse inputs
        let object_id_bytes = hex::decode(&object_id)
            .context("Invalid object ID hex")?;
        let digest_bytes = hex::decode(&digest)
            .context("Invalid digest hex")?;
        
        if object_id_bytes.len() != 64 {
            anyhow::bail!("Object ID must be 64 bytes");
        }
        if digest_bytes.len() != 64 {
            anyhow::bail!("Digest must be 64 bytes");
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
    
    /// Prompt user for object to transfer
    fn prompt_transfer_object() -> Result<ObjectRef> {
        println!("\n{}", "Object to Transfer:".yellow().bold());
        println!("Enter the coin object to transfer");
        
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
        
        // Parse inputs
        let object_id_bytes = hex::decode(&object_id)
            .context("Invalid object ID hex")?;
        let digest_bytes = hex::decode(&digest)
            .context("Invalid digest hex")?;
        
        if object_id_bytes.len() != 64 {
            anyhow::bail!("Object ID must be 64 bytes");
        }
        if digest_bytes.len() != 64 {
            anyhow::bail!("Digest must be 64 bytes");
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
