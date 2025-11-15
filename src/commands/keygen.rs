//! Key generation and management commands

use anyhow::{Context, Result};
use base64::Engine;
use colored::Colorize;
use silver_core::SignatureScheme;
use silver_crypto::keys::{HDWallet, KeyPair, Mnemonic};
use silver_crypto::encryption::{Argon2Params, EncryptedKey, KeyEncryption};
use std::fs;
use std::path::PathBuf;

/// Key generation command
pub struct KeygenCommand;

impl KeygenCommand {
    /// Generate a new keypair
    pub fn generate(
        format: &str,
        scheme: Option<SignatureScheme>,
        output: Option<PathBuf>,
        encrypt: bool,
    ) -> Result<()> {
        let scheme = scheme.unwrap_or(SignatureScheme::Dilithium3);
        
        println!("{}", "🔑 Generating new keypair...".cyan().bold());
        println!("Signature scheme: {:?}", scheme);
        
        // Generate keypair
        let keypair = KeyPair::generate(scheme)
            .context("Failed to generate keypair")?;
        
        // Derive address
        let address = keypair.address();
        
        println!("\n{}", "✓ Keypair generated successfully!".green().bold());
        println!("\n{}", "Address:".yellow().bold());
        println!("{}", hex::encode(address.as_bytes()));
        
        // Handle encryption if requested
        let private_key_data = if encrypt {
            println!("\n{}", "🔒 Encrypting private key...".cyan());
            let password = dialoguer::Password::new()
                .with_prompt("Enter password to encrypt private key")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()
                .context("Failed to read password")?;
            
            let encrypted = KeyEncryption::encrypt_classical(
                keypair.private_key(),
                &password,
                Argon2Params::production(),
            ).context("Failed to encrypt private key")?;
            
            println!("{}", "✓ Private key encrypted".green());
            
            match format {
                "json" => encrypted.to_json()?,
                "hex" => encrypted.to_hex()?,
                "base64" => encrypted.to_base64()?,
                _ => encrypted.to_json()?,
            }
        } else {
            match format {
                "hex" => hex::encode(keypair.private_key()),
                "base64" => base64::engine::general_purpose::STANDARD.encode(keypair.private_key()),
                "json" => {
                    serde_json::to_string_pretty(&serde_json::json!({
                        "scheme": format!("{:?}", scheme),
                        "private_key": hex::encode(keypair.private_key()),
                        "public_key": hex::encode(&keypair.public_key_struct().bytes),
                        "address": hex::encode(address.as_bytes()),
                    }))?
                }
                _ => hex::encode(keypair.private_key()),
            }
        };
        
        println!("\n{}", "Public Key:".yellow().bold());
        println!("{}", hex::encode(&keypair.public_key_struct().bytes));
        
        // Save to file if output path specified
        if let Some(output_path) = output {
            fs::write(&output_path, &private_key_data)
                .context("Failed to write key to file")?;
            println!("\n{}", format!("✓ Private key saved to: {}", output_path.display()).green());
        } else {
            println!("\n{}", "Private Key:".yellow().bold());
            if encrypt {
                println!("{}", "Encrypted (save this securely):".red().bold());
            } else {
                println!("{}", "⚠️  WARNING: Unencrypted! Keep this secret!".red().bold());
            }
            println!("{}", private_key_data);
        }
        
        println!("\n{}", "💡 Tip: Use --encrypt to password-protect your key".cyan());
        println!("{}", "💡 Tip: Use --output <file> to save to a file".cyan());
        
        Ok(())
    }
    
    /// Generate a mnemonic phrase
    pub fn generate_mnemonic(word_count: usize, output: Option<PathBuf>) -> Result<()> {
        println!("{}", format!("🔑 Generating {}-word mnemonic phrase...", word_count).cyan().bold());
        
        let mnemonic = Mnemonic::generate_with_word_count(word_count)
            .context("Failed to generate mnemonic")?;
        
        let phrase = mnemonic.phrase();
        
        println!("\n{}", "✓ Mnemonic generated successfully!".green().bold());
        println!("\n{}", "⚠️  IMPORTANT: Write down these words in order and keep them safe!".red().bold());
        println!("{}", "Anyone with these words can access your funds!".red());
        
        println!("\n{}", "Mnemonic Phrase:".yellow().bold());
        println!("{}", "─".repeat(60));
        
        // Display words in a grid
        let words = mnemonic.words();
        for (i, word) in words.iter().enumerate() {
            print!("{:2}. {:12}", i + 1, word);
            if (i + 1) % 4 == 0 {
                println!();
            }
        }
        if words.len() % 4 != 0 {
            println!();
        }
        println!("{}", "─".repeat(60));
        
        // Save to file if requested
        if let Some(output_path) = output {
            fs::write(&output_path, &phrase)
                .context("Failed to write mnemonic to file")?;
            println!("\n{}", format!("✓ Mnemonic saved to: {}", output_path.display()).green());
        }
        
        println!("\n{}", "💡 Use 'silver keygen from-mnemonic' to derive keys from this phrase".cyan());
        
        Ok(())
    }
    
    /// Derive keypair from mnemonic
    pub fn from_mnemonic(
        mnemonic_phrase: Option<String>,
        scheme: Option<SignatureScheme>,
        derivation_path: Option<String>,
        output: Option<PathBuf>,
    ) -> Result<()> {
        let scheme = scheme.unwrap_or(SignatureScheme::Dilithium3);
        
        // Get mnemonic phrase
        let phrase = if let Some(p) = mnemonic_phrase {
            p
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt("Enter mnemonic phrase")
                .interact_text()
                .context("Failed to read mnemonic")?
        };
        
        println!("{}", "🔑 Deriving keypair from mnemonic...".cyan().bold());
        
        let mnemonic = Mnemonic::from_phrase(&phrase)
            .context("Invalid mnemonic phrase")?;
        
        let passphrase = dialoguer::Password::new()
            .with_prompt("Enter passphrase (leave empty for none)")
            .allow_empty_password(true)
            .interact()
            .context("Failed to read passphrase")?;
        
        let wallet = HDWallet::from_mnemonic(&mnemonic, &passphrase, scheme);
        
        let path = derivation_path.unwrap_or_else(|| "m/44'/0'/0'/0/0".to_string());
        let keypair = wallet.derive_keypair(&path)
            .context("Failed to derive keypair")?;
        
        let address = keypair.address();
        
        println!("\n{}", "✓ Keypair derived successfully!".green().bold());
        println!("\nDerivation path: {}", path);
        println!("\n{}", "Address:".yellow().bold());
        println!("{}", hex::encode(address.as_bytes()));
        
        println!("\n{}", "Public Key:".yellow().bold());
        println!("{}", hex::encode(&keypair.public_key_struct().bytes));
        
        // Optionally save private key
        if let Some(output_path) = output {
            let encrypt = dialoguer::Confirm::new()
                .with_prompt("Encrypt private key before saving?")
                .default(true)
                .interact()
                .context("Failed to read confirmation")?;
            
            let private_key_data = if encrypt {
                let password = dialoguer::Password::new()
                    .with_prompt("Enter password to encrypt private key")
                    .with_confirmation("Confirm password", "Passwords do not match")
                    .interact()
                    .context("Failed to read password")?;
                
                let encrypted = KeyEncryption::encrypt_classical(
                    keypair.private_key(),
                    &password,
                    Argon2Params::production(),
                ).context("Failed to encrypt private key")?;
                
                encrypted.to_json()?
            } else {
                hex::encode(keypair.private_key())
            };
            
            fs::write(&output_path, &private_key_data)
                .context("Failed to write key to file")?;
            println!("\n{}", format!("✓ Private key saved to: {}", output_path.display()).green());
        }
        
        Ok(())
    }
    
    /// Import a keypair from various formats
    pub fn import(
        input: PathBuf,
        format: &str,
        encrypted: bool,
        output: Option<PathBuf>,
    ) -> Result<()> {
        println!("{}", "📥 Importing keypair...".cyan().bold());
        
        let data = fs::read_to_string(&input)
            .context("Failed to read input file")?;
        
        let private_key_bytes = if encrypted {
            let password = dialoguer::Password::new()
                .with_prompt("Enter password to decrypt private key")
                .interact()
                .context("Failed to read password")?;
            
            let encrypted_key = match format {
                "json" => EncryptedKey::from_json(&data)?,
                "hex" => EncryptedKey::from_hex(&data)?,
                "base64" => EncryptedKey::from_base64(&data)?,
                _ => EncryptedKey::from_json(&data)?,
            };
            
            KeyEncryption::decrypt(&encrypted_key, &password)
                .context("Failed to decrypt private key")?
        } else {
            match format {
                "hex" => hex::decode(data.trim())
                    .context("Invalid hex format")?,
                "base64" => base64::engine::general_purpose::STANDARD.decode(data.trim())
                    .context("Invalid base64 format")?,
                "json" => {
                    let json: serde_json::Value = serde_json::from_str(&data)
                        .context("Invalid JSON format")?;
                    hex::decode(json["private_key"].as_str().context("Missing private_key field")?)
                        .context("Invalid hex in JSON")?
                }
                _ => hex::decode(data.trim())
                    .context("Invalid hex format")?,
            }
        };
        
        // Try to determine the scheme (for now, default to Dilithium3)
        let scheme = SignatureScheme::Dilithium3;
        let keypair = KeyPair::new(
            scheme,
            vec![], // We'd need to derive public key from private key
            private_key_bytes,
        );
        
        let address = keypair.address();
        
        println!("\n{}", "✓ Keypair imported successfully!".green().bold());
        println!("\n{}", "Address:".yellow().bold());
        println!("{}", hex::encode(address.as_bytes()));
        
        if let Some(output_path) = output {
            let export_data = serde_json::to_string_pretty(&serde_json::json!({
                "scheme": format!("{:?}", scheme),
                "address": hex::encode(address.as_bytes()),
            }))?;
            
            fs::write(&output_path, export_data)
                .context("Failed to write output file")?;
            println!("\n{}", format!("✓ Key info saved to: {}", output_path.display()).green());
        }
        
        Ok(())
    }
    
    /// Export a keypair to various formats
    pub fn export(
        input: PathBuf,
        format: &str,
        output: PathBuf,
        encrypt: bool,
    ) -> Result<()> {
        println!("{}", "📤 Exporting keypair...".cyan().bold());
        
        let data = fs::read_to_string(&input)
            .context("Failed to read input file")?;
        
        // Parse the input (assuming it's in some format)
        let private_key_bytes = hex::decode(data.trim())
            .context("Failed to decode private key")?;
        
        let output_data = if encrypt {
            let password = dialoguer::Password::new()
                .with_prompt("Enter password to encrypt private key")
                .with_confirmation("Confirm password", "Passwords do not match")
                .interact()
                .context("Failed to read password")?;
            
            let encrypted = KeyEncryption::encrypt_classical(
                &private_key_bytes,
                &password,
                Argon2Params::production(),
            ).context("Failed to encrypt private key")?;
            
            match format {
                "json" => encrypted.to_json()?,
                "hex" => encrypted.to_hex()?,
                "base64" => encrypted.to_base64()?,
                _ => encrypted.to_json()?,
            }
        } else {
            match format {
                "hex" => hex::encode(&private_key_bytes),
                "base64" => base64::engine::general_purpose::STANDARD.encode(&private_key_bytes),
                "json" => {
                    serde_json::to_string_pretty(&serde_json::json!({
                        "private_key": hex::encode(&private_key_bytes),
                    }))?
                }
                _ => hex::encode(&private_key_bytes),
            }
        };
        
        fs::write(&output, &output_data)
            .context("Failed to write output file")?;
        
        println!("\n{}", format!("✓ Keypair exported to: {}", output.display()).green().bold());
        
        Ok(())
    }
    
    /// Show address derived from a public key
    pub fn show_address(public_key: &str) -> Result<()> {
        println!("{}", "🔍 Deriving address from public key...".cyan().bold());
        
        let pk_bytes = hex::decode(public_key)
            .context("Invalid hex format for public key")?;
        
        let address = silver_crypto::hashing::derive_address(&pk_bytes);
        
        println!("\n{}", "Address:".yellow().bold());
        println!("{}", hex::encode(address.as_bytes()));
        
        Ok(())
    }
}
