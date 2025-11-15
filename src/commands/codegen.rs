//! Code generation command for creating Rust bindings from Quantum modules

use clap::Parser;
use silver_sdk::CodeGenerator;
use std::fs;
use std::path::PathBuf;

/// Generate Rust bindings from Quantum modules
#[derive(Parser, Debug)]
pub struct CodegenCommand {
    /// Path to Quantum source file
    #[arg(short, long)]
    pub source: Option<PathBuf>,

    /// Path to compiled bytecode file
    #[arg(short, long)]
    pub bytecode: Option<PathBuf>,

    /// Output file path (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Generate module helper struct
    #[arg(long, default_value = "true")]
    pub module_helper: bool,
}

impl CodegenCommand {
    /// Execute the codegen command
    pub fn execute(&self) -> anyhow::Result<()> {
        let mut generator = CodeGenerator::new();

        // Generate code from source or bytecode
        let rust_code = if let Some(source_path) = &self.source {
            // Read Quantum source file
            let source = fs::read_to_string(source_path)
                .map_err(|e| anyhow::anyhow!("Failed to read source file: {}", e))?;

            // Generate Rust bindings
            generator.generate_from_source(&source)
                .map_err(|e| anyhow::anyhow!("Code generation failed: {}", e))?
        } else if let Some(bytecode_path) = &self.bytecode {
            // Read compiled bytecode
            let bytecode = fs::read(bytecode_path)
                .map_err(|e| anyhow::anyhow!("Failed to read bytecode file: {}", e))?;

            // Generate Rust bindings
            generator.generate_from_bytecode(&bytecode)
                .map_err(|e| anyhow::anyhow!("Code generation failed: {}", e))?
        } else {
            return Err(anyhow::anyhow!("Either --source or --bytecode must be provided"));
        };

        // Write output
        if let Some(output_path) = &self.output {
            fs::write(output_path, &rust_code)
                .map_err(|e| anyhow::anyhow!("Failed to write output file: {}", e))?;
            
            println!("✓ Generated Rust bindings: {}", output_path.display());
        } else {
            // Print to stdout
            println!("{}", rust_code);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_codegen_from_source() {
        let source = r#"
            module my_package::coin {
                struct Coin has key, store {
                    value: u64
                }
                
                public fun mint(value: u64): Coin {
                    Coin { value }
                }
            }
        "#;

        // Create temporary source file
        let mut source_file = NamedTempFile::new().unwrap();
        source_file.write_all(source.as_bytes()).unwrap();
        source_file.flush().unwrap();

        // Create temporary output file
        let output_file = NamedTempFile::new().unwrap();

        let cmd = CodegenCommand {
            source: Some(source_file.path().to_path_buf()),
            bytecode: None,
            output: Some(output_file.path().to_path_buf()),
            module_helper: true,
        };

        let result = cmd.execute();
        assert!(result.is_ok());

        // Verify output file was created
        let output_content = fs::read_to_string(output_file.path()).unwrap();
        assert!(output_content.contains("struct Coin"));
        assert!(output_content.contains("pub fn call_mint"));
    }
}
