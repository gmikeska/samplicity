//! Address deployment module for Samplicity
//!
//! Handles key generation, program compilation, and address deployment.

use bip39::Mnemonic;
use musk::simplicityhl::num::U256;
use musk::{Arguments, Program, Value, ValueConstructible, WitnessName};
use secp256k1::{Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// Result of deploying a new address
#[derive(Debug)]
pub struct DeployedAddress {
    /// The taproot address string
    pub address: String,
    /// The x-only public key (32 bytes)
    pub pubkey: [u8; 32],
    /// SHA256 hash of the public key (hex string)
    pub pk_hash: String,
    /// The mnemonic phrase used to generate the key
    pub mnemonic: String,
}

/// Error type for deployment operations
#[derive(Debug)]
pub enum DeployError {
    KeyGeneration(String),
    ProgramLoad(String),
    Compilation(String),
}

impl std::fmt::Display for DeployError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeployError::KeyGeneration(msg) => write!(f, "Key generation error: {}", msg),
            DeployError::ProgramLoad(msg) => write!(f, "Program load error: {}", msg),
            DeployError::Compilation(msg) => write!(f, "Compilation error: {}", msg),
        }
    }
}

impl std::error::Error for DeployError {}

/// Deploy a new p2pkh address
///
/// This function:
/// 1. Generates a new mnemonic and derives a keypair
/// 2. Computes SHA256 of the x-only public key
/// 3. Compiles the p2pkh.simf program with the PK_HASH parameter
/// 4. Returns the address and key material
pub fn deploy_new_address<P: AsRef<Path>>(
    program_path: P,
    address_params: &'static musk::elements::AddressParams,
) -> Result<DeployedAddress, DeployError> {
    // Generate random entropy for mnemonic (128 bits = 12 words)
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy)
        .map_err(|e| DeployError::KeyGeneration(format!("Failed to generate entropy: {}", e)))?;
    
    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| DeployError::KeyGeneration(format!("Failed to create mnemonic: {}", e)))?;
    let mnemonic_phrase = mnemonic.to_string();

    // Derive seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Create secp256k1 context
    let secp = Secp256k1::new();

    // Use first 32 bytes of seed as secret key
    let secret_key = SecretKey::from_slice(&seed[..32])
        .map_err(|e| DeployError::KeyGeneration(format!("Invalid secret key: {}", e)))?;

    // Get the keypair and extract x-only public key
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_pubkey, _parity) = keypair.x_only_public_key();
    let pubkey_bytes: [u8; 32] = xonly_pubkey.serialize();

    // Compute SHA256 of the public key
    let mut hasher = Sha256::new();
    hasher.update(&pubkey_bytes);
    let pk_hash_bytes: [u8; 32] = hasher.finalize().into();
    let pk_hash_hex = hex::encode(&pk_hash_bytes);

    // Load the p2pkh program
    let program = Program::from_file(program_path)
        .map_err(|e| DeployError::ProgramLoad(format!("Failed to load program: {}", e)))?;

    // Create arguments with PK_HASH
    let mut args = HashMap::new();
    args.insert(
        WitnessName::from_str_unchecked("PK_HASH"),
        Value::u256(U256::from_byte_array(pk_hash_bytes)),
    );

    // Instantiate the program
    let compiled = program
        .instantiate(Arguments::from(args))
        .map_err(|e| DeployError::Compilation(format!("Failed to instantiate program: {}", e)))?;

    // Generate the address
    let address = compiled.address(address_params);

    Ok(DeployedAddress {
        address: address.to_string(),
        pubkey: pubkey_bytes,
        pk_hash: pk_hash_hex,
        mnemonic: mnemonic_phrase,
    })
}

/// Get address parameters for a given network name
pub fn get_address_params(network: &str) -> &'static musk::elements::AddressParams {
    match network.to_lowercase().as_str() {
        "liquidv1" | "liquid" | "mainnet" => &musk::elements::AddressParams::LIQUID,
        "testnet" | "liquidtestnet" => &musk::elements::AddressParams::LIQUID_TESTNET,
        _ => &musk::elements::AddressParams::ELEMENTS, // regtest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_computation() {
        // Test that SHA256 computation matches expected format
        let test_bytes = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&test_bytes);
        let result: [u8; 32] = hasher.finalize().into();
        let hex_result = hex::encode(&result);
        
        // SHA256 of 32 zero bytes
        assert_eq!(hex_result.len(), 64);
    }

    #[test]
    fn test_get_address_params() {
        let testnet = get_address_params("testnet");
        let liquid = get_address_params("liquidv1");
        let regtest = get_address_params("regtest");
        
        // Just verify they don't panic and return different params
        assert!(std::ptr::eq(testnet, &musk::elements::AddressParams::LIQUID_TESTNET));
        assert!(std::ptr::eq(liquid, &musk::elements::AddressParams::LIQUID));
        assert!(std::ptr::eq(regtest, &musk::elements::AddressParams::ELEMENTS));
    }
}

