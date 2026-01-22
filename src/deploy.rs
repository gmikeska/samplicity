//! Address deployment module for Samplicity
//!
//! Handles key generation, program compilation, and address deployment.

#![allow(clippy::missing_errors_doc)]

use bip39::Mnemonic;
use musk::simplicityhl::num::U256;
use musk::{Arguments, Program, Value, ValueConstructible, WitnessName};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

// Re-export AddressType for convenience
pub use musk::AddressType;

/// Detect if an address is confidential based on its prefix
///
/// Confidential addresses start with "tlq" (testnet) or "lq" (mainnet)
/// Explicit addresses start with "tex" (testnet) or "ex" (mainnet)
#[must_use]
pub fn detect_address_type(address: &str) -> AddressType {
    if address.starts_with("tlq") || address.starts_with("lq") {
        AddressType::Confidential
    } else {
        AddressType::Explicit
    }
}

/// Result of deploying a new address
#[derive(Debug)]
#[allow(dead_code)] // Fields reserved for future confidential transaction support
pub struct DeployedAddress {
    /// The taproot address string
    pub address: String,
    /// The x-only public key (32 bytes)
    pub pubkey: [u8; 32],
    /// SHA256 hash of the public key (hex string)
    pub pk_hash: String,
    /// The mnemonic phrase used to generate the key
    pub mnemonic: String,
    /// Whether this is a confidential address
    pub is_confidential: bool,
    /// The blinding secret key (only for confidential addresses)
    pub blinding_sk: Option<[u8; 32]>,
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
            Self::KeyGeneration(msg) => write!(f, "Key generation error: {msg}"),
            Self::ProgramLoad(msg) => write!(f, "Program load error: {msg}"),
            Self::Compilation(msg) => write!(f, "Compilation error: {msg}"),
        }
    }
}

impl std::error::Error for DeployError {}

/// Deploy a new p2pkh address
///
/// This function:
/// 1. Generates a new mnemonic and derives a keypair
/// 2. Computes SHA256 of the x-only public key
/// 3. Compiles the p2pkh.simf program with the `PK_HASH` parameter
/// 4. For confidential addresses, generates a blinding keypair
/// 5. Returns the address and key material
pub fn deploy_new_address<P: AsRef<Path>>(
    program_path: P,
    address_params: &'static musk::elements::AddressParams,
    address_type: AddressType,
) -> Result<DeployedAddress, DeployError> {
    // Generate random entropy for mnemonic (128 bits = 12 words)
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy)
        .map_err(|e| DeployError::KeyGeneration(format!("Failed to generate entropy: {e}")))?;

    // Create mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| DeployError::KeyGeneration(format!("Failed to create mnemonic: {e}")))?;
    let mnemonic_phrase = mnemonic.to_string();

    // Derive seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Create secp256k1 context
    let secp = Secp256k1::new();

    // Use first 32 bytes of seed as secret key
    let secret_key = SecretKey::from_slice(&seed[..32])
        .map_err(|e| DeployError::KeyGeneration(format!("Invalid secret key: {e}")))?;

    // Get the keypair and extract x-only public key
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret_key);
    let (xonly_pubkey, _parity) = keypair.x_only_public_key();
    let pubkey_bytes: [u8; 32] = xonly_pubkey.serialize();

    // Compute SHA256 of the public key
    let mut hasher = Sha256::new();
    hasher.update(pubkey_bytes);
    let pk_hash_bytes: [u8; 32] = hasher.finalize().into();
    let pk_hash_hex = hex::encode(pk_hash_bytes);

    // Load the p2pkh program
    let program = Program::from_file(program_path)
        .map_err(|e| DeployError::ProgramLoad(format!("Failed to load program: {e}")))?;

    // Create arguments with PK_HASH
    let mut args = HashMap::new();
    args.insert(
        WitnessName::from_str_unchecked("PK_HASH"),
        Value::u256(U256::from_byte_array(pk_hash_bytes)),
    );

    // Instantiate the program
    let compiled = program
        .instantiate(Arguments::from(args))
        .map_err(|e| DeployError::Compilation(format!("Failed to instantiate program: {e}")))?;

    // Generate the address based on type
    let (address, blinding_sk) = match address_type {
        AddressType::Explicit => (compiled.address(address_params), None),
        AddressType::Confidential => {
            // Generate blinding keypair using additional entropy
            let mut blinding_entropy = [0u8; 32];
            getrandom::fill(&mut blinding_entropy).map_err(|e| {
                DeployError::KeyGeneration(format!("Failed to generate blinding entropy: {e}"))
            })?;

            let blinding_secret = SecretKey::from_slice(&blinding_entropy).map_err(|e| {
                DeployError::KeyGeneration(format!("Invalid blinding secret key: {e}"))
            })?;
            let blinding_public = PublicKey::from_secret_key(&secp, &blinding_secret);

            let address = compiled.confidential_address(address_params, blinding_public);
            (address, Some(blinding_entropy))
        }
    };

    Ok(DeployedAddress {
        address: address.to_string(),
        pubkey: pubkey_bytes,
        pk_hash: pk_hash_hex,
        mnemonic: mnemonic_phrase,
        is_confidential: address_type == AddressType::Confidential,
        blinding_sk,
    })
}

/// Get address parameters for a given network name
#[must_use]
pub fn get_address_params(network: &str) -> &'static musk::elements::AddressParams {
    match network.to_lowercase().as_str() {
        "liquidv1" | "liquid" | "mainnet" => &musk::elements::AddressParams::LIQUID,
        "testnet" | "liquidtestnet" => &musk::elements::AddressParams::LIQUID_TESTNET,
        _ => &musk::elements::AddressParams::ELEMENTS, // regtest
    }
}

/// Deploy a change address for a spending transaction
///
/// This is essentially the same as `deploy_new_address` - change addresses
/// are regular p2pkh addresses that receive the remainder from a spend.
/// Change addresses always use the same address type as the source.
pub fn deploy_change_address<P: AsRef<Path>>(
    program_path: P,
    address_params: &'static musk::elements::AddressParams,
    address_type: AddressType,
) -> Result<DeployedAddress, DeployError> {
    deploy_new_address(program_path, address_params, address_type)
}

/// Get the script pubkey for a given public key hash
///
/// This loads the p2pkh program, instantiates it with the given `pk_hash`,
/// and returns the compiled script pubkey.
pub fn get_script_pubkey_for_pk_hash<P: AsRef<Path>>(
    program_path: P,
    pk_hash: &[u8; 32],
    address_params: &'static musk::elements::AddressParams,
) -> Result<musk::elements::Script, DeployError> {
    let program = Program::from_file(program_path)
        .map_err(|e| DeployError::ProgramLoad(format!("Failed to load program: {e}")))?;

    let mut args = HashMap::new();
    args.insert(
        WitnessName::from_str_unchecked("PK_HASH"),
        Value::u256(U256::from_byte_array(*pk_hash)),
    );

    let compiled = program
        .instantiate(Arguments::from(args))
        .map_err(|e| DeployError::Compilation(format!("Failed to instantiate program: {e}")))?;

    let address = compiled.address(address_params);
    Ok(address.script_pubkey())
}
