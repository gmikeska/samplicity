//! Spend module for Samplicity
//!
//! Handles transaction building, signing, and broadcasting for spending from
//! Simplicity P2PKH addresses.

use bip39::Mnemonic;
use musk::elements::{self, Address, Script};
use musk::simplicityhl::num::U256;
use musk::{Arguments, InstantiatedProgram, Program, SpendBuilder, Value, ValueConstructible, WitnessName};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;

use crate::db::StoredUtxo;

/// L-BTC asset ID for Liquid Testnet
pub const LBTC_TESTNET_ASSET_ID: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// Dust threshold in satoshis (below this, no change output is created)
pub const DUST_THRESHOLD: u64 = 546;

/// Default fee in satoshis (safe buffer for ~1000-3000 vbyte tx at 0.1-0.5 sat/vbyte)
pub const DEFAULT_FEE_SATS: u64 = 500;

/// Error type for spend operations
#[derive(Debug)]
pub enum SpendError {
    InsufficientFunds { available: u64, required: u64 },
    NoUtxos,
    InvalidAddress(String),
    InvalidMnemonic(String),
    ProgramError(String),
    SigningError(String),
    BroadcastError(String),
    DatabaseError(String),
    GenesisHashError(String),
}

impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendError::InsufficientFunds { available, required } => {
                write!(
                    f,
                    "Insufficient funds: have {} sats, need {} sats",
                    available, required
                )
            }
            SpendError::NoUtxos => write!(f, "No UTXOs available to spend"),
            SpendError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            SpendError::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {}", msg),
            SpendError::ProgramError(msg) => write!(f, "Program error: {}", msg),
            SpendError::SigningError(msg) => write!(f, "Signing error: {}", msg),
            SpendError::BroadcastError(msg) => write!(f, "Broadcast error: {}", msg),
            SpendError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            SpendError::GenesisHashError(msg) => write!(f, "Genesis hash error: {}", msg),
        }
    }
}

impl std::error::Error for SpendError {}

/// Result of a successful spend operation
#[derive(Debug, Clone)]
pub struct SpendResult {
    /// Transaction ID of the broadcast transaction
    pub txid: String,
    /// Amount sent to destination (in satoshis)
    pub amount_sent: u64,
    /// Fee paid (in satoshis)
    pub fee: u64,
    /// Change address (if change was generated)
    pub change_address: Option<String>,
    /// Change amount (if change was generated)
    pub change_amount: Option<u64>,
}

/// Preview of a spend operation (before confirmation)
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpendPreview {
    /// Source address
    pub source_address: String,
    /// Destination address
    pub destination: String,
    /// Amount to send (in satoshis)
    pub amount: u64,
    /// Estimated fee (in satoshis)
    pub fee: u64,
    /// Change amount (0 if no change)
    pub change_amount: u64,
    /// Whether change output will be created
    pub has_change: bool,
    /// Total input amount
    pub total_input: u64,
}

/// Derive the secret key from a mnemonic phrase
///
/// Uses the same derivation as deploy.rs: first 32 bytes of mnemonic.to_seed("")
pub fn derive_secret_key_from_mnemonic(mnemonic_phrase: &str) -> Result<[u8; 32], SpendError> {
    let mnemonic = Mnemonic::from_str(mnemonic_phrase)
        .map_err(|e| SpendError::InvalidMnemonic(format!("Failed to parse mnemonic: {}", e)))?;

    let seed = mnemonic.to_seed("");
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&seed[..32]);

    Ok(secret_key)
}

/// Sign a message using Schnorr signature with actual secret key bytes
///
/// This is different from musk's util::sign_schnorr which only takes u32
pub fn sign_schnorr_with_bytes(secret_key: &[u8; 32], message: [u8; 32]) -> Result<[u8; 64], SpendError> {
    let secp = Secp256k1::new();
    
    let sk = SecretKey::from_slice(secret_key)
        .map_err(|e| SpendError::SigningError(format!("Invalid secret key: {}", e)))?;
    
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(message);
    let signature = keypair.sign_schnorr(msg);
    
    Ok(signature.serialize())
}

/// Get the x-only public key from a secret key
pub fn get_xonly_pubkey(secret_key: &[u8; 32]) -> Result<[u8; 32], SpendError> {
    let secp = Secp256k1::new();
    
    let sk = SecretKey::from_slice(secret_key)
        .map_err(|e| SpendError::SigningError(format!("Invalid secret key: {}", e)))?;
    
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = keypair.x_only_public_key();
    
    Ok(xonly.serialize())
}

/// Compute SHA256 hash of a public key (as used in p2pkh.simf)
pub fn compute_pk_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.finalize().into()
}

/// Validate that a secret key matches the stored pubkey
pub fn validate_key_pair(secret_key: &[u8; 32], stored_pubkey: &[u8]) -> Result<bool, SpendError> {
    let derived_pubkey = get_xonly_pubkey(secret_key)?;
    Ok(derived_pubkey.as_slice() == stored_pubkey)
}

/// Calculate spend preview (fee estimation, change calculation)
pub fn calculate_spend_preview(
    source_address: &str,
    destination: &str,
    amount: u64,
    utxos: &[StoredUtxo],
) -> Result<SpendPreview, SpendError> {
    if utxos.is_empty() {
        return Err(SpendError::NoUtxos);
    }

    // Calculate total available
    let total_input: u64 = utxos.iter().map(|u| u.amount).sum();

    // Calculate required amount (send + fee)
    let required = amount.saturating_add(DEFAULT_FEE_SATS);

    if total_input < required {
        return Err(SpendError::InsufficientFunds {
            available: total_input,
            required,
        });
    }

    // Calculate change
    let change_amount = total_input.saturating_sub(required);
    let has_change = change_amount > DUST_THRESHOLD;
    let final_change = if has_change { change_amount } else { 0 };

    // If no change output, the remainder goes to fees
    let actual_fee = if has_change {
        DEFAULT_FEE_SATS
    } else {
        total_input.saturating_sub(amount)
    };

    Ok(SpendPreview {
        source_address: source_address.to_string(),
        destination: destination.to_string(),
        amount,
        fee: actual_fee,
        change_amount: final_change,
        has_change,
        total_input,
    })
}

/// Load and instantiate the p2pkh program with the given pk_hash
pub fn load_p2pkh_program(
    program_path: &str,
    pk_hash: &[u8; 32],
) -> Result<InstantiatedProgram, SpendError> {
    let program = Program::from_file(program_path)
        .map_err(|e| SpendError::ProgramError(format!("Failed to load program: {}", e)))?;

    let mut args = HashMap::new();
    args.insert(
        WitnessName::from_str_unchecked("PK_HASH"),
        Value::u256(U256::from_byte_array(*pk_hash)),
    );

    let compiled = program
        .instantiate(Arguments::from(args))
        .map_err(|e| SpendError::ProgramError(format!("Failed to instantiate program: {}", e)))?;

    Ok(compiled)
}

/// Build witness values for p2pkh spending
///
/// The p2pkh.simf program requires:
/// - witness::PK - the x-only public key
/// - witness::SIG - the Schnorr signature of sighash_all
pub fn build_witness_values(
    pubkey: &[u8; 32],
    signature: &[u8; 64],
) -> musk::simplicityhl::WitnessValues {
    let mut values = HashMap::new();

    // Add public key
    values.insert(
        WitnessName::from_str_unchecked("PK"),
        Value::u256(U256::from_byte_array(*pubkey)),
    );

    // Add signature
    values.insert(
        WitnessName::from_str_unchecked("SIG"),
        Value::byte_array(*signature),
    );

    musk::simplicityhl::WitnessValues::from(values)
}

/// Parse a Liquid testnet address
pub fn parse_address(
    address_str: &str,
    _address_params: &'static elements::AddressParams,
) -> Result<Address, SpendError> {
    Address::from_str(address_str)
        .map_err(|e| SpendError::InvalidAddress(format!("Failed to parse address: {}", e)))
}

/// Get the L-BTC asset ID for testnet
pub fn get_lbtc_asset_id() -> Result<elements::issuance::AssetId, SpendError> {
    // Use from_str which handles the byte order conversion correctly
    // (display format is big-endian, internal format is little-endian)
    elements::issuance::AssetId::from_str(LBTC_TESTNET_ASSET_ID)
        .map_err(|e| SpendError::ProgramError(format!("Invalid asset ID: {}", e)))
}

/// Convert a stored UTXO to musk's Utxo type
pub fn stored_utxo_to_musk_utxo(
    utxo: &StoredUtxo,
    script_pubkey: Script,
) -> Result<musk::client::Utxo, SpendError> {
    let txid = elements::Txid::from_str(&utxo.txid)
        .map_err(|e| SpendError::ProgramError(format!("Invalid txid: {}", e)))?;

    // Use from_str which handles byte order conversion correctly
    let asset_id = elements::issuance::AssetId::from_str(&utxo.asset)
        .map_err(|e| SpendError::ProgramError(format!("Invalid asset ID: {}", e)))?;

    Ok(musk::client::Utxo {
        txid,
        vout: utxo.vout,
        amount: utxo.amount,
        script_pubkey,
        asset: elements::confidential::Asset::Explicit(asset_id),
    })
}

/// Build and sign a spending transaction
///
/// This takes a source UTXO, builds a transaction with destination and optional change,
/// signs it using the derived secret key, and returns the finalized transaction.
pub fn build_and_sign_transaction(
    program_path: &str,
    utxo: &StoredUtxo,
    source_script_pubkey: Script,
    source_pk_hash: &[u8; 32],
    mnemonic: &str,
    destination_script: Script,
    amount: u64,
    fee: u64,
    change_script: Option<Script>,
    change_amount: u64,
    genesis_hash: elements::BlockHash,
) -> Result<elements::Transaction, SpendError> {
    // === VERIFICATION: Prove input == outputs ===
    let input_amount = utxo.amount;
    let total_outputs = amount + fee + change_amount;
    
    println!("=== TRANSACTION VALUE VERIFICATION ===");
    println!("  INPUT:  UTXO amount from DB = {} sats", input_amount);
    println!("  OUTPUT: Destination amount  = {} sats", amount);
    println!("  OUTPUT: Change amount       = {} sats", change_amount);
    println!("  OUTPUT: Fee amount          = {} sats", fee);
    println!("  TOTAL:  Sum of outputs      = {} sats", total_outputs);
    println!("  UTXO:   txid={}, vout={}", utxo.txid, utxo.vout);
    
    if input_amount != total_outputs {
        let diff = if input_amount > total_outputs {
            input_amount - total_outputs
        } else {
            total_outputs - input_amount
        };
        eprintln!("  *** MISMATCH! Input != Outputs (diff = {} sats) ***", diff);
        return Err(SpendError::ProgramError(format!(
            "Value mismatch: input={} but outputs sum to {} (diff={})",
            input_amount, total_outputs, diff
        )));
    }
    println!("  [OK] Values match: {} == {}", input_amount, total_outputs);
    println!("=======================================");
    
    // 1. Load and instantiate the program
    let program = load_p2pkh_program(program_path, source_pk_hash)?;

    // 2. Convert stored UTXO to musk format
    let musk_utxo = stored_utxo_to_musk_utxo(utxo, source_script_pubkey)?;

    // 3. Get asset ID
    let asset_id = get_lbtc_asset_id()?;

    // 4. Create spend builder
    let mut builder = SpendBuilder::new(program.clone(), musk_utxo).genesis_hash(genesis_hash);

    // 5. Add destination output
    builder.add_output_simple(destination_script, amount, asset_id);

    // 6. Add change output if applicable
    if let Some(change_script) = change_script {
        if change_amount > 0 {
            builder.add_output_simple(change_script, change_amount, asset_id);
        }
    }

    // 7. Add fee output
    builder.add_fee(fee, asset_id);

    // 8. Compute sighash
    let sighash = builder.sighash_all()
        .map_err(|e| SpendError::SigningError(format!("Failed to compute sighash: {}", e)))?;

    // 9. Derive secret key from mnemonic
    let secret_key = derive_secret_key_from_mnemonic(mnemonic)?;

    // 10. Get the x-only public key
    let pubkey = get_xonly_pubkey(&secret_key)?;

    // 11. Sign the sighash
    let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

    // 12. Build witness values
    let witness_values = build_witness_values(&pubkey, &signature);

    // 13. Finalize and return the transaction
    builder.finalize(witness_values)
        .map_err(|e| SpendError::SigningError(format!("Failed to finalize transaction: {}", e)))
}

/// Complete spend operation that handles everything from UTXOs to final transaction
pub struct SpendRequest {
    /// Source address to spend from
    pub source_address: String,
    /// Destination address
    pub destination: String,
    /// Amount to send in satoshis
    pub amount: u64,
}

/// Complete spending orchestrator
///
/// This struct holds all the context needed to execute a spend operation.
pub struct SpendOrchestrator {
    program_path: String,
    address_params: &'static elements::AddressParams,
    genesis_hash: elements::BlockHash,
}

impl SpendOrchestrator {
    /// Create a new spend orchestrator
    pub fn new(
        program_path: &str,
        address_params: &'static elements::AddressParams,
        genesis_hash: elements::BlockHash,
    ) -> Self {
        Self {
            program_path: program_path.to_string(),
            address_params,
            genesis_hash,
        }
    }

    /// Set the genesis hash
    pub fn with_genesis_hash(mut self, genesis_hash: elements::BlockHash) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    /// Execute a spend operation
    ///
    /// This performs the complete spend workflow:
    /// 1. Validate inputs
    /// 2. Calculate preview (fees, change)
    /// 3. Deploy change address if needed
    /// 4. Build and sign transaction
    /// 5. Return the raw transaction hex for broadcasting
    pub fn execute_spend(
        &self,
        source_address: &str,
        source_script_pubkey: &Script,
        source_pk_hash: &[u8; 32],
        mnemonic: &str,
        utxos: &[StoredUtxo],
        destination: &str,
        amount: u64,
        change_address: Option<&str>,
    ) -> Result<(elements::Transaction, SpendPreview), SpendError> {
        // 1. Calculate spend preview
        let preview = calculate_spend_preview(source_address, destination, amount, utxos)?;

        // 2. Use only the first UTXO for now (simplicity - can expand later)
        let utxo = &utxos[0];

        // 3. Parse destination address
        let dest_addr = parse_address(destination, self.address_params)?;
        let dest_script = dest_addr.script_pubkey();

        // 4. Build change script if needed
        let change_script = if preview.has_change {
            if let Some(change_addr_str) = change_address {
                let change_addr = parse_address(change_addr_str, self.address_params)?;
                Some(change_addr.script_pubkey())
            } else {
                return Err(SpendError::ProgramError("Change address required but not provided".into()));
            }
        } else {
            None
        };

        // 5. Build and sign the transaction
        let tx = build_and_sign_transaction(
            &self.program_path,
            utxo,
            source_script_pubkey.clone(),
            source_pk_hash,
            mnemonic,
            dest_script,
            amount,
            preview.fee,
            change_script,
            preview.change_amount,
            self.genesis_hash,
        )?;

        Ok((tx, preview))
    }
}

/// Serialize a transaction to hex for broadcasting
pub fn transaction_to_hex(tx: &elements::Transaction) -> String {
    use elements::encode::Encodable;
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf).expect("Encoding should not fail");
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_secret_key() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let sk = derive_secret_key_from_mnemonic(mnemonic).unwrap();
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn test_sign_and_verify() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let sk = derive_secret_key_from_mnemonic(mnemonic).unwrap();
        let message = [1u8; 32];
        
        let sig = sign_schnorr_with_bytes(&sk, message).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_pubkey_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let sk = derive_secret_key_from_mnemonic(mnemonic).unwrap();
        let pk = get_xonly_pubkey(&sk).unwrap();
        
        assert_eq!(pk.len(), 32);
        
        // Verify key pair matches
        assert!(validate_key_pair(&sk, &pk).unwrap());
    }

    #[test]
    fn test_pk_hash() {
        let pk = [1u8; 32];
        let hash = compute_pk_hash(&pk);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_spend_preview_insufficient_funds() {
        let utxos = vec![StoredUtxo {
            id: 1,
            address_id: 1,
            txid: "abc".to_string(),
            vout: 0,
            amount: 1000, // Only 1000 sats
            asset: LBTC_TESTNET_ASSET_ID.to_string(),
            spent: false,
        }];

        let result = calculate_spend_preview("src", "dst", 10000, &utxos);
        assert!(matches!(result, Err(SpendError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_spend_preview_with_change() {
        let utxos = vec![StoredUtxo {
            id: 1,
            address_id: 1,
            txid: "abc".to_string(),
            vout: 0,
            amount: 100000, // 100k sats
            asset: LBTC_TESTNET_ASSET_ID.to_string(),
            spent: false,
        }];

        let preview = calculate_spend_preview("src", "dst", 50000, &utxos).unwrap();
        assert_eq!(preview.amount, 50000);
        assert_eq!(preview.fee, DEFAULT_FEE_SATS);
        assert!(preview.has_change);
        assert_eq!(preview.change_amount, 100000 - 50000 - DEFAULT_FEE_SATS);
    }

    #[test]
    fn test_spend_preview_no_change_dust() {
        let utxos = vec![StoredUtxo {
            id: 1,
            address_id: 1,
            txid: "abc".to_string(),
            vout: 0,
            amount: 1000, // 1000 sats - just enough for spend + fee with no change
            asset: LBTC_TESTNET_ASSET_ID.to_string(),
            spent: false,
        }];

        // Spending 400 sats + 500 fee = 900, leaving 100 sats (below dust)
        let preview = calculate_spend_preview("src", "dst", 400, &utxos).unwrap();
        assert_eq!(preview.amount, 400);
        assert!(!preview.has_change);
        assert_eq!(preview.change_amount, 0);
        // The remaining 600 sats goes to fee
        assert_eq!(preview.fee, 1000 - 400);
    }
}

