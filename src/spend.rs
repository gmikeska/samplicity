//! Spend module for Samplicity
//!
//! Handles transaction building, signing, and broadcasting for spending from
//! Simplicity P2PKH addresses.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_arguments)]

use bip39::Mnemonic;
use musk::elements::{self, Address, Script};
use musk::simplicityhl::num::U256;
use musk::{
    Arguments, InstantiatedProgram, Program, SpendBuilder, Value, ValueConstructible, WitnessName,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::str::FromStr;

use crate::db::StoredUtxo;
use musk::RpcClient;
use std::sync::Arc;

/// L-BTC asset ID for Liquid Testnet
pub const LBTC_TESTNET_ASSET_ID: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// Dust threshold in satoshis (below this, no change output is created)
pub const DUST_THRESHOLD: u64 = 546;

/// Default fee rate in satoshis per kilobyte (fallback when estimation fails)
pub const DEFAULT_FEE_RATE_SAT_PER_KB: u64 = 1000; // 1 sat/byte

/// Minimum fee in satoshis (floor for very small transactions)
pub const MIN_FEE_SATS: u64 = 250;

/// Estimated sizes for transaction components (in bytes)
mod tx_size {
    /// Base transaction overhead (version, locktime, input/output counts)
    pub const BASE: usize = 10;

    /// Per-input size (Simplicity/Taproot inputs are larger than segwit)
    pub const INPUT: usize = 150;

    /// Per-output size for explicit outputs
    pub const OUTPUT_EXPLICIT: usize = 45;

    /// Per-output size for confidential outputs (includes range proofs)
    pub const OUTPUT_CONFIDENTIAL: usize = 2500;

    /// Fee output size
    pub const FEE_OUTPUT: usize = 45;
}

/// Check if an address is confidential based on its prefix
///
/// Confidential addresses start with "tlq" (testnet) or "lq" (mainnet)
/// Explicit addresses start with "tex" (testnet) or "ex" (mainnet)
#[must_use]
pub fn is_confidential_address(address: &str) -> bool {
    address.starts_with("tlq") || address.starts_with("lq")
}

/// Error type for spend operations
#[derive(Debug)]
#[allow(dead_code)] // Variants reserved for future use
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
    ConfidentialNotSupported(String),
}

impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientFunds {
                available,
                required,
            } => {
                write!(
                    f,
                    "Insufficient funds: have {available} sats, need {required} sats"
                )
            }
            Self::NoUtxos => write!(f, "No UTXOs available to spend"),
            Self::InvalidAddress(msg) => write!(f, "Invalid address: {msg}"),
            Self::InvalidMnemonic(msg) => write!(f, "Invalid mnemonic: {msg}"),
            Self::ProgramError(msg) => write!(f, "Program error: {msg}"),
            Self::SigningError(msg) => write!(f, "Signing error: {msg}"),
            Self::BroadcastError(msg) => write!(f, "Broadcast error: {msg}"),
            Self::DatabaseError(msg) => write!(f, "Database error: {msg}"),
            Self::GenesisHashError(msg) => write!(f, "Genesis hash error: {msg}"),
            Self::ConfidentialNotSupported(msg) => {
                write!(f, "Confidential spending not yet supported: {msg}")
            }
        }
    }
}

impl std::error::Error for SpendError {}

/// Result of a successful spend operation
#[derive(Debug, Clone)]
#[allow(dead_code)] // Reserved for future use
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
/// Uses the same derivation as deploy.rs: first 32 bytes of `mnemonic.to_seed`("")
pub fn derive_secret_key_from_mnemonic(mnemonic_phrase: &str) -> Result<[u8; 32], SpendError> {
    let mnemonic = Mnemonic::from_str(mnemonic_phrase)
        .map_err(|e| SpendError::InvalidMnemonic(format!("Failed to parse mnemonic: {e}")))?;

    let seed = mnemonic.to_seed("");
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&seed[..32]);

    Ok(secret_key)
}

/// Sign a message using Schnorr signature with actual secret key bytes
///
/// This is different from musk's `util::sign_schnorr` which only takes u32
pub fn sign_schnorr_with_bytes(
    secret_key: &[u8; 32],
    message: [u8; 32],
) -> Result<[u8; 64], SpendError> {
    let secp = Secp256k1::new();

    let sk = SecretKey::from_slice(secret_key)
        .map_err(|e| SpendError::SigningError(format!("Invalid secret key: {e}")))?;

    let keypair = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(message);
    let signature = keypair.sign_schnorr(msg);

    Ok(signature.serialize())
}

/// Get the x-only public key from a secret key
pub fn get_xonly_pubkey(secret_key: &[u8; 32]) -> Result<[u8; 32], SpendError> {
    let secp = Secp256k1::new();

    let sk = SecretKey::from_slice(secret_key)
        .map_err(|e| SpendError::SigningError(format!("Invalid secret key: {e}")))?;

    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = keypair.x_only_public_key();

    Ok(xonly.serialize())
}

/// Compute SHA256 hash of a public key (as used in p2pkh.simf)
#[must_use]
#[allow(dead_code)] // Used in tests
pub fn compute_pk_hash(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.finalize().into()
}

/// Validate that a secret key matches the stored pubkey
#[allow(dead_code)] // Used in tests
pub fn validate_key_pair(secret_key: &[u8; 32], stored_pubkey: &[u8]) -> Result<bool, SpendError> {
    let derived_pubkey = get_xonly_pubkey(secret_key)?;
    Ok(derived_pubkey.as_slice() == stored_pubkey)
}

/// Estimate transaction size based on input/output count and confidentiality
///
/// # Arguments
///
/// * `num_inputs` - Number of UTXOs being spent
/// * `dest_is_confidential` - Whether the destination is confidential
/// * `has_change` - Whether a change output will be created
/// * `change_is_confidential` - Whether the change output is confidential
const fn estimate_tx_size(
    num_inputs: usize,
    dest_is_confidential: bool,
    has_change: bool,
    change_is_confidential: bool,
) -> usize {
    let mut size = tx_size::BASE;

    // Add input sizes
    size += tx_size::INPUT * num_inputs;

    // Add destination output size
    size += if dest_is_confidential {
        tx_size::OUTPUT_CONFIDENTIAL
    } else {
        tx_size::OUTPUT_EXPLICIT
    };

    // Add change output size if applicable
    if has_change {
        size += if change_is_confidential {
            tx_size::OUTPUT_CONFIDENTIAL
        } else {
            tx_size::OUTPUT_EXPLICIT
        };
    }

    // Add fee output
    size += tx_size::FEE_OUTPUT;

    size
}

/// Calculate fee from estimated transaction size and fee rate
///
/// # Arguments
///
/// * `tx_size` - Estimated transaction size in bytes
/// * `fee_rate_sat_per_kb` - Fee rate in satoshis per kilobyte
fn calculate_fee_from_size(tx_size: usize, fee_rate_sat_per_kb: u64) -> u64 {
    #[allow(clippy::cast_possible_truncation)]
    let fee = (tx_size as u64 * fee_rate_sat_per_kb) / 1000;
    fee.max(MIN_FEE_SATS)
}

/// Calculate spend preview (fee estimation, change calculation) with dynamic fee
///
/// # Arguments
///
/// * `source_address` - Source address
/// * `destination` - Destination address
/// * `amount` - Amount to send in satoshis
/// * `utxos` - Available UTXOs to spend
/// * `fee_rate_sat_per_kb` - Optional fee rate (uses default if None)
pub fn calculate_spend_preview(
    source_address: &str,
    destination: &str,
    amount: u64,
    utxos: &[StoredUtxo],
) -> Result<SpendPreview, SpendError> {
    calculate_spend_preview_with_fee_rate(source_address, destination, amount, utxos, None, None)
}

/// Calculate spend preview with explicit fee rate and change address
///
/// # Arguments
///
/// * `source_address` - Source address
/// * `destination` - Destination address
/// * `amount` - Amount to send in satoshis
/// * `utxos` - Available UTXOs to spend (all will be consumed)
/// * `fee_rate_sat_per_kb` - Optional fee rate in sat/kB (uses default if None)
/// * `change_address` - Optional change address (needed to determine if change is confidential)
pub fn calculate_spend_preview_with_fee_rate(
    source_address: &str,
    destination: &str,
    amount: u64,
    utxos: &[StoredUtxo],
    fee_rate_sat_per_kb: Option<u64>,
    change_address: Option<&str>,
) -> Result<SpendPreview, SpendError> {
    if utxos.is_empty() {
        return Err(SpendError::NoUtxos);
    }

    let fee_rate = fee_rate_sat_per_kb.unwrap_or(DEFAULT_FEE_RATE_SAT_PER_KB);

    // Calculate total available from ALL UTXOs
    let total_input: u64 = utxos.iter().map(|u| u.amount).sum();

    // Determine confidentiality for fee estimation
    let dest_is_confidential = is_confidential_address(destination);
    let change_is_confidential = change_address.is_some_and(is_confidential_address);

    // First pass: estimate with change output
    let size_with_change = estimate_tx_size(
        utxos.len(),
        dest_is_confidential,
        true,
        change_is_confidential,
    );
    let fee_with_change = calculate_fee_from_size(size_with_change, fee_rate);

    // Calculate required amount (send + fee)
    let required_with_change = amount.saturating_add(fee_with_change);

    if total_input < required_with_change {
        // Try without change output (lower fee)
        let size_no_change = estimate_tx_size(utxos.len(), dest_is_confidential, false, false);
        let fee_no_change = calculate_fee_from_size(size_no_change, fee_rate);
        let required_no_change = amount.saturating_add(fee_no_change);

        if total_input < required_no_change {
            return Err(SpendError::InsufficientFunds {
                available: total_input,
                required: required_with_change,
            });
        }

        // No change output case - remainder goes to fee
        let actual_fee = total_input.saturating_sub(amount);
        return Ok(SpendPreview {
            source_address: source_address.to_string(),
            destination: destination.to_string(),
            amount,
            fee: actual_fee,
            change_amount: 0,
            has_change: false,
            total_input,
        });
    }

    // Calculate change
    let change_amount = total_input.saturating_sub(required_with_change);
    let has_change = change_amount > DUST_THRESHOLD;

    if has_change {
        Ok(SpendPreview {
            source_address: source_address.to_string(),
            destination: destination.to_string(),
            amount,
            fee: fee_with_change,
            change_amount,
            has_change: true,
            total_input,
        })
    } else {
        // Change would be dust, add it to fee instead
        // Recalculate fee without change output
        let size_no_change = estimate_tx_size(utxos.len(), dest_is_confidential, false, false);
        let base_fee_no_change = calculate_fee_from_size(size_no_change, fee_rate);
        let actual_fee = total_input.saturating_sub(amount);

        // Make sure fee is at least the base fee
        if actual_fee < base_fee_no_change {
            return Err(SpendError::InsufficientFunds {
                available: total_input,
                required: amount + base_fee_no_change,
            });
        }

        Ok(SpendPreview {
            source_address: source_address.to_string(),
            destination: destination.to_string(),
            amount,
            fee: actual_fee,
            change_amount: 0,
            has_change: false,
            total_input,
        })
    }
}

/// Load and instantiate the p2pkh program with the given `pk_hash`
pub fn load_p2pkh_program(
    program_path: &str,
    pk_hash: &[u8; 32],
) -> Result<InstantiatedProgram, SpendError> {
    let program = Program::from_file(program_path)
        .map_err(|e| SpendError::ProgramError(format!("Failed to load program: {e}")))?;

    let mut args = HashMap::new();
    args.insert(
        WitnessName::from_str_unchecked("PK_HASH"),
        Value::u256(U256::from_byte_array(*pk_hash)),
    );

    let compiled = program
        .instantiate(Arguments::from(args))
        .map_err(|e| SpendError::ProgramError(format!("Failed to instantiate program: {e}")))?;

    Ok(compiled)
}

/// Build witness values for p2pkh spending
///
/// The p2pkh.simf program requires:
/// - `witness::PK` - the x-only public key
/// - `witness::SIG` - the Schnorr signature of `sighash_all`
#[must_use]
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
        .map_err(|e| SpendError::InvalidAddress(format!("Failed to parse address: {e}")))
}

/// Get the L-BTC asset ID for testnet
pub fn get_lbtc_asset_id() -> Result<elements::issuance::AssetId, SpendError> {
    // Use from_str which handles the byte order conversion correctly
    // (display format is big-endian, internal format is little-endian)
    elements::issuance::AssetId::from_str(LBTC_TESTNET_ASSET_ID)
        .map_err(|e| SpendError::ProgramError(format!("Invalid asset ID: {e}")))
}

/// Convert a stored UTXO to musk's Utxo type
pub fn stored_utxo_to_musk_utxo(
    utxo: &StoredUtxo,
    script_pubkey: Script,
) -> Result<musk::client::Utxo, SpendError> {
    let txid = elements::Txid::from_str(&utxo.txid)
        .map_err(|e| SpendError::ProgramError(format!("Invalid txid: {e}")))?;

    // Use from_str which handles byte order conversion correctly
    let asset_id = elements::issuance::AssetId::from_str(&utxo.asset)
        .map_err(|e| SpendError::ProgramError(format!("Invalid asset ID: {e}")))?;

    // Convert blinding data from Vec<u8> to fixed-size arrays
    let amount_blinder = utxo.amount_blinder.as_ref().and_then(|v| {
        if v.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(v);
            Some(arr)
        } else {
            None
        }
    });

    let asset_blinder = utxo.asset_blinder.as_ref().and_then(|v| {
        if v.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(v);
            Some(arr)
        } else {
            None
        }
    });

    let amount_commitment = utxo.amount_commitment.as_ref().and_then(|v| {
        if v.len() == 33 {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(v);
            Some(arr)
        } else {
            None
        }
    });

    let asset_commitment = utxo.asset_commitment.as_ref().and_then(|v| {
        if v.len() == 33 {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(v);
            Some(arr)
        } else {
            None
        }
    });

    Ok(musk::client::Utxo {
        txid,
        vout: utxo.vout,
        amount: utxo.amount,
        script_pubkey,
        asset: elements::confidential::Asset::Explicit(asset_id),
        amount_blinder,
        asset_blinder,
        amount_commitment,
        asset_commitment,
    })
}

/// Build and sign a spending transaction from multiple UTXOs
///
/// This takes multiple source UTXOs, builds a transaction with destination and optional change,
/// signs each input using the derived secret key, and returns the finalized transaction.
/// All UTXOs are consumed to prevent address reuse.
pub fn build_and_sign_transaction(
    program_path: &str,
    utxos: &[StoredUtxo],
    source_script_pubkey: &Script,
    source_pk_hash: &[u8; 32],
    mnemonic: &str,
    destination_script: Script,
    amount: u64,
    fee: u64,
    change_script: Option<Script>,
    change_amount: u64,
    genesis_hash: elements::BlockHash,
) -> Result<elements::Transaction, SpendError> {
    if utxos.is_empty() {
        return Err(SpendError::NoUtxos);
    }

    // === VERIFICATION: Prove input == outputs ===
    let input_amount: u64 = utxos.iter().map(|u| u.amount).sum();
    let total_outputs = amount + fee + change_amount;

    println!("=== TRANSACTION VALUE VERIFICATION ===");
    println!(
        "  INPUTS: {} UTXOs totaling {input_amount} sats",
        utxos.len()
    );
    for (i, utxo) in utxos.iter().enumerate() {
        println!(
            "    [{i}] txid={}:{} amount={}",
            utxo.txid, utxo.vout, utxo.amount
        );
    }
    println!("  OUTPUT: Destination amount  = {amount} sats");
    println!("  OUTPUT: Change amount       = {change_amount} sats");
    println!("  OUTPUT: Fee amount          = {fee} sats");
    println!("  TOTAL:  Sum of outputs      = {total_outputs} sats");

    if input_amount != total_outputs {
        let diff = input_amount.abs_diff(total_outputs);
        eprintln!("  *** MISMATCH! Input != Outputs (diff = {diff} sats) ***");
        return Err(SpendError::ProgramError(format!(
            "Value mismatch: input={input_amount} but outputs sum to {total_outputs} (diff={diff})"
        )));
    }
    println!("  [OK] Values match: {input_amount} == {total_outputs}");
    println!("=======================================");

    // 1. Load and instantiate the program
    let program = load_p2pkh_program(program_path, source_pk_hash)?;

    // 2. Convert all stored UTXOs to musk format
    let musk_utxos: Vec<musk::client::Utxo> = utxos
        .iter()
        .map(|u| stored_utxo_to_musk_utxo(u, source_script_pubkey.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    // 3. Get asset ID
    let asset_id = get_lbtc_asset_id()?;

    // 4. Create spend builder with all UTXOs
    let mut builder = SpendBuilder::new(program, musk_utxos).genesis_hash(genesis_hash);

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

    // 8. Derive secret key from mnemonic
    let secret_key = derive_secret_key_from_mnemonic(mnemonic)?;

    // 9. Get the x-only public key
    let pubkey = get_xonly_pubkey(&secret_key)?;

    // 10. Sign each input
    let num_inputs = builder.num_inputs();
    let mut witness_values_vec = Vec::with_capacity(num_inputs);

    for i in 0..num_inputs {
        // Compute sighash for this input
        let sighash = builder.sighash_all_for_input(i).map_err(|e| {
            SpendError::SigningError(format!("Failed to compute sighash for input {i}: {e}"))
        })?;

        // Sign this input
        let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

        // Build witness values for this input
        let witness_values = build_witness_values(&pubkey, &signature);
        witness_values_vec.push(witness_values);
    }

    // 11. Finalize with all witness values
    builder
        .finalize_multi(witness_values_vec)
        .map_err(|e| SpendError::SigningError(format!("Failed to finalize transaction: {e}")))
}

/// Build and sign a confidential transaction from multiple UTXOs
///
/// This is used when the destination or change address is confidential.
/// All UTXOs are consumed to prevent address reuse.
/// The process is:
/// 1. Build an unsigned transaction with explicit values
/// 2. Call rawblindrawtransaction RPC to blind outputs going to confidential addresses
/// 3. Compute sighash for each input from the blinded transaction
/// 4. Sign each input and return the blinded transaction
#[allow(clippy::too_many_arguments, clippy::too_many_lines, clippy::needless_pass_by_value)]
pub fn build_and_sign_confidential_transaction(
    program_path: &str,
    utxos: &[StoredUtxo],
    source_script_pubkey: &Script,
    source_pk_hash: &[u8; 32],
    mnemonic: &str,
    dest_addr: &Address,
    destination_script: Script,
    amount: u64,
    fee: u64,
    change_addr: Option<Address>,
    change_script: Option<Script>,
    change_amount: u64,
    genesis_hash: elements::BlockHash,
    rpc_client: &RpcClient,
) -> Result<elements::Transaction, SpendError> {
    if utxos.is_empty() {
        return Err(SpendError::NoUtxos);
    }

    // === VERIFICATION: Prove input == outputs ===
    let input_amount: u64 = utxos.iter().map(|u| u.amount).sum();
    let total_outputs = amount + fee + change_amount;

    println!("=== CONFIDENTIAL TRANSACTION VALUE VERIFICATION ===");
    println!(
        "  INPUTS: {} UTXOs totaling {input_amount} sats",
        utxos.len()
    );
    for (i, utxo) in utxos.iter().enumerate() {
        println!(
            "    [{i}] txid={}:{} amount={}",
            utxo.txid, utxo.vout, utxo.amount
        );
    }
    println!("  OUTPUT: Destination amount  = {amount} sats");
    println!("  OUTPUT: Change amount       = {change_amount} sats");
    println!("  OUTPUT: Fee amount          = {fee} sats");
    println!("  TOTAL:  Sum of outputs      = {total_outputs} sats");
    println!(
        "  Dest is confidential: {}",
        is_confidential_address(&dest_addr.to_string())
    );
    if let Some(change) = &change_addr {
        println!(
            "  Change is confidential: {}",
            is_confidential_address(&change.to_string())
        );
    }

    if input_amount != total_outputs {
        let diff = input_amount.abs_diff(total_outputs);
        eprintln!("  *** MISMATCH! Input != Outputs (diff = {diff} sats) ***");
        return Err(SpendError::ProgramError(format!(
            "Value mismatch: input={input_amount} but outputs sum to {total_outputs} (diff={diff})"
        )));
    }
    println!("  [OK] Values match: {input_amount} == {total_outputs}");
    println!("=================================================");

    // 1. Load and instantiate the program
    let program = load_p2pkh_program(program_path, source_pk_hash)?;

    // 2. Convert all stored UTXOs to musk format
    let musk_utxos: Vec<musk::client::Utxo> = utxos
        .iter()
        .map(|u| stored_utxo_to_musk_utxo(u, source_script_pubkey.clone()))
        .collect::<Result<Vec<_>, _>>()?;

    // 3. Get asset ID
    let asset_id = get_lbtc_asset_id()?;

    // 4. Create spend builder with all UTXOs
    let mut builder = SpendBuilder::new(program.clone(), musk_utxos).genesis_hash(genesis_hash);

    // 5. Add destination output (with nonce for confidential addresses)
    if is_confidential_address(&dest_addr.to_string()) {
        // Get the blinding pubkey from the confidential address
        let blinding_key = dest_addr.blinding_pubkey.ok_or_else(|| {
            SpendError::ConfidentialNotSupported(
                "Confidential address missing blinding pubkey".to_string(),
            )
        })?;
        let nonce = musk::elements::confidential::Nonce::Confidential(blinding_key);
        builder.add_confidential_output(destination_script, amount, asset_id, nonce);
    } else {
        builder.add_output_simple(destination_script, amount, asset_id);
    }

    // 6. Add change output if applicable
    if let Some(change_script) = change_script {
        if change_amount > 0 {
            if let Some(change_a) = &change_addr {
                if is_confidential_address(&change_a.to_string()) {
                    let blinding_key = change_a.blinding_pubkey.ok_or_else(|| {
                        SpendError::ConfidentialNotSupported(
                            "Change confidential address missing blinding pubkey".to_string(),
                        )
                    })?;
                    let nonce = musk::elements::confidential::Nonce::Confidential(blinding_key);
                    builder.add_confidential_output(change_script, change_amount, asset_id, nonce);
                } else {
                    builder.add_output_simple(change_script, change_amount, asset_id);
                }
            } else {
                builder.add_output_simple(change_script, change_amount, asset_id);
            }
        }
    }

    // 7. Add fee output
    builder.add_fee(fee, asset_id);

    // 8. Derive secret key from mnemonic
    let secret_key = derive_secret_key_from_mnemonic(mnemonic)?;

    // 9. Get the x-only public key
    let pubkey = get_xonly_pubkey(&secret_key)?;

    // 10. Check if we need to blind
    if builder.needs_blinding() {
        println!("Transaction needs blinding, calling rawblindrawtransaction...");

        // 11. Build unsigned transaction
        let unsigned_tx = builder.build_unsigned();

        // 12. Get blinding parameters for all inputs
        let blinding_params = builder.get_blinding_params();
        println!("  Blinding {} inputs:", blinding_params.input_amounts.len());
        for (i, amt) in blinding_params.input_amounts.iter().enumerate() {
            println!("    [{i}] amount={amt} sats");
        }

        // 13. Call rawblindrawtransaction RPC
        let blinded_tx = rpc_client
            .blind_transaction(
                &unsigned_tx,
                &blinding_params.input_amount_blinders,
                &blinding_params.input_amounts,
                &blinding_params.input_assets,
                &blinding_params.input_asset_blinders,
            )
            .map_err(|e| SpendError::BroadcastError(format!("Failed to blind transaction: {e}")))?;

        println!("Transaction blinded successfully");

        // 14. Sign each input
        let num_inputs = builder.num_inputs();
        let mut satisfied_programs = Vec::with_capacity(num_inputs);

        for i in 0..num_inputs {
            // Compute sighash for this input from the blinded transaction
            let sighash = builder
                .sighash_all_for_blinded_input(&blinded_tx, i)
                .map_err(|e| {
                    SpendError::SigningError(format!(
                        "Failed to compute sighash for input {i}: {e}"
                    ))
                })?;

            // Sign this input
            let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

            // Build witness values and satisfy the program
            let witness_values = build_witness_values(&pubkey, &signature);
            let satisfied = program.satisfy(witness_values).map_err(|e| {
                SpendError::SigningError(format!("Failed to satisfy program for input {i}: {e}"))
            })?;
            satisfied_programs.push(satisfied);
        }

        // 15. Finalize the blinded transaction with all witnesses
        let satisfied_refs: Vec<_> = satisfied_programs.iter().collect();
        builder
            .finalize_blinded_refs(blinded_tx, &satisfied_refs)
            .map_err(|e| {
                SpendError::SigningError(format!("Failed to finalize blinded transaction: {e}"))
            })
    } else {
        // No blinding needed, use regular flow
        println!("No blinding needed, using explicit transaction flow");

        // Sign each input
        let num_inputs = builder.num_inputs();
        let mut witness_values_vec = Vec::with_capacity(num_inputs);

        for i in 0..num_inputs {
            // Compute sighash for this input
            let sighash = builder.sighash_all_for_input(i).map_err(|e| {
                SpendError::SigningError(format!("Failed to compute sighash for input {i}: {e}"))
            })?;

            // Sign this input
            let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

            // Build witness values for this input
            let witness_values = build_witness_values(&pubkey, &signature);
            witness_values_vec.push(witness_values);
        }

        // Finalize with all witness values
        builder
            .finalize_multi(witness_values_vec)
            .map_err(|e| SpendError::SigningError(format!("Failed to finalize transaction: {e}")))
    }
}

/// Complete spend operation that handles everything from UTXOs to final transaction
#[allow(dead_code)] // Reserved for future use
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
    rpc_client: Option<Arc<RpcClient>>,
}

impl SpendOrchestrator {
    /// Create a new spend orchestrator
    #[must_use]
    pub fn new(
        program_path: &str,
        address_params: &'static elements::AddressParams,
        genesis_hash: elements::BlockHash,
    ) -> Self {
        Self {
            program_path: program_path.to_string(),
            address_params,
            genesis_hash,
            rpc_client: None,
        }
    }

    /// Set the RPC client for blinding confidential transactions
    #[must_use]
    pub fn with_rpc_client(mut self, rpc_client: Arc<RpcClient>) -> Self {
        self.rpc_client = Some(rpc_client);
        self
    }

    /// Set the genesis hash
    #[must_use]
    #[allow(dead_code)] // Used in tests
    pub const fn with_genesis_hash(mut self, genesis_hash: elements::BlockHash) -> Self {
        self.genesis_hash = genesis_hash;
        self
    }

    /// Execute a spend operation
    ///
    /// This performs the complete spend workflow:
    /// 1. Get fee rate from RPC (or use default)
    /// 2. Calculate preview (fees, change) using ALL UTXOs
    /// 3. Build and sign transaction consuming ALL UTXOs
    /// 4. If destination or change is confidential, blind the transaction
    /// 5. Return the signed transaction for broadcasting
    ///
    /// All UTXOs are consumed in the transaction to prevent address reuse.
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
        // 1. Get fee rate from RPC (if available)
        let fee_rate = self
            .rpc_client
            .as_ref()
            .and_then(|c| c.estimate_smart_fee(6).ok().flatten())
            .unwrap_or(DEFAULT_FEE_RATE_SAT_PER_KB);

        println!("Using fee rate: {fee_rate} sat/kB");

        // 2. Calculate spend preview using ALL UTXOs
        let preview = calculate_spend_preview_with_fee_rate(
            source_address,
            destination,
            amount,
            utxos,
            Some(fee_rate),
            change_address,
        )?;

        println!(
            "Spending {} UTXOs totaling {} sats",
            utxos.len(),
            preview.total_input
        );

        // 3. Parse destination address
        let dest_addr = parse_address(destination, self.address_params)?;
        let dest_script = dest_addr.script_pubkey();

        // 4. Build change script if needed
        let change_script = if preview.has_change {
            if let Some(change_addr_str) = change_address {
                let change_addr = parse_address(change_addr_str, self.address_params)?;
                Some(change_addr.script_pubkey())
            } else {
                return Err(SpendError::ProgramError(
                    "Change address required but not provided".into(),
                ));
            }
        } else {
            None
        };

        // 5. Check if we need blinding (destination or change is confidential)
        let dest_is_confidential = is_confidential_address(destination);
        let change_is_confidential = change_address.is_some_and(is_confidential_address);
        let needs_blinding = dest_is_confidential || change_is_confidential;

        // 6. Build and sign the transaction using ALL UTXOs (with optional blinding)
        let tx = if needs_blinding {
            // For confidential outputs, we need the RPC client to blind
            let rpc_client = self.rpc_client.as_ref().ok_or_else(|| {
                SpendError::ConfidentialNotSupported(
                    "RPC client required for confidential transactions".to_string(),
                )
            })?;

            build_and_sign_confidential_transaction(
                &self.program_path,
                utxos, // All UTXOs
                source_script_pubkey,
                source_pk_hash,
                mnemonic,
                &dest_addr,
                dest_script,
                amount,
                preview.fee,
                change_address
                    .map(|a| parse_address(a, self.address_params))
                    .transpose()?,
                change_script,
                preview.change_amount,
                self.genesis_hash,
                rpc_client,
            )?
        } else {
            // Explicit transaction - no blinding needed
            build_and_sign_transaction(
                &self.program_path,
                utxos, // All UTXOs
                source_script_pubkey,
                source_pk_hash,
                mnemonic,
                dest_script,
                amount,
                preview.fee,
                change_script,
                preview.change_amount,
                self.genesis_hash,
            )?
        };

        Ok((tx, preview))
    }
}

/// Serialize a transaction to hex for broadcasting
///
/// # Panics
///
/// Panics if encoding the transaction fails, which should not happen for valid transactions.
#[must_use]
pub fn transaction_to_hex(tx: &elements::Transaction) -> String {
    use elements::encode::Encodable;
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf)
        .expect("Encoding should not fail");
    hex::encode(buf)
}
