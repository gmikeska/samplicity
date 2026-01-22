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

/// Default fee in satoshis (safe buffer for ~1000-3000 vbyte tx at 0.1-0.5 sat/vbyte)
pub const DEFAULT_FEE_SATS: u64 = 500;

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

/// Build and sign a spending transaction
///
/// This takes a source UTXO, builds a transaction with destination and optional change,
/// signs it using the derived secret key, and returns the finalized transaction.
#[allow(clippy::redundant_clone)]
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
    println!("  INPUT:  UTXO amount from DB = {input_amount} sats");
    println!("  OUTPUT: Destination amount  = {amount} sats");
    println!("  OUTPUT: Change amount       = {change_amount} sats");
    println!("  OUTPUT: Fee amount          = {fee} sats");
    println!("  TOTAL:  Sum of outputs      = {total_outputs} sats");
    println!("  UTXO:   txid={}, vout={}", utxo.txid, utxo.vout);

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
    let sighash = builder
        .sighash_all()
        .map_err(|e| SpendError::SigningError(format!("Failed to compute sighash: {e}")))?;

    // 9. Derive secret key from mnemonic
    let secret_key = derive_secret_key_from_mnemonic(mnemonic)?;

    // 10. Get the x-only public key
    let pubkey = get_xonly_pubkey(&secret_key)?;

    // 11. Sign the sighash
    let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

    // 12. Build witness values
    let witness_values = build_witness_values(&pubkey, &signature);

    // 13. Finalize and return the transaction
    builder
        .finalize(witness_values)
        .map_err(|e| SpendError::SigningError(format!("Failed to finalize transaction: {e}")))
}

/// Build and sign a confidential transaction
///
/// This is used when the destination or change address is confidential.
/// The process is:
/// 1. Build an unsigned transaction with explicit values
/// 2. Call rawblindrawtransaction RPC to blind outputs going to confidential addresses
/// 3. Compute sighash from the blinded transaction
/// 4. Sign and return the blinded transaction
#[allow(clippy::too_many_arguments)]
pub fn build_and_sign_confidential_transaction(
    program_path: &str,
    utxo: &StoredUtxo,
    source_script_pubkey: Script,
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
    // === VERIFICATION: Prove input == outputs ===
    let input_amount = utxo.amount;
    let total_outputs = amount + fee + change_amount;

    println!("=== CONFIDENTIAL TRANSACTION VALUE VERIFICATION ===");
    println!("  INPUT:  UTXO amount from DB = {input_amount} sats");
    println!("  OUTPUT: Destination amount  = {amount} sats");
    println!("  OUTPUT: Change amount       = {change_amount} sats");
    println!("  OUTPUT: Fee amount          = {fee} sats");
    println!("  TOTAL:  Sum of outputs      = {total_outputs} sats");
    println!("  UTXO:   txid={}, vout={}", utxo.txid, utxo.vout);
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

    // 2. Convert stored UTXO to musk format
    let musk_utxo = stored_utxo_to_musk_utxo(utxo, source_script_pubkey)?;

    // 3. Get asset ID
    let asset_id = get_lbtc_asset_id()?;

    // 4. Create spend builder
    let mut builder =
        SpendBuilder::new(program.clone(), musk_utxo.clone()).genesis_hash(genesis_hash);

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

    // 8. Check if we need to blind
    if builder.needs_blinding() {
        println!("Transaction needs blinding, calling rawblindrawtransaction...");

        // 9. Build unsigned transaction
        let unsigned_tx = builder.build_unsigned();

        // 10. Get blinding parameters
        let blinding_params = builder.get_blinding_params();
        println!(
            "  Input amount blinder: {}",
            blinding_params.input_amount_blinders[0]
        );
        println!(
            "  Input asset blinder: {}",
            blinding_params.input_asset_blinders[0]
        );
        println!("  Input amount: {} sats", blinding_params.input_amounts[0]);
        println!("  Input asset: {}", blinding_params.input_assets[0]);

        // 11. Call rawblindrawtransaction RPC
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

        // 12. Compute sighash from the blinded transaction
        let sighash = builder
            .sighash_all_for_blinded(&blinded_tx)
            .map_err(|e| SpendError::SigningError(format!("Failed to compute sighash: {e}")))?;

        // 13. Derive secret key from mnemonic
        let secret_key = derive_secret_key_from_mnemonic(mnemonic)?;

        // 14. Get the x-only public key
        let pubkey = get_xonly_pubkey(&secret_key)?;

        // 15. Sign the sighash
        let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

        // 16. Build witness values
        let witness_values = build_witness_values(&pubkey, &signature);

        // 17. Satisfy the program
        let satisfied = program
            .satisfy(witness_values)
            .map_err(|e| SpendError::SigningError(format!("Failed to satisfy program: {e}")))?;

        // 18. Finalize the blinded transaction with witness
        builder
            .finalize_blinded(blinded_tx, &satisfied)
            .map_err(|e| {
                SpendError::SigningError(format!("Failed to finalize blinded transaction: {e}"))
            })
    } else {
        // No blinding needed, use regular flow
        println!("No blinding needed, using explicit transaction flow");

        // 8. Compute sighash
        let sighash = builder
            .sighash_all()
            .map_err(|e| SpendError::SigningError(format!("Failed to compute sighash: {e}")))?;

        // 9. Derive secret key from mnemonic
        let secret_key = derive_secret_key_from_mnemonic(mnemonic)?;

        // 10. Get the x-only public key
        let pubkey = get_xonly_pubkey(&secret_key)?;

        // 11. Sign the sighash
        let signature = sign_schnorr_with_bytes(&secret_key, sighash)?;

        // 12. Build witness values
        let witness_values = build_witness_values(&pubkey, &signature);

        // 13. Finalize and return the transaction
        builder
            .finalize(witness_values)
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
    /// 1. Validate inputs
    /// 2. Calculate preview (fees, change)
    /// 3. Deploy change address if needed
    /// 4. Build and sign transaction
    /// 5. If destination or change is confidential, blind the transaction
    /// 6. Return the raw transaction hex for broadcasting
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
                return Err(SpendError::ProgramError(
                    "Change address required but not provided".into(),
                ));
            }
        } else {
            None
        };

        // 5. Check if we need blinding (destination or change is confidential)
        let dest_is_confidential = is_confidential_address(destination);
        let change_is_confidential = change_address.map_or(false, is_confidential_address);
        let needs_blinding = dest_is_confidential || change_is_confidential;

        // 6. Build and sign the transaction (with optional blinding)
        let tx = if needs_blinding {
            // For confidential outputs, we need the RPC client to blind
            let rpc_client = self.rpc_client.as_ref().ok_or_else(|| {
                SpendError::ConfidentialNotSupported(
                    "RPC client required for confidential transactions".to_string(),
                )
            })?;

            build_and_sign_confidential_transaction(
                &self.program_path,
                utxo,
                source_script_pubkey.clone(),
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
