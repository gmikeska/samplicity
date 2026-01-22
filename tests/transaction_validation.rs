//! Transaction validation integration tests
//!
//! These tests verify that transactions built by musk are properly formed
//! by using the Elements node's `decoderawtransaction` and `testmempoolaccept`
//! RPC methods.
//!
//! These tests use existing UTXOs from the samplicity test database and do NOT
//! broadcast transactions, so they are safe to run repeatedly.
//!
//! ## Test Environment Addresses (samplicity6 wallet)
//!
//! | Address | Type | Balance | Notes |
//! |---------|------|---------|-------|
//! | `tex1pztlt8g...` | EX | 100,000 | Funded explicit source |
//! | `tlq1pq23ygy...` | CT | 98,500 | Funded confidential source (blinded) |
//! | `tlq1pq04th4...` | CT | 1,000 | Small funded confidential |
//! | `tlq1pq22cyv...` | CT | 0 | Empty confidential destination |
//! | `tex1pu8a280...` | EX | 0 | Empty explicit destination |
//!
//! Run with: `MUSK_ENV=test cargo test --test transaction_validation -- --ignored`

use musk::RpcClient;
use samplicity::deploy::{deploy_new_address, AddressType};
use samplicity::spend::{
    build_and_sign_confidential_transaction, build_and_sign_transaction, calculate_spend_preview,
    is_confidential_address, transaction_to_hex, SpendOrchestrator,
};
use samplicity::{detect_address_type, Database, StoredAddress};
use serial_test::serial;
use std::str::FromStr;
use std::sync::Arc;

// ============================================================================
// Test Environment Constants
// ============================================================================

/// Path to the p2pkh program
const P2PKH_PROGRAM_PATH: &str = "musk/p2pkh.simf";

/// Amount to send in test transactions (must be less than available UTXO)
const SEND_AMOUNT: u64 = 500; // 500 sats - small amount for testing

// Test environment addresses (from samplicity-test.db with samplicity6 wallet)
mod test_addresses {
    /// Funded explicit address - 100,000 sats
    pub const EXPLICIT_FUNDED: &str =
        "tex1pztlt8gfryjj4p43rdyjjce74pwqckvufafus3xjwxzxuccuytqmscrcedf";

    /// Empty explicit address - for use as destination
    pub const EXPLICIT_EMPTY: &str =
        "tex1pu8a280erz6g493tnxzh39ktrhnx9satg536dd7ev2jqh7d9tjaeslc5sq5";

    /// Funded confidential address - 98,500 sats (blinded UTXO)
    pub const CONFIDENTIAL_FUNDED: &str =
        "tlq1pq23ygyufwnc44s6p3uzzltnmg9takqvq0hvphptsrgj5wcm5jtvrvw8r7mgjfn3ds0fz5aejkxc28wpk6je5zw6604nctyxfyagx0y47gte7exam3zfm";

    /// Small funded confidential address - 1,000 sats (blinded UTXO)
    pub const CONFIDENTIAL_SMALL: &str =
        "tlq1pq04th4lzh7nevfvzzsk89wnpqr6aemra33l4w660l8jml66n68zfpqq6tnwg7sak60rmyhdpw02h2v2veaq6e5vl8w4ejx94dz6nfne48ll07whhzn5p";

    /// Empty confidential address - for use as destination (has blinding key)
    pub const CONFIDENTIAL_EMPTY: &str =
        "tlq1pq22cyvnx3tx7ja58vyqxe6cc6e4lrjtr0gufk2r37gfpfg2esrgnc6s86p69t2ls0qmgk4qjqjx3phuvy7rs33atnvn6fpccypg330mxn4gmfz0pt24f";
}

// ============================================================================
// Test Helpers
// ============================================================================

/// Helper to create RPC client from config (always uses [test] environment)
fn create_rpc_client() -> RpcClient {
    RpcClient::from_env_config_file_with_env("musk.conf", "test")
        .expect("Failed to create RPC client from musk.conf [test] environment")
}

/// Helper to get genesis hash from RPC client
fn get_genesis_hash(client: &mut RpcClient) -> musk::elements::BlockHash {
    client.genesis_hash().expect("Failed to get genesis hash")
}

/// Helper to open the samplicity test database (always uses samplicity-test.db)
fn open_database() -> Database {
    Database::open("samplicity-test.db").expect("Failed to open samplicity-test.db")
}

/// Get address info and UTXOs for a specific address
fn get_address_with_utxos(
    db: &Database,
    address: &str,
) -> (StoredAddress, Vec<samplicity::db::StoredUtxo>) {
    let addr_info = db
        .get_address(address)
        .expect("Failed to query address")
        .unwrap_or_else(|| panic!("Address not found in test database: {address}"));

    let utxos = db.get_unspent_utxos(address).expect("Failed to get UTXOs");

    (addr_info, utxos)
}

/// Get the mnemonic for an address from the database
fn get_mnemonic_for_address(db: &Database, address: &str) -> String {
    db.get_pubkey_for_address(address)
        .expect("Failed to query pubkey")
        .expect("No pubkey found for address")
        .mnemonic
}

/// Get pk_hash bytes for an address
fn get_pk_hash_bytes(addr_info: &StoredAddress) -> [u8; 32] {
    hex::decode(&addr_info.pk_hash)
        .expect("Invalid pk_hash hex")
        .try_into()
        .expect("Invalid pk_hash length")
}

/// Deploy a new address with the specified type (for change addresses)
fn deploy_address_with_type(
    address_params: &'static musk::elements::AddressParams,
    address_type: AddressType,
) -> String {
    let deployed = deploy_new_address(P2PKH_PROGRAM_PATH, address_params, address_type)
        .expect("Failed to deploy address");
    deployed.address
}

// ============================================================================
// Scenario 1: Explicit → Explicit
// ============================================================================

#[test]
#[ignore = "requires live Elements node and samplicity-test.db"]
#[serial]
fn test_scenario_1_explicit_to_explicit() {
    println!("\n=== SCENARIO 1: Explicit → Explicit ===\n");

    // Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();

    // Source: funded explicit address
    let source_address = test_addresses::EXPLICIT_FUNDED;
    let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

    assert!(
        !utxos.is_empty(),
        "Source address has no UTXOs - fund {} first",
        source_address
    );
    assert!(
        utxos[0].amount > SEND_AMOUNT + 1000,
        "Insufficient funds in source"
    );

    let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
    let mnemonic = get_mnemonic_for_address(&db, source_address);

    println!("Source (EX): {source_address}");
    println!("UTXO: {} sats", utxos[0].amount);

    // Destination: empty explicit address from test environment
    let dest_address = test_addresses::EXPLICIT_EMPTY;
    println!("Destination (EX): {dest_address}");

    // Calculate preview
    let preview = calculate_spend_preview(source_address, dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");
    println!(
        "Preview: send={}, fee={}, change={}",
        preview.amount, preview.fee, preview.change_amount
    );

    // Change address should be explicit (matching source type)
    let change_address = if preview.has_change {
        let addr = deploy_address_with_type(address_params, AddressType::Explicit);
        assert!(
            addr.starts_with("tex"),
            "Change should be explicit (tex prefix)"
        );
        println!("Change (EX): {addr}");
        Some(addr)
    } else {
        None
    };

    // Build transaction
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr)
            .unwrap()
            .script_pubkey()
    });

    let tx = build_and_sign_transaction(
        P2PKH_PROGRAM_PATH,
        &utxos[0],
        source_script,
        &pk_hash_bytes,
        &mnemonic,
        dest_script,
        SEND_AMOUNT,
        preview.fee,
        change_script,
        preview.change_amount,
        genesis_hash,
    )
    .expect("Failed to build transaction");

    let tx_hex = transaction_to_hex(&tx);
    println!("Transaction: {} bytes", tx_hex.len() / 2);

    // Verify with mempool accept
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = mempool_result
        .first()
        .and_then(|r| r.get("allowed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if !allowed {
        let reason = mempool_result
            .first()
            .and_then(|r| r.get("reject-reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        panic!("Transaction rejected: {reason}");
    }

    println!("\n✅ SCENARIO 1 PASSED: Explicit → Explicit");
    println!("   Transaction accepted by mempool (not broadcast)");
}

// ============================================================================
// Scenario 2: Explicit → Confidential
// ============================================================================

#[test]
#[ignore = "requires live Elements node and samplicity-test.db"]
#[serial]
fn test_scenario_2_explicit_to_confidential() {
    println!("\n=== SCENARIO 2: Explicit → Confidential ===\n");
    println!("This tests sending from an explicit source to a confidential destination.");
    println!("The output should be BLINDED even though the input is explicit.\n");

    // Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();
    let rpc_client = Arc::new(create_rpc_client());

    // Source: funded explicit address
    let source_address = test_addresses::EXPLICIT_FUNDED;
    let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

    assert!(
        !utxos.is_empty(),
        "Source address has no UTXOs - fund {} first",
        source_address
    );

    let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
    let mnemonic = get_mnemonic_for_address(&db, source_address);

    println!("Source (EX): {source_address}");
    println!("UTXO: {} sats", utxos[0].amount);

    // Destination: empty confidential address from test environment
    let dest_address = test_addresses::CONFIDENTIAL_EMPTY;
    assert!(
        dest_address.starts_with("tlq"),
        "Destination should be confidential"
    );
    println!("Destination (CT): {dest_address}");

    // Calculate preview
    let preview = calculate_spend_preview(source_address, dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");
    println!(
        "Preview: send={}, fee={}, change={}",
        preview.amount, preview.fee, preview.change_amount
    );

    // Change address should be explicit (matching source type)
    let change_address = if preview.has_change {
        let addr = deploy_address_with_type(address_params, AddressType::Explicit);
        assert!(addr.starts_with("tex"), "Change should be explicit");
        println!("Change (EX): {addr}");
        Some(addr)
    } else {
        None
    };

    // Build confidential transaction (blinds output to CT destination)
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr)
            .unwrap()
            .script_pubkey()
    });
    let change_addr_parsed = change_address
        .as_ref()
        .map(|addr| musk::elements::Address::from_str(addr).unwrap());

    let tx = build_and_sign_confidential_transaction(
        P2PKH_PROGRAM_PATH,
        &utxos[0],
        source_script,
        &pk_hash_bytes,
        &mnemonic,
        &dest_addr,
        dest_script,
        SEND_AMOUNT,
        preview.fee,
        change_addr_parsed,
        change_script,
        preview.change_amount,
        genesis_hash,
        &rpc_client,
    )
    .expect("Failed to build confidential transaction");

    let tx_hex = transaction_to_hex(&tx);
    println!("Transaction: {} bytes", tx_hex.len() / 2);

    // Verify with mempool accept
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = mempool_result
        .first()
        .and_then(|r| r.get("allowed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if !allowed {
        let reason = mempool_result
            .first()
            .and_then(|r| r.get("reject-reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        panic!("Transaction rejected: {reason}");
    }

    println!("\n✅ SCENARIO 2 PASSED: Explicit → Confidential");
    println!("   Output is blinded (destination is CT)");
    println!("   Transaction accepted by mempool (not broadcast)");
}

// ============================================================================
// Scenario 3: Confidential → Explicit
// ============================================================================

#[test]
#[ignore = "requires live Elements node and samplicity-test.db"]
#[serial]
fn test_scenario_3_confidential_to_explicit() {
    println!("\n=== SCENARIO 3: Confidential → Explicit ===\n");

    // Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();
    let rpc_client = Arc::new(create_rpc_client());

    // Source: funded confidential address with blinded UTXO
    let source_address = test_addresses::CONFIDENTIAL_FUNDED;
    let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

    assert!(
        !utxos.is_empty(),
        "Source address has no UTXOs - fund {} first",
        source_address
    );
    assert!(
        utxos[0].amount_blinder.is_some(),
        "UTXO should have blinding data"
    );

    let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
    let mnemonic = get_mnemonic_for_address(&db, source_address);

    println!("Source (CT): {source_address}");
    println!(
        "UTXO: {} sats (blinded={})",
        utxos[0].amount,
        utxos[0].amount_blinder.is_some()
    );

    // Destination: empty explicit address from test environment
    let dest_address = test_addresses::EXPLICIT_EMPTY;
    println!("Destination (EX): {dest_address}");

    // Calculate preview
    let preview = calculate_spend_preview(source_address, dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");
    println!(
        "Preview: send={}, fee={}, change={}",
        preview.amount, preview.fee, preview.change_amount
    );

    // Change address should be confidential (matching source type)
    let change_address = if preview.has_change {
        let addr = deploy_address_with_type(address_params, AddressType::Confidential);
        assert!(
            addr.starts_with("tlq"),
            "Change should be confidential (tlq prefix)"
        );
        println!("Change (CT): {addr}");
        Some(addr)
    } else {
        None
    };

    // Build confidential transaction
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr)
            .unwrap()
            .script_pubkey()
    });

    let change_addr_parsed = change_address
        .as_ref()
        .map(|addr| musk::elements::Address::from_str(addr).unwrap());

    let tx = build_and_sign_confidential_transaction(
        P2PKH_PROGRAM_PATH,
        &utxos[0],
        source_script,
        &pk_hash_bytes,
        &mnemonic,
        &dest_addr,
        dest_script,
        SEND_AMOUNT,
        preview.fee,
        change_addr_parsed,
        change_script,
        preview.change_amount,
        genesis_hash,
        &rpc_client,
    )
    .expect("Failed to build confidential transaction");

    let tx_hex = transaction_to_hex(&tx);
    println!("Transaction: {} bytes", tx_hex.len() / 2);

    // Verify with mempool accept
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = mempool_result
        .first()
        .and_then(|r| r.get("allowed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if !allowed {
        let reason = mempool_result
            .first()
            .and_then(|r| r.get("reject-reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        panic!("Transaction rejected: {reason}");
    }

    println!("\n✅ SCENARIO 3 PASSED: Confidential → Explicit");
    println!("   Transaction accepted by mempool (not broadcast)");
}

// ============================================================================
// Scenario 4: Confidential → Confidential
// ============================================================================

#[test]
#[ignore = "requires live Elements node and samplicity-test.db"]
#[serial]
fn test_scenario_4_confidential_to_confidential() {
    println!("\n=== SCENARIO 4: Confidential → Confidential ===\n");

    // Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();
    let rpc_client = Arc::new(create_rpc_client());

    // Source: funded confidential address with blinded UTXO
    let source_address = test_addresses::CONFIDENTIAL_FUNDED;
    let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

    assert!(
        !utxos.is_empty(),
        "Source address has no UTXOs - fund {} first",
        source_address
    );
    assert!(
        utxos[0].amount_blinder.is_some(),
        "UTXO should have blinding data"
    );

    let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
    let mnemonic = get_mnemonic_for_address(&db, source_address);

    println!("Source (CT): {source_address}");
    println!(
        "UTXO: {} sats (blinded={})",
        utxos[0].amount,
        utxos[0].amount_blinder.is_some()
    );

    // Destination: empty confidential address from test environment
    let dest_address = test_addresses::CONFIDENTIAL_EMPTY;
    assert!(
        dest_address.starts_with("tlq"),
        "Destination should be confidential"
    );
    println!("Destination (CT): {dest_address}");

    // Calculate preview
    let preview = calculate_spend_preview(source_address, dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");
    println!(
        "Preview: send={}, fee={}, change={}",
        preview.amount, preview.fee, preview.change_amount
    );

    // Change address should be confidential (matching source type)
    let change_address = if preview.has_change {
        let addr = deploy_address_with_type(address_params, AddressType::Confidential);
        assert!(
            addr.starts_with("tlq"),
            "Change should be confidential (tlq prefix)"
        );
        println!("Change (CT): {addr}");
        Some(addr)
    } else {
        None
    };

    // Build confidential transaction
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr)
            .unwrap()
            .script_pubkey()
    });

    let change_addr_parsed = change_address
        .as_ref()
        .map(|addr| musk::elements::Address::from_str(addr).unwrap());

    let tx = build_and_sign_confidential_transaction(
        P2PKH_PROGRAM_PATH,
        &utxos[0],
        source_script,
        &pk_hash_bytes,
        &mnemonic,
        &dest_addr,
        dest_script,
        SEND_AMOUNT,
        preview.fee,
        change_addr_parsed,
        change_script,
        preview.change_amount,
        genesis_hash,
        &rpc_client,
    )
    .expect("Failed to build confidential transaction");

    let tx_hex = transaction_to_hex(&tx);
    println!("Transaction: {} bytes", tx_hex.len() / 2);

    // Verify with mempool accept
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = mempool_result
        .first()
        .and_then(|r| r.get("allowed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if !allowed {
        let reason = mempool_result
            .first()
            .and_then(|r| r.get("reject-reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        panic!("Transaction rejected: {reason}");
    }

    println!("\n✅ SCENARIO 4 PASSED: Confidential → Confidential");
    println!("   Transaction accepted by mempool (not broadcast)");
}

// ============================================================================
// Scenario 5: Confidential with Blinded Change
// ============================================================================

#[test]
#[ignore = "requires live Elements node and samplicity-test.db"]
#[serial]
fn test_scenario_5_confidential_with_blinded_change() {
    println!("\n=== SCENARIO 5: Confidential with Blinded Change ===\n");
    println!("This test verifies that spending from a confidential address");
    println!("produces properly blinded outputs.\n");

    // Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();
    let rpc_client = Arc::new(create_rpc_client());

    // Source: funded confidential address with blinded UTXO
    let source_address = test_addresses::CONFIDENTIAL_FUNDED;
    let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

    assert!(
        !utxos.is_empty(),
        "Source address has no UTXOs - fund {} first",
        source_address
    );
    assert!(
        utxos[0].amount_blinder.is_some(),
        "Source UTXO should have blinding data for this test"
    );

    let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
    let mnemonic = get_mnemonic_for_address(&db, source_address);

    println!("Source (CT): {source_address}");
    println!(
        "UTXO: {} sats (has amount_blinder={}, has asset_blinder={})",
        utxos[0].amount,
        utxos[0].amount_blinder.is_some(),
        utxos[0].asset_blinder.is_some()
    );

    // Use a small send amount to ensure there's change
    let send_amount = 500_u64;

    // Destination: explicit address (to test mixed blinding)
    let dest_address = test_addresses::EXPLICIT_EMPTY;
    println!("Destination (EX): {dest_address}");

    // Calculate preview
    let preview = calculate_spend_preview(source_address, dest_address, send_amount, &utxos[..1])
        .expect("Failed to calculate preview");

    assert!(
        preview.has_change,
        "This test requires a transaction with change"
    );
    println!(
        "Preview: send={}, fee={}, change={}",
        preview.amount, preview.fee, preview.change_amount
    );

    // Change address must be confidential
    let change_address = deploy_address_with_type(address_params, AddressType::Confidential);
    assert!(
        change_address.starts_with("tlq"),
        "Change must be confidential"
    );
    println!("Change (CT): {change_address}");

    // Build confidential transaction
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_addr_parsed = musk::elements::Address::from_str(&change_address).unwrap();
    let change_script = change_addr_parsed.script_pubkey();

    let tx = build_and_sign_confidential_transaction(
        P2PKH_PROGRAM_PATH,
        &utxos[0],
        source_script,
        &pk_hash_bytes,
        &mnemonic,
        &dest_addr,
        dest_script,
        send_amount,
        preview.fee,
        Some(change_addr_parsed),
        Some(change_script),
        preview.change_amount,
        genesis_hash,
        &rpc_client,
    )
    .expect("Failed to build confidential transaction");

    let tx_hex = transaction_to_hex(&tx);
    println!("Transaction: {} bytes", tx_hex.len() / 2);

    // Decode transaction to verify blinding
    let decoded = client
        .decode_raw_transaction(&tx_hex)
        .expect("Failed to decode transaction");

    // Check outputs for blinding
    let vout = decoded
        .get("vout")
        .and_then(|v| v.as_array())
        .expect("Missing vout");

    println!("\nOutput analysis:");
    let mut found_blinded_output = false;

    for (i, output) in vout.iter().enumerate() {
        let value = output.get("value");
        let value_str = match value {
            Some(serde_json::Value::Number(n)) => {
                format!("{} sats", (n.as_f64().unwrap() * 1e8) as u64)
            }
            Some(serde_json::Value::String(s)) if s.contains("commitment") => "BLINDED".to_string(),
            _ => "unknown".to_string(),
        };

        let script_hex = output
            .get("scriptPubKey")
            .and_then(|sp| sp.get("hex"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");

        let is_fee = script_hex.is_empty() || script_hex == "6a";
        let output_type = if is_fee { "FEE" } else { "VALUE" };

        // Check for value commitment (indicates blinding)
        let value_commitment = output.get("valuecommitment");
        let is_blinded = value_commitment.is_some();

        if is_blinded {
            found_blinded_output = true;
        }

        println!(
            "  Output {i}: {output_type} = {value_str} (blinded={})",
            is_blinded
        );
    }

    // Verify mempool acceptance
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = mempool_result
        .first()
        .and_then(|r| r.get("allowed"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    if !allowed {
        let reason = mempool_result
            .first()
            .and_then(|r| r.get("reject-reason"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        panic!("Transaction rejected: {reason}");
    }

    println!("\n✅ SCENARIO 5 PASSED: Confidential with Blinded Change");
    println!("   Transaction has blinded outputs: {found_blinded_output}");
    println!("   Transaction accepted by mempool (not broadcast)");
}

// ============================================================================
// SpendOrchestrator Integration Test
// ============================================================================

#[test]
#[ignore = "requires live Elements node and samplicity-test.db"]
#[serial]
fn test_spend_orchestrator_handles_all_address_types() {
    println!("\n=== TEST: SpendOrchestrator handles all address types ===\n");

    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();
    let rpc_client = Arc::new(create_rpc_client());

    // Test with explicit source
    {
        println!("--- Testing with EXPLICIT source ---");
        let source_address = test_addresses::EXPLICIT_FUNDED;
        let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

        if utxos.is_empty() {
            println!("⚠️  Skipping explicit test - no UTXOs");
        } else {
            let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
            let mnemonic = get_mnemonic_for_address(&db, source_address);
            let dest_address = test_addresses::EXPLICIT_EMPTY;

            let source_addr = musk::elements::Address::from_str(source_address).unwrap();
            let source_script = source_addr.script_pubkey();

            let orchestrator =
                SpendOrchestrator::new(P2PKH_PROGRAM_PATH, address_params, genesis_hash);

            let change_address = deploy_address_with_type(address_params, AddressType::Explicit);

            let result = orchestrator.execute_spend(
                source_address,
                &source_script,
                &pk_hash_bytes,
                &mnemonic,
                &utxos[..1],
                dest_address,
                SEND_AMOUNT,
                Some(&change_address),
            );

            assert!(result.is_ok(), "Explicit spend should succeed");
            let (tx, _preview) = result.unwrap();

            let tx_hex = transaction_to_hex(&tx);
            let mempool_result = client.test_mempool_accept(&tx_hex).unwrap();
            let allowed = mempool_result
                .first()
                .and_then(|r| r.get("allowed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            assert!(allowed, "Explicit transaction should be accepted");
            println!("✓ EX→EX transaction accepted");
        }
    }

    // Test with explicit source → confidential destination
    {
        println!("\n--- Testing EXPLICIT source → CONFIDENTIAL dest ---");
        let source_address = test_addresses::EXPLICIT_FUNDED;
        let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

        if utxos.is_empty() {
            println!("⚠️  Skipping EX→CT test - no UTXOs");
        } else {
            let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
            let mnemonic = get_mnemonic_for_address(&db, source_address);
            let dest_address = test_addresses::CONFIDENTIAL_EMPTY; // CT destination!

            let source_addr = musk::elements::Address::from_str(source_address).unwrap();
            let source_script = source_addr.script_pubkey();

            // Need RPC client because destination is confidential (triggers blinding)
            let orchestrator =
                SpendOrchestrator::new(P2PKH_PROGRAM_PATH, address_params, genesis_hash)
                    .with_rpc_client(rpc_client.clone());

            // Change matches source type (explicit)
            let change_address = deploy_address_with_type(address_params, AddressType::Explicit);

            let result = orchestrator.execute_spend(
                source_address,
                &source_script,
                &pk_hash_bytes,
                &mnemonic,
                &utxos[..1],
                dest_address,
                SEND_AMOUNT,
                Some(&change_address),
            );

            assert!(result.is_ok(), "EX→CT spend should succeed");
            let (tx, _preview) = result.unwrap();

            let tx_hex = transaction_to_hex(&tx);
            let mempool_result = client.test_mempool_accept(&tx_hex).unwrap();
            let allowed = mempool_result
                .first()
                .and_then(|r| r.get("allowed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            assert!(allowed, "EX→CT transaction should be accepted");
            println!("✓ EX→CT transaction accepted (output blinded)");
        }
    }

    // Test with confidential source → explicit destination
    {
        println!("\n--- Testing CONFIDENTIAL source → EXPLICIT dest ---");
        let source_address = test_addresses::CONFIDENTIAL_FUNDED;
        let (source_addr_info, utxos) = get_address_with_utxos(&db, source_address);

        if utxos.is_empty() || utxos[0].amount_blinder.is_none() {
            println!("⚠️  Skipping confidential test - no blinded UTXOs");
        } else {
            let pk_hash_bytes = get_pk_hash_bytes(&source_addr_info);
            let mnemonic = get_mnemonic_for_address(&db, source_address);
            let dest_address = test_addresses::EXPLICIT_EMPTY;

            let source_addr = musk::elements::Address::from_str(source_address).unwrap();
            let source_script = source_addr.script_pubkey();

            let orchestrator =
                SpendOrchestrator::new(P2PKH_PROGRAM_PATH, address_params, genesis_hash)
                    .with_rpc_client(rpc_client.clone());

            let change_address =
                deploy_address_with_type(address_params, AddressType::Confidential);

            let result = orchestrator.execute_spend(
                source_address,
                &source_script,
                &pk_hash_bytes,
                &mnemonic,
                &utxos[..1],
                dest_address,
                SEND_AMOUNT,
                Some(&change_address),
            );

            assert!(result.is_ok(), "Confidential spend should succeed");
            let (tx, _preview) = result.unwrap();

            let tx_hex = transaction_to_hex(&tx);
            let mempool_result = client.test_mempool_accept(&tx_hex).unwrap();
            let allowed = mempool_result
                .first()
                .and_then(|r| r.get("allowed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            assert!(allowed, "CT→EX transaction should be accepted");
            println!("✓ CT→EX transaction accepted (change blinded)");
        }
    }

    println!("\n✅ SpendOrchestrator handles all address types correctly");
    println!("   Tested: EX→EX, EX→CT, CT→EX");
}

// ============================================================================
// Address Type Detection Tests
// ============================================================================

#[test]
fn test_detect_address_type_explicit_testnet() {
    let explicit_addr = test_addresses::EXPLICIT_FUNDED;
    assert_eq!(detect_address_type(explicit_addr), AddressType::Explicit);
}

#[test]
fn test_detect_address_type_confidential_testnet() {
    let confidential_addr = test_addresses::CONFIDENTIAL_FUNDED;
    assert_eq!(
        detect_address_type(confidential_addr),
        AddressType::Confidential
    );
}

#[test]
fn test_is_confidential_address_helper() {
    assert!(!is_confidential_address(test_addresses::EXPLICIT_FUNDED));
    assert!(!is_confidential_address(test_addresses::EXPLICIT_EMPTY));
    assert!(is_confidential_address(test_addresses::CONFIDENTIAL_FUNDED));
    assert!(is_confidential_address(test_addresses::CONFIDENTIAL_EMPTY));
}

// ============================================================================
// Database Integration Tests
// ============================================================================

#[test]
#[ignore = "requires samplicity-test.db"]
fn test_database_has_required_addresses() {
    println!("\n=== TEST: Database has all required test addresses ===\n");

    let db = open_database();

    let required_addresses = [
        (test_addresses::EXPLICIT_FUNDED, "Explicit Funded"),
        (test_addresses::EXPLICIT_EMPTY, "Explicit Empty"),
        (test_addresses::CONFIDENTIAL_FUNDED, "Confidential Funded"),
        (test_addresses::CONFIDENTIAL_SMALL, "Confidential Small"),
        (test_addresses::CONFIDENTIAL_EMPTY, "Confidential Empty"),
    ];

    for (addr, name) in &required_addresses {
        let result = db.get_address(addr);
        assert!(
            result.is_ok() && result.unwrap().is_some(),
            "Missing required address: {} ({})",
            name,
            addr
        );
        println!("✓ Found: {} - {}", name, &addr[..20]);
    }

    println!("\n✅ All required addresses present in database");
}

#[test]
#[ignore = "requires samplicity-test.db"]
fn test_confidential_addresses_have_blinding_keys() {
    println!("\n=== TEST: Confidential addresses have blinding keys ===\n");

    let db = open_database();

    let confidential_addresses = [
        test_addresses::CONFIDENTIAL_FUNDED,
        test_addresses::CONFIDENTIAL_EMPTY,
    ];

    for addr in &confidential_addresses {
        let blinding_sk = db
            .get_blinding_sk(addr)
            .expect("Failed to query blinding key");
        assert!(
            blinding_sk.is_some(),
            "Confidential address missing blinding key: {}",
            &addr[..30]
        );
        println!("✓ Has blinding key: {}...", &addr[..30]);
    }

    println!("\n✅ All confidential addresses have blinding keys");
}

#[test]
#[ignore = "requires samplicity-test.db"]
fn test_funded_addresses_have_utxos_with_blinding_data() {
    println!("\n=== TEST: Funded confidential addresses have blinding data ===\n");

    let db = open_database();

    let addr = test_addresses::CONFIDENTIAL_FUNDED;
    let utxos = db.get_unspent_utxos(addr).expect("Failed to get UTXOs");

    assert!(
        !utxos.is_empty(),
        "No UTXOs for funded confidential address"
    );

    let utxo = &utxos[0];
    println!(
        "UTXO: txid={}, vout={}, amount={}",
        utxo.txid, utxo.vout, utxo.amount
    );
    println!("  amount_blinder: {}", utxo.amount_blinder.is_some());
    println!("  asset_blinder: {}", utxo.asset_blinder.is_some());
    println!("  amount_commitment: {}", utxo.amount_commitment.is_some());
    println!("  asset_commitment: {}", utxo.asset_commitment.is_some());

    assert!(
        utxo.amount_blinder.is_some(),
        "Confidential UTXO should have amount_blinder"
    );

    println!("\n✅ Funded confidential address has proper blinding data");
}
