//! Transaction validation integration tests
//!
//! These tests verify that transactions built by musk are properly formed
//! by using the Elements node's `decoderawtransaction` and `testmempoolaccept`
//! RPC methods.
//!
//! These tests use existing UTXOs from the samplicity database and do NOT
//! broadcast transactions, so they are safe to run repeatedly.
//!
//! Run with: cargo test --test transaction_validation -- --ignored

use musk::RpcClient;
use samplicity::deploy::{deploy_new_address, AddressType};
use samplicity::spend::{
    build_and_sign_transaction, calculate_spend_preview, transaction_to_hex, SpendOrchestrator,
};
use samplicity::{detect_address_type, Database, StoredAddress};
use serial_test::serial;
use std::str::FromStr;

/// Path to the p2pkh program
const P2PKH_PROGRAM_PATH: &str = "musk/p2pkh.simf";

/// Amount to send in test transactions (must be less than available UTXO)
const SEND_AMOUNT: u64 = 500; // 500 sats - small amount for testing

/// Helper to create RPC client from config
fn create_rpc_client() -> RpcClient {
    RpcClient::from_config_file("musk.conf").expect("Failed to create RPC client from musk.conf")
}

/// Helper to get genesis hash from RPC client
fn get_genesis_hash(client: &mut RpcClient) -> musk::elements::BlockHash {
    client.genesis_hash().expect("Failed to get genesis hash")
}

/// Helper to open the samplicity database
fn open_database() -> Database {
    Database::open("samplicity.db").expect("Failed to open samplicity.db")
}

/// Find an address with UTXOs that we can use for testing
fn find_funded_address(db: &Database) -> Option<(StoredAddress, Vec<samplicity::db::StoredUtxo>)> {
    let addresses = db.get_all_addresses().ok()?;
    
    for addr in addresses {
        let utxos = db.get_unspent_utxos(&addr.address).ok()?;
        if !utxos.is_empty() && utxos[0].amount > SEND_AMOUNT + 1000 {
            // Found an address with sufficient funds
            return Some((addr, utxos));
        }
    }
    None
}

/// Get the mnemonic for an address from the database
fn get_mnemonic_for_address(db: &Database, address: &str) -> Option<String> {
    db.get_pubkey_for_address(address)
        .ok()
        .flatten()
        .map(|p| p.mnemonic)
}

/// Deploy a test destination address
fn deploy_destination_address(
    address_params: &'static musk::elements::AddressParams,
) -> String {
    let deployed = deploy_new_address(P2PKH_PROGRAM_PATH, address_params, AddressType::Explicit)
        .expect("Failed to deploy destination address");
    deployed.address
}

#[test]
#[ignore = "requires live Elements node and samplicity.db"]
#[serial]
fn test_decode_raw_transaction_structure() {
    println!("\n=== TEST: decoderawtransaction validates transaction structure ===\n");

    // 1. Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();

    println!("Connected to node, genesis_hash: {genesis_hash}");

    // 2. Find a funded address from the database
    let Some((source_addr_info, utxos)) = find_funded_address(&db) else {
        println!("SKIPPED: No funded addresses found in database");
        return;
    };
    
    let source_address = &source_addr_info.address;
    let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr_info.pk_hash)
        .expect("Invalid pk_hash hex")
        .try_into()
        .expect("Invalid pk_hash length");
    
    println!("Using source address: {}", source_address);
    println!("UTXO: txid={}, vout={}, amount={} sats", 
             utxos[0].txid, utxos[0].vout, utxos[0].amount);

    // 3. Get mnemonic for signing
    let Some(mnemonic) = get_mnemonic_for_address(&db, source_address) else {
        println!("SKIPPED: No mnemonic found for address");
        return;
    };

    // 4. Deploy a destination address
    let dest_address = deploy_destination_address(address_params);
    println!("Destination address: {dest_address}");

    // 5. Calculate spend preview
    let preview = calculate_spend_preview(source_address, &dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");
    println!("Preview: amount={}, fee={}, change={}", 
             preview.amount, preview.fee, preview.change_amount);

    // 6. Deploy change address if needed
    let change_address = if preview.has_change {
        Some(deploy_destination_address(address_params))
    } else {
        None
    };

    // 7. Build transaction
    let source_addr_parsed = musk::elements::Address::from_str(source_address)
        .expect("Failed to parse source address");
    let source_script = source_addr_parsed.script_pubkey();
    
    let dest_addr = musk::elements::Address::from_str(&dest_address)
        .expect("Failed to parse dest address");
    let dest_script = dest_addr.script_pubkey();
    
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr)
            .expect("Failed to parse change address")
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
    println!("Built transaction: {} bytes", tx_hex.len() / 2);

    // 8. Decode the transaction using the node
    let decoded = client
        .decode_raw_transaction(&tx_hex)
        .expect("Failed to decode transaction");

    println!("\n=== DECODED TRANSACTION ===");
    println!("{}", serde_json::to_string_pretty(&decoded).unwrap());

    // 9. Verify transaction structure
    let vin = decoded.get("vin").expect("Missing vin");
    let vout = decoded.get("vout").expect("Missing vout");

    assert!(vin.is_array(), "vin should be an array");
    assert!(vout.is_array(), "vout should be an array");

    let vin_arr = vin.as_array().unwrap();
    let vout_arr = vout.as_array().unwrap();

    // Should have exactly 1 input
    assert_eq!(vin_arr.len(), 1, "Should have exactly 1 input");

    // Verify input references our UTXO
    let input = &vin_arr[0];
    let input_txid = input.get("txid").and_then(|v| v.as_str()).unwrap();
    let input_vout = input.get("vout").and_then(|v| v.as_u64()).unwrap() as u32;
    assert_eq!(input_txid, utxos[0].txid, "Input should reference our UTXO");
    assert_eq!(input_vout, utxos[0].vout, "Input vout should match");

    // Should have outputs: destination + change (if any) + fee
    let expected_outputs = if preview.has_change { 3 } else { 2 };
    assert_eq!(
        vout_arr.len(),
        expected_outputs,
        "Should have {} outputs",
        expected_outputs
    );

    println!("\n=== TRANSACTION STRUCTURE VALIDATED ===");
    println!("✓ Transaction has {} input(s)", vin_arr.len());
    println!("✓ Transaction has {} output(s)", vout_arr.len());
    println!("✓ Input references correct UTXO");
}

#[test]
#[ignore = "requires live Elements node and samplicity.db"]
#[serial]
fn test_mempool_accept_validates_spend() {
    println!("\n=== TEST: testmempoolaccept validates transaction ===\n");

    // 1. Setup
    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();

    println!("Connected to node, genesis_hash: {genesis_hash}");

    // 2. Find a funded address
    let Some((source_addr_info, utxos)) = find_funded_address(&db) else {
        println!("SKIPPED: No funded addresses found in database");
        return;
    };
    
    let source_address = &source_addr_info.address;
    let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr_info.pk_hash)
        .expect("Invalid pk_hash hex")
        .try_into()
        .expect("Invalid pk_hash length");
    
    println!("Using source address: {}", source_address);
    println!("UTXO: txid={}, vout={}, amount={} sats", 
             utxos[0].txid, utxos[0].vout, utxos[0].amount);

    // 3. Get mnemonic
    let Some(mnemonic) = get_mnemonic_for_address(&db, source_address) else {
        println!("SKIPPED: No mnemonic found for address");
        return;
    };

    // 4. Deploy destination
    let dest_address = deploy_destination_address(address_params);
    println!("Destination address: {dest_address}");

    // 5. Use SpendOrchestrator
    let orchestrator = SpendOrchestrator::new(P2PKH_PROGRAM_PATH, address_params, genesis_hash);

    let preview = calculate_spend_preview(source_address, &dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");

    let change_address = if preview.has_change {
        Some(deploy_destination_address(address_params))
    } else {
        None
    };

    let source_addr_parsed = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr_parsed.script_pubkey();

    let (tx, final_preview) = orchestrator
        .execute_spend(
            source_address,
            &source_script,
            &pk_hash_bytes,
            &mnemonic,
            &utxos[..1],
            &dest_address,
            SEND_AMOUNT,
            change_address.as_deref(),
        )
        .expect("Failed to execute spend");

    let tx_hex = transaction_to_hex(&tx);
    println!("Built transaction: {} bytes", tx_hex.len() / 2);
    println!("Preview: amount={}, fee={}, change={}", 
             final_preview.amount, final_preview.fee, final_preview.change_amount);

    // 6. Test mempool acceptance (DO NOT BROADCAST)
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    println!("\n=== MEMPOOL ACCEPTANCE RESULT ===");
    println!("{}", serde_json::to_string_pretty(&mempool_result).unwrap());

    // 7. Verify the result
    assert!(!mempool_result.is_empty(), "testmempoolaccept should return a result");
    
    let result = &mempool_result[0];
    let allowed = result.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false);

    if allowed {
        println!("\n✓ Transaction ACCEPTED by mempool!");
        println!("(Transaction NOT broadcast - this is a validation-only test)");
    } else {
        let reject_reason = result
            .get("reject-reason")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        panic!(
            "Transaction REJECTED by mempool: {}\nThis indicates a bug in transaction construction.",
            reject_reason
        );
    }
}

#[test]
#[ignore = "requires live Elements node and samplicity.db"]
#[serial]
fn test_transaction_roundtrip_decode() {
    println!("\n=== TEST: Transaction encode/decode roundtrip ===\n");

    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();

    // Find funded address
    let Some((source_addr_info, utxos)) = find_funded_address(&db) else {
        println!("SKIPPED: No funded addresses found in database");
        return;
    };
    
    let source_address = &source_addr_info.address;
    let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr_info.pk_hash)
        .expect("Invalid pk_hash hex")
        .try_into()
        .expect("Invalid pk_hash length");

    let Some(mnemonic) = get_mnemonic_for_address(&db, source_address) else {
        println!("SKIPPED: No mnemonic found for address");
        return;
    };

    // Deploy destination
    let dest_address = deploy_destination_address(address_params);

    // Calculate preview
    let preview = calculate_spend_preview(source_address, &dest_address, SEND_AMOUNT, &utxos[..1]).unwrap();
    let change_address = if preview.has_change {
        Some(deploy_destination_address(address_params))
    } else {
        None
    };

    // Build transaction
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(&dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr).unwrap().script_pubkey()
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
    ).unwrap();

    // Encode to hex
    let tx_hex_original = transaction_to_hex(&tx);

    // Decode via node
    let decoded = client.decode_raw_transaction(&tx_hex_original).unwrap();

    // Verify txid matches
    let decoded_txid = decoded.get("txid").and_then(|v| v.as_str()).unwrap();
    let expected_txid = tx.txid().to_string();
    
    println!("Original tx hex length: {} bytes", tx_hex_original.len() / 2);
    println!("Expected txid: {expected_txid}");
    println!("Decoded txid:  {decoded_txid}");

    assert_eq!(decoded_txid, expected_txid, "Decoded txid should match original");

    // Verify version and locktime
    let version = decoded.get("version").and_then(|v| v.as_u64()).unwrap();
    let locktime = decoded.get("locktime").and_then(|v| v.as_u64()).unwrap();
    
    assert_eq!(version, 2, "Transaction version should be 2");
    assert_eq!(locktime, 0, "Locktime should be 0");

    println!("\n✓ Transaction roundtrip validation successful");
    println!("✓ TXID matches: {expected_txid}");
    println!("✓ Version: {version}");
    println!("✓ Locktime: {locktime}");
}

#[test]
#[ignore = "requires live Elements node and samplicity.db"]
#[serial]
fn test_verify_output_values() {
    println!("\n=== TEST: Verify output values match expected amounts ===\n");

    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();

    // Find funded address
    let Some((source_addr_info, utxos)) = find_funded_address(&db) else {
        println!("SKIPPED: No funded addresses found in database");
        return;
    };
    
    let source_address = &source_addr_info.address;
    let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr_info.pk_hash)
        .expect("Invalid pk_hash hex")
        .try_into()
        .expect("Invalid pk_hash length");
    let input_amount = utxos[0].amount;

    let Some(mnemonic) = get_mnemonic_for_address(&db, source_address) else {
        println!("SKIPPED: No mnemonic found for address");
        return;
    };

    // Destination
    let dest_address = deploy_destination_address(address_params);

    // Preview
    let preview = calculate_spend_preview(source_address, &dest_address, SEND_AMOUNT, &utxos[..1]).unwrap();
    let change_address = if preview.has_change {
        Some(deploy_destination_address(address_params))
    } else {
        None
    };

    // Build
    let source_addr = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(&dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr).unwrap().script_pubkey()
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
    ).unwrap();

    let tx_hex = transaction_to_hex(&tx);
    let decoded = client.decode_raw_transaction(&tx_hex).unwrap();

    // Extract output values
    let vout = decoded.get("vout").and_then(|v| v.as_array()).unwrap();
    
    println!("Input amount: {} sats", input_amount);
    println!("Expected send: {} sats", SEND_AMOUNT);
    println!("Expected fee: {} sats", preview.fee);
    println!("Expected change: {} sats", preview.change_amount);
    println!("Expected total outputs: {} sats", SEND_AMOUNT + preview.fee + preview.change_amount);
    println!("\nDecoded outputs:");

    let mut total_output_value: u64 = 0;
    let mut found_fee = false;

    for (i, output) in vout.iter().enumerate() {
        // Get value - may be explicit or blinded
        let value = if let Some(v) = output.get("value").and_then(|v| v.as_f64()) {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let sats = (v * 100_000_000.0).round() as u64;
            sats
        } else {
            0 // Confidential output
        };

        // Check if this is a fee output (empty scriptPubKey)
        let script_hex = output
            .get("scriptPubKey")
            .and_then(|sp| sp.get("hex"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let is_fee = script_hex.is_empty() || script_hex == "6a";

        if is_fee {
            println!("  Output {i}: FEE = {} sats", value);
            found_fee = true;
        } else {
            println!("  Output {i}: {} sats (script: {}...)", value, &script_hex[..script_hex.len().min(20)]);
        }
        
        total_output_value += value;
    }

    println!("\nTotal output value (including fee output): {} sats", total_output_value);

    // Verify conservation of value - fee is already included in outputs
    assert_eq!(
        input_amount,
        total_output_value,
        "Input amount should equal sum of all outputs (including fee)"
    );

    assert!(found_fee, "Should find fee output");

    println!("\n✓ Output values validated successfully");
    println!("✓ Conservation of value verified: {} = {} + {} + {}", 
             input_amount, SEND_AMOUNT, preview.change_amount, preview.fee);
}

// ============================================================================
// Address Type Detection Tests
// ============================================================================

#[test]
fn test_detect_address_type_explicit_testnet() {
    // Explicit testnet addresses start with "tex"
    let explicit_addr = "tex1pxv4f8xhds9gzwenwtrh62khlvyxfjjpeg4mujzf38pqha3u4sslsvvk9v6";
    assert_eq!(detect_address_type(explicit_addr), AddressType::Explicit);
}

#[test]
fn test_detect_address_type_confidential_testnet() {
    // Confidential testnet addresses start with "tlq"
    let confidential_addr = "tlq1pqwq88n6llaqfl6xves5kg7dsefmq57z4yl0w5kpmz0sv2y2jz0terr2pwj7g0wel43gmsjyxmrwknr5c708mkumvd7kenxw5gkme4y7xkpyfv0rnu749";
    assert_eq!(detect_address_type(confidential_addr), AddressType::Confidential);
}

#[test]
fn test_detect_address_type_explicit_mainnet() {
    // Explicit mainnet addresses start with "ex"
    let explicit_addr = "ex1q0000000000000000000000000000000000000000";
    assert_eq!(detect_address_type(explicit_addr), AddressType::Explicit);
}

#[test]
fn test_detect_address_type_confidential_mainnet() {
    // Confidential mainnet addresses start with "lq"
    let confidential_addr = "lq1qq0000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(detect_address_type(confidential_addr), AddressType::Confidential);
}

// ============================================================================
// Change Address Type Tests
// ============================================================================

/// Helper to deploy an address with a specific type
fn deploy_address_with_type(
    address_params: &'static musk::elements::AddressParams,
    address_type: AddressType,
) -> String {
    let deployed = deploy_new_address(P2PKH_PROGRAM_PATH, address_params, address_type)
        .expect("Failed to deploy address");
    deployed.address
}

#[test]
#[serial]
fn test_explicit_source_produces_explicit_change() {
    println!("\n=== TEST: Explicit source address produces explicit change address ===\n");

    let client = create_rpc_client();
    let address_params = client.address_params();

    // Deploy an explicit source address
    let source_address = deploy_address_with_type(address_params, AddressType::Explicit);
    println!("Source address (explicit): {source_address}");

    // Verify it's detected as explicit
    let detected_type = detect_address_type(&source_address);
    assert_eq!(detected_type, AddressType::Explicit, "Source should be detected as explicit");

    // Deploy a "change" address using the detected type
    let change_address = deploy_address_with_type(address_params, detected_type);
    println!("Change address: {change_address}");

    // Verify the change address is also explicit
    let change_type = detect_address_type(&change_address);
    assert_eq!(change_type, AddressType::Explicit, "Change address should be explicit");

    // Explicit addresses should start with "tex" on testnet
    assert!(
        change_address.starts_with("tex"),
        "Explicit change address should start with 'tex', got: {}",
        &change_address[..change_address.len().min(10)]
    );

    println!("✓ Explicit source → explicit change address");
}

#[test]
#[serial]
fn test_confidential_source_produces_confidential_change() {
    println!("\n=== TEST: Confidential source address produces confidential change address ===\n");

    let client = create_rpc_client();
    let address_params = client.address_params();

    // Deploy a confidential source address
    let source_address = deploy_address_with_type(address_params, AddressType::Confidential);
    println!("Source address (confidential): {source_address}");

    // Verify it's detected as confidential
    let detected_type = detect_address_type(&source_address);
    assert_eq!(detected_type, AddressType::Confidential, "Source should be detected as confidential");

    // Deploy a "change" address using the detected type
    let change_address = deploy_address_with_type(address_params, detected_type);
    println!("Change address: {change_address}");

    // Verify the change address is also confidential
    let change_type = detect_address_type(&change_address);
    assert_eq!(change_type, AddressType::Confidential, "Change address should be confidential");

    // Confidential addresses should start with "tlq" on testnet
    assert!(
        change_address.starts_with("tlq"),
        "Confidential change address should start with 'tlq', got: {}",
        &change_address[..change_address.len().min(10)]
    );

    println!("✓ Confidential source → confidential change address");
}

#[test]
#[ignore = "requires live Elements node and samplicity.db with a confidential funded address"]
#[serial]
fn test_spend_from_confidential_address_uses_confidential_change() {
    println!("\n=== TEST: Spending from confidential address uses confidential change ===\n");

    let mut client = create_rpc_client();
    let address_params = client.address_params();
    let genesis_hash = get_genesis_hash(&mut client);
    let db = open_database();

    // Find a funded confidential address
    let addresses = db.get_all_addresses().expect("Failed to get addresses");
    let confidential_funded = addresses.iter().find(|addr| {
        detect_address_type(&addr.address) == AddressType::Confidential
            && db.get_unspent_utxos(&addr.address).map(|u| !u.is_empty()).unwrap_or(false)
    });

    let Some(source_addr_info) = confidential_funded else {
        println!("SKIPPED: No funded confidential addresses found in database");
        return;
    };

    let source_address = &source_addr_info.address;
    let mut utxos = db.get_unspent_utxos(source_address).expect("Failed to get UTXOs");
    utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    if utxos[0].amount < SEND_AMOUNT + 1000 {
        println!("SKIPPED: Insufficient funds in confidential address");
        return;
    }

    let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr_info.pk_hash)
        .expect("Invalid pk_hash hex")
        .try_into()
        .expect("Invalid pk_hash length");

    let Some(mnemonic) = get_mnemonic_for_address(&db, source_address) else {
        println!("SKIPPED: No mnemonic found for address");
        return;
    };

    println!("Source address (confidential): {source_address}");
    println!("UTXO: {} sats", utxos[0].amount);

    // Deploy destination (explicit for simplicity)
    let dest_address = deploy_destination_address(address_params);
    println!("Destination address: {dest_address}");

    // Calculate preview
    let preview = calculate_spend_preview(source_address, &dest_address, SEND_AMOUNT, &utxos[..1])
        .expect("Failed to calculate preview");

    // Deploy change address with SAME TYPE as source
    let source_type = detect_address_type(source_address);
    assert_eq!(source_type, AddressType::Confidential);

    let change_address = if preview.has_change {
        let addr = deploy_address_with_type(address_params, source_type);
        println!("Change address (should be confidential): {addr}");
        
        // Verify change address is confidential
        let change_type = detect_address_type(&addr);
        assert_eq!(
            change_type,
            AddressType::Confidential,
            "Change address should be confidential when source is confidential"
        );
        assert!(
            addr.starts_with("tlq"),
            "Confidential change address should start with 'tlq'"
        );
        Some(addr)
    } else {
        None
    };

    // Build the transaction
    let source_addr_parsed = musk::elements::Address::from_str(source_address).unwrap();
    let source_script = source_addr_parsed.script_pubkey();
    let dest_addr = musk::elements::Address::from_str(&dest_address).unwrap();
    let dest_script = dest_addr.script_pubkey();
    let change_script = change_address.as_ref().map(|addr| {
        musk::elements::Address::from_str(addr).unwrap().script_pubkey()
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
    println!("Built transaction: {} bytes", tx_hex.len() / 2);

    // Verify mempool acceptance
    let mempool_result = client
        .test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = mempool_result
        .first()
        .and_then(|r| r.get("allowed"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    assert!(allowed, "Transaction should be accepted by mempool");

    println!("\n✓ Confidential source → confidential change address");
    println!("✓ Transaction accepted by mempool");
}
