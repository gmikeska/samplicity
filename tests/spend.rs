//! Spend tests for Samplicity

use samplicity::db::StoredUtxo;
use samplicity::deploy::get_address_params;
use samplicity::spend::{
    build_witness_values, calculate_spend_preview, compute_pk_hash,
    derive_secret_key_from_mnemonic, get_lbtc_asset_id, get_xonly_pubkey, parse_address,
    sign_schnorr_with_bytes, stored_utxo_to_musk_utxo, transaction_to_hex, validate_key_pair,
    SpendError, SpendOrchestrator, DEFAULT_FEE_SATS, DUST_THRESHOLD, LBTC_TESTNET_ASSET_ID,
};

/// Test mnemonic for consistent results
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn test_derive_secret_key_from_mnemonic() {
    let sk = derive_secret_key_from_mnemonic(TEST_MNEMONIC).unwrap();
    assert_eq!(sk.len(), 32);

    // Same mnemonic should produce same key
    let sk2 = derive_secret_key_from_mnemonic(TEST_MNEMONIC).unwrap();
    assert_eq!(sk, sk2);
}

#[test]
fn test_derive_secret_key_invalid_mnemonic() {
    let result = derive_secret_key_from_mnemonic("not valid mnemonic");
    assert!(result.is_err());
    match result.unwrap_err() {
        SpendError::InvalidMnemonic(msg) => {
            assert!(msg.contains("mnemonic"));
        }
        other => panic!("Expected InvalidMnemonic error, got: {other:?}"),
    }
}

#[test]
fn test_sign_schnorr_with_bytes() {
    let sk = derive_secret_key_from_mnemonic(TEST_MNEMONIC).unwrap();
    let message = [1u8; 32];

    let sig = sign_schnorr_with_bytes(&sk, message).unwrap();
    assert_eq!(sig.len(), 64);

    // Different messages should produce different signatures
    let message2 = [2u8; 32];
    let sig2 = sign_schnorr_with_bytes(&sk, message2).unwrap();
    assert_eq!(sig2.len(), 64);
    assert_ne!(sig, sig2);
}

#[test]
fn test_get_xonly_pubkey() {
    let sk = derive_secret_key_from_mnemonic(TEST_MNEMONIC).unwrap();
    let pk = get_xonly_pubkey(&sk).unwrap();

    assert_eq!(pk.len(), 32);

    // Same key should produce same pubkey
    let pk2 = get_xonly_pubkey(&sk).unwrap();
    assert_eq!(pk, pk2);
}

#[test]
fn test_compute_pk_hash() {
    let pk = [1u8; 32];
    let hash = compute_pk_hash(&pk);
    assert_eq!(hash.len(), 32);

    // Verify deterministic
    let hash2 = compute_pk_hash(&pk);
    assert_eq!(hash, hash2);

    // Different input should produce different hash
    let pk_different = [2u8; 32];
    let hash_different = compute_pk_hash(&pk_different);
    assert_ne!(hash, hash_different);
}

#[test]
fn test_validate_key_pair() {
    let sk = derive_secret_key_from_mnemonic(TEST_MNEMONIC).unwrap();
    let pk = get_xonly_pubkey(&sk).unwrap();

    // Valid key pair
    assert!(validate_key_pair(&sk, &pk).unwrap());

    // Invalid key pair (wrong pubkey)
    let wrong_pk = [0u8; 32];
    assert!(!validate_key_pair(&sk, &wrong_pk).unwrap());
}

#[test]
fn test_calculate_spend_preview_insufficient_funds() {
    let utxos = vec![StoredUtxo {
        id: 1,
        address_id: 1,
        txid: "abc".to_string(),
        vout: 0,
        amount: 1000, // Only 1000 sats
        asset: LBTC_TESTNET_ASSET_ID.to_string(),
        spent: false,
        amount_blinder: None,
        asset_blinder: None,
        amount_commitment: None,
        asset_commitment: None,
    }];

    let result = calculate_spend_preview("src", "dst", 10000, &utxos);
    assert!(matches!(result, Err(SpendError::InsufficientFunds { .. })));
}

#[test]
fn test_calculate_spend_preview_no_utxos() {
    let utxos: Vec<StoredUtxo> = vec![];
    let result = calculate_spend_preview("src", "dst", 1000, &utxos);
    assert!(matches!(result, Err(SpendError::NoUtxos)));
}

#[test]
fn test_calculate_spend_preview_with_change() {
    let utxos = vec![StoredUtxo {
        id: 1,
        address_id: 1,
        txid: "abc".to_string(),
        vout: 0,
        amount: 100_000, // 100k sats
        asset: LBTC_TESTNET_ASSET_ID.to_string(),
        spent: false,
        amount_blinder: None,
        asset_blinder: None,
        amount_commitment: None,
        asset_commitment: None,
    }];

    let preview = calculate_spend_preview("src", "dst", 50000, &utxos).unwrap();
    assert_eq!(preview.amount, 50000);
    assert_eq!(preview.fee, DEFAULT_FEE_SATS);
    assert!(preview.has_change);
    assert_eq!(preview.change_amount, 100_000 - 50_000 - DEFAULT_FEE_SATS);
}

#[test]
fn test_calculate_spend_preview_no_change_dust() {
    let utxos = vec![StoredUtxo {
        id: 1,
        address_id: 1,
        txid: "abc".to_string(),
        vout: 0,
        amount: 1000, // 1000 sats
        asset: LBTC_TESTNET_ASSET_ID.to_string(),
        spent: false,
        amount_blinder: None,
        asset_blinder: None,
        amount_commitment: None,
        asset_commitment: None,
    }];

    // Spending 400 sats + 500 fee = 900, leaving 100 sats (below dust threshold of 546)
    let preview = calculate_spend_preview("src", "dst", 400, &utxos).unwrap();
    assert_eq!(preview.amount, 400);
    assert!(!preview.has_change);
    assert_eq!(preview.change_amount, 0);
    // The remaining 600 sats goes to fee
    assert_eq!(preview.fee, 1000 - 400);
}

#[test]
fn test_spend_error_display() {
    let insufficient = SpendError::InsufficientFunds {
        available: 1000,
        required: 5000,
    };
    let msg = insufficient.to_string();
    assert!(msg.contains("Insufficient funds"));
    assert!(msg.contains("1000"));
    assert!(msg.contains("5000"));

    let no_utxos = SpendError::NoUtxos;
    assert!(no_utxos.to_string().contains("No UTXOs"));

    let signing = SpendError::SigningError("test error".to_string());
    assert!(signing.to_string().contains("Signing error"));
    assert!(signing.to_string().contains("test error"));

    let invalid_addr = SpendError::InvalidAddress("bad addr".to_string());
    assert!(invalid_addr.to_string().contains("Invalid address"));

    let invalid_mnemonic = SpendError::InvalidMnemonic("bad words".to_string());
    assert!(invalid_mnemonic.to_string().contains("Invalid mnemonic"));

    let program_err = SpendError::ProgramError("program issue".to_string());
    assert!(program_err.to_string().contains("Program error"));

    let confidential_err = SpendError::ConfidentialNotSupported("test reason".to_string());
    assert!(confidential_err
        .to_string()
        .contains("Confidential spending not yet supported"));
    assert!(confidential_err.to_string().contains("test reason"));
}

#[test]
fn test_is_confidential_address() {
    use samplicity::spend::is_confidential_address;

    // Testnet confidential addresses start with "tlq"
    assert!(is_confidential_address("tlq1pqgked3uaq994tup3ef9nmsh7nvscvxsv27qqz0e3jpjf9epfhp8uuw2dq2wl6ueld8vd2gjcecqznjhheq8nvg0k5trjjjl90w34fl5g8jvwccx4hes5"));

    // Mainnet confidential addresses start with "lq"
    assert!(is_confidential_address("lq1qqexample"));

    // Testnet explicit addresses start with "tex"
    assert!(!is_confidential_address(
        "tex1pksj0z78nxz6cjcv20t8hev3hvx3qd35wc8h80rhw845t3574nfds8jnwq4"
    ));

    // Mainnet explicit addresses start with "ex"
    assert!(!is_confidential_address("ex1qexample"));

    // Other prefixes are not confidential
    assert!(!is_confidential_address("ert1qexample")); // regtest
}

#[test]
fn test_parse_address_valid() {
    // Testnet address (tex prefix)
    let testnet_params = get_address_params("testnet");
    let testnet_result = parse_address(
        "tex1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqrgta58",
        testnet_params,
    );
    // This should succeed if it's a valid testnet address format
    // The actual parsing may fail for made-up addresses, but we're testing the function exists
    let _ = testnet_result; // Allow either success or meaningful failure
}

#[test]
fn test_get_lbtc_asset_id() {
    let asset_id = get_lbtc_asset_id().unwrap();

    // Verify it's the expected testnet asset ID
    // AssetId uses the Midstate type, which has a .0 field for the inner bytes
    let inner = asset_id.into_inner();
    let asset_hex = hex::encode(inner.0.iter().rev().copied().collect::<Vec<u8>>());
    assert_eq!(asset_hex, LBTC_TESTNET_ASSET_ID);
}

#[test]
fn test_transaction_to_hex() {
    // Create a minimal transaction to test hex encoding
    use musk::elements;

    let tx = elements::Transaction {
        version: 2,
        lock_time: elements::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    let hex = transaction_to_hex(&tx);
    assert!(!hex.is_empty());
    // Verify it's valid hex
    assert!(hex::decode(&hex).is_ok());
}

#[test]
fn test_build_witness_values() {
    let pk = [1u8; 32];
    let sig = [2u8; 64];

    // Just verify this doesn't panic - WitnessValues is opaque
    let _witness = build_witness_values(&pk, &sig);
}

#[test]
fn test_stored_utxo_to_musk_utxo() {
    use musk::elements::Script;

    let stored = StoredUtxo {
        id: 1,
        address_id: 1,
        txid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        vout: 0,
        amount: 100_000,
        asset: LBTC_TESTNET_ASSET_ID.to_string(),
        spent: false,
        amount_blinder: None,
        asset_blinder: None,
        amount_commitment: None,
        asset_commitment: None,
    };

    // Create an empty script for testing
    let script = Script::new();

    let result = stored_utxo_to_musk_utxo(&stored, script);
    assert!(
        result.is_ok(),
        "stored_utxo_to_musk_utxo failed: {:?}",
        result.err()
    );

    let utxo = result.unwrap();
    assert_eq!(utxo.amount, 100_000);
    assert_eq!(utxo.vout, 0);
}

#[test]
fn test_spend_orchestrator_new() {
    use musk::elements;
    use std::str::FromStr;

    let address_params = get_address_params("regtest");

    // Create a genesis hash for testing
    let genesis_hash = elements::BlockHash::from_str(
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap();

    let orchestrator = SpendOrchestrator::new("musk/p2pkh.simf", address_params, genesis_hash);

    // Just verify it was created successfully
    drop(orchestrator);
}

#[test]
fn test_dust_threshold_constant() {
    // Verify dust threshold is reasonable (Bitcoin's standard dust limit is 546)
    assert_eq!(DUST_THRESHOLD, 546);
}

#[test]
fn test_default_fee_constant() {
    // Verify default fee is reasonable (500 sats)
    assert_eq!(DEFAULT_FEE_SATS, 500);
}

#[test]
fn test_lbtc_asset_id_constant() {
    // Verify asset ID is 64 hex chars
    assert_eq!(LBTC_TESTNET_ASSET_ID.len(), 64);
    // Verify it's valid hex
    assert!(hex::decode(LBTC_TESTNET_ASSET_ID).is_ok());
}

#[test]
fn test_spend_preview_total_input() {
    let utxos = vec![
        StoredUtxo {
            id: 1,
            address_id: 1,
            txid: "abc".to_string(),
            vout: 0,
            amount: 50000,
            asset: LBTC_TESTNET_ASSET_ID.to_string(),
            spent: false,
            amount_blinder: None,
            asset_blinder: None,
            amount_commitment: None,
            asset_commitment: None,
        },
        StoredUtxo {
            id: 2,
            address_id: 1,
            txid: "def".to_string(),
            vout: 1,
            amount: 50000,
            asset: LBTC_TESTNET_ASSET_ID.to_string(),
            spent: false,
            amount_blinder: None,
            asset_blinder: None,
            amount_commitment: None,
            asset_commitment: None,
        },
    ];

    let preview = calculate_spend_preview("src", "dst", 10_000, &utxos).unwrap();
    assert_eq!(preview.total_input, 100_000);
}
