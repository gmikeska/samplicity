//! Deploy tests for Samplicity

use samplicity::deploy::{
    deploy_change_address, deploy_new_address, get_address_params, get_script_pubkey_for_pk_hash,
    DeployError,
};
use sha2::{Digest, Sha256};

/// Path to the p2pkh program for testing
const P2PKH_PROGRAM_PATH: &str = "musk/p2pkh.simf";

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

    // Verify different networks return different params by comparing bech_hrp
    // (can't use ptr::eq across crate boundaries)
    assert_ne!(testnet.bech_hrp, regtest.bech_hrp);
    assert_ne!(liquid.bech_hrp, testnet.bech_hrp);
    assert_ne!(liquid.bech_hrp, regtest.bech_hrp);

    // Verify expected HRP values
    assert_eq!(testnet.bech_hrp.as_str(), "tex");
    assert_eq!(liquid.bech_hrp.as_str(), "ex");
    assert_eq!(regtest.bech_hrp.as_str(), "ert");
}

#[test]
fn test_deploy_error_display() {
    let key_gen_error = DeployError::KeyGeneration("test key error".to_string());
    assert!(key_gen_error.to_string().contains("Key generation error"));
    assert!(key_gen_error.to_string().contains("test key error"));

    let program_load_error = DeployError::ProgramLoad("test load error".to_string());
    assert!(program_load_error.to_string().contains("Program load error"));
    assert!(program_load_error.to_string().contains("test load error"));

    let compilation_error = DeployError::Compilation("test compile error".to_string());
    assert!(compilation_error.to_string().contains("Compilation error"));
    assert!(compilation_error.to_string().contains("test compile error"));
}

#[test]
fn test_deploy_new_address() {
    let address_params = get_address_params("regtest");

    let result = deploy_new_address(P2PKH_PROGRAM_PATH, address_params);
    assert!(result.is_ok(), "deploy_new_address failed: {:?}", result.err());

    let deployed = result.unwrap();

    // Verify address starts with correct prefix for regtest
    assert!(
        deployed.address.starts_with("ert1p"),
        "Expected regtest taproot address starting with ert1p, got: {}",
        deployed.address
    );

    // Verify pubkey is 32 bytes (x-only)
    assert_eq!(deployed.pubkey.len(), 32);

    // Verify pk_hash is 64 hex chars (32 bytes)
    assert_eq!(deployed.pk_hash.len(), 64);

    // Verify mnemonic has 12 words
    let word_count = deployed.mnemonic.split_whitespace().count();
    assert_eq!(word_count, 12, "Expected 12-word mnemonic, got {} words", word_count);

    // Verify pk_hash is actually SHA256 of pubkey
    let mut hasher = Sha256::new();
    hasher.update(&deployed.pubkey);
    let computed_hash = hex::encode(hasher.finalize());
    assert_eq!(deployed.pk_hash, computed_hash);
}

#[test]
fn test_deploy_change_address() {
    // deploy_change_address is identical to deploy_new_address
    let address_params = get_address_params("testnet");

    let result = deploy_change_address(P2PKH_PROGRAM_PATH, address_params);
    assert!(result.is_ok(), "deploy_change_address failed: {:?}", result.err());

    let deployed = result.unwrap();

    // Verify address starts with correct prefix for testnet
    assert!(
        deployed.address.starts_with("tex1p") || deployed.address.starts_with("tlq1p"),
        "Expected testnet taproot address, got: {}",
        deployed.address
    );
}

#[test]
fn test_get_script_pubkey_for_pk_hash() {
    let address_params = get_address_params("regtest");

    // Create a test pk_hash (SHA256 of some data)
    let test_pubkey = [42u8; 32];
    let mut hasher = Sha256::new();
    hasher.update(&test_pubkey);
    let pk_hash: [u8; 32] = hasher.finalize().into();

    let result = get_script_pubkey_for_pk_hash(P2PKH_PROGRAM_PATH, &pk_hash, address_params);
    assert!(result.is_ok(), "get_script_pubkey_for_pk_hash failed: {:?}", result.err());

    let script = result.unwrap();

    // Script should be non-empty (taproot witness program)
    assert!(!script.is_empty());
}

#[test]
fn test_deploy_with_invalid_program_path() {
    let address_params = get_address_params("regtest");

    let result = deploy_new_address("/nonexistent/path/program.simf", address_params);
    assert!(result.is_err());

    match result.unwrap_err() {
        DeployError::ProgramLoad(msg) => {
            assert!(msg.contains("Failed to load program"));
        }
        other => panic!("Expected ProgramLoad error, got: {:?}", other),
    }
}
