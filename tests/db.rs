//! Database tests for Samplicity

use samplicity::db::Database;

#[test]
fn test_database_creation() {
    let db = Database::open_in_memory().unwrap();
    let addresses = db.get_all_addresses().unwrap();
    assert!(addresses.is_empty());
}

#[test]
fn test_get_pubkey_for_address() {
    let db = Database::open_in_memory().unwrap();

    let pubkey = vec![1u8; 32];
    let pk_hash = "test_pk_hash";
    let mnemonic = "test mnemonic phrase words";

    let pubkey_id = db.insert_pubkey(&pubkey, pk_hash, mnemonic).unwrap();
    db.insert_address("test_addr", pubkey_id, &pubkey).unwrap();

    // Retrieve pubkey for address
    let stored_pubkey = db.get_pubkey_for_address("test_addr").unwrap();
    assert!(stored_pubkey.is_some());

    let pk = stored_pubkey.unwrap();
    assert_eq!(pk.pubkey, pubkey);
    assert_eq!(pk.pubkey_sha2, pk_hash);
    assert_eq!(pk.mnemonic, mnemonic);
}

#[test]
fn test_get_pubkey_for_nonexistent_address() {
    let db = Database::open_in_memory().unwrap();

    let result = db.get_pubkey_for_address("nonexistent_addr").unwrap();
    assert!(result.is_none());
}

#[test]
fn test_delete_address() {
    let db = Database::open_in_memory().unwrap();

    // Create address with UTXOs
    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    let addr_id = db
        .insert_address("addr_to_delete", pubkey_id, &[2u8; 32])
        .unwrap();
    db.upsert_utxo(addr_id, "txid1", 0, 100000, "lbtc").unwrap();

    // Verify address exists
    let addr = db.get_address("addr_to_delete").unwrap();
    assert!(addr.is_some());

    // Delete address
    let deleted = db.delete_address("addr_to_delete").unwrap();
    assert!(deleted);

    // Verify address is gone
    let addr = db.get_address("addr_to_delete").unwrap();
    assert!(addr.is_none());

    // Verify UTXOs are gone
    let utxos = db.get_unspent_utxos("addr_to_delete").unwrap();
    assert!(utxos.is_empty());
}

#[test]
fn test_delete_address_not_found() {
    let db = Database::open_in_memory().unwrap();

    let deleted = db.delete_address("nonexistent_addr").unwrap();
    assert!(!deleted);
}

#[test]
fn test_delete_address_preserves_shared_pubkey() {
    let db = Database::open_in_memory().unwrap();

    // Create one pubkey shared by two addresses
    let pubkey_id = db
        .insert_pubkey(&[1u8; 32], "shared_hash", "shared_mnemonic")
        .unwrap();
    db.insert_address("addr1", pubkey_id, &[2u8; 32]).unwrap();
    db.insert_address("addr2", pubkey_id, &[3u8; 32]).unwrap();

    // Delete first address
    let deleted = db.delete_address("addr1").unwrap();
    assert!(deleted);

    // Second address should still have access to the pubkey
    let pubkey = db.get_pubkey_for_address("addr2").unwrap();
    assert!(pubkey.is_some());
    assert_eq!(pubkey.unwrap().pubkey_sha2, "shared_hash");
}

#[test]
fn test_get_address_id() {
    let db = Database::open_in_memory().unwrap();

    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    let expected_id = db
        .insert_address("test_addr", pubkey_id, &[2u8; 32])
        .unwrap();

    let addr_id = db.get_address_id("test_addr").unwrap();
    assert!(addr_id.is_some());
    assert_eq!(addr_id.unwrap(), expected_id);
}

#[test]
fn test_get_address_id_not_found() {
    let db = Database::open_in_memory().unwrap();

    let addr_id = db.get_address_id("nonexistent").unwrap();
    assert!(addr_id.is_none());
}

#[test]
fn test_get_unspent_utxos_by_id() {
    let db = Database::open_in_memory().unwrap();

    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    let addr_id = db
        .insert_address("test_addr", pubkey_id, &[2u8; 32])
        .unwrap();

    // Insert UTXOs
    db.upsert_utxo(addr_id, "txid1", 0, 100000, "lbtc").unwrap();
    db.upsert_utxo(addr_id, "txid2", 1, 50000, "lbtc").unwrap();

    // Get UTXOs by address ID
    let utxos = db.get_unspent_utxos_by_id(addr_id).unwrap();
    assert_eq!(utxos.len(), 2);
    assert_eq!(utxos.iter().map(|u| u.amount).sum::<u64>(), 150000);
}

#[test]
fn test_remove_utxos_empty_keep_list() {
    let db = Database::open_in_memory().unwrap();

    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    let addr_id = db
        .insert_address("test_addr", pubkey_id, &[2u8; 32])
        .unwrap();

    // Insert UTXOs
    db.upsert_utxo(addr_id, "txid1", 0, 100000, "lbtc").unwrap();
    db.upsert_utxo(addr_id, "txid2", 1, 50000, "lbtc").unwrap();

    // Remove all UTXOs by passing empty keep list
    let removed = db.remove_utxos_not_in_list(addr_id, &[]).unwrap();
    assert_eq!(removed, 2);

    // Verify all UTXOs are gone
    let utxos = db.get_unspent_utxos_by_id(addr_id).unwrap();
    assert!(utxos.is_empty());
}

#[test]
fn test_insert_and_retrieve() {
    let db = Database::open_in_memory().unwrap();

    let pubkey = vec![1u8; 32];
    let pk_hash = "abc123";
    let mnemonic = "test mnemonic words";

    let pubkey_id = db.insert_pubkey(&pubkey, pk_hash, mnemonic).unwrap();
    assert!(pubkey_id > 0);

    let address = "tlq1ptest123";
    let witness_pk = vec![2u8; 32];

    let addr_id = db.insert_address(address, pubkey_id, &witness_pk).unwrap();
    assert!(addr_id > 0);

    let addresses = db.get_all_addresses().unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(addresses[0].address, address);
    assert_eq!(addresses[0].pk_hash, pk_hash);
}

#[test]
fn test_balance_update() {
    let db = Database::open_in_memory().unwrap();

    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    db.insert_address("addr1", pubkey_id, &[2u8; 32]).unwrap();

    // Initial balance is 0
    let addr = db.get_address("addr1").unwrap().unwrap();
    assert_eq!(addr.balance, 0);

    // Update balance
    let changed = db.update_balance("addr1", 100000).unwrap();
    assert!(changed);

    // Verify update
    let addr = db.get_address("addr1").unwrap().unwrap();
    assert_eq!(addr.balance, 100000);

    // Same balance should not report change
    let changed = db.update_balance("addr1", 100000).unwrap();
    assert!(!changed);
}

#[test]
fn test_utxo_operations() {
    let db = Database::open_in_memory().unwrap();

    // Create address
    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    let addr_id = db.insert_address("addr1", pubkey_id, &[2u8; 32]).unwrap();

    // Insert UTXOs
    db.upsert_utxo(addr_id, "txid1", 0, 100000, "lbtc_asset")
        .unwrap();
    db.upsert_utxo(addr_id, "txid2", 1, 50000, "lbtc_asset")
        .unwrap();

    // Get unspent UTXOs
    let utxos = db.get_unspent_utxos("addr1").unwrap();
    assert_eq!(utxos.len(), 2);
    assert_eq!(utxos.iter().map(|u| u.amount).sum::<u64>(), 150000);

    // Mark one as spent
    let marked = db.mark_utxo_spent("txid1", 0).unwrap();
    assert!(marked);

    // Should only have one unspent now
    let utxos = db.get_unspent_utxos("addr1").unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].txid, "txid2");
}

#[test]
fn test_utxo_sync() {
    let db = Database::open_in_memory().unwrap();

    // Create address
    let pubkey_id = db.insert_pubkey(&[1u8; 32], "hash", "mnemonic").unwrap();
    db.insert_address("addr1", pubkey_id, &[2u8; 32]).unwrap();

    // Initial sync
    let utxos = vec![
        ("txid1".to_string(), 0u32, 100000u64, "lbtc".to_string()),
        ("txid2".to_string(), 1u32, 50000u64, "lbtc".to_string()),
    ];
    db.sync_utxos("addr1", &utxos).unwrap();

    let stored = db.get_unspent_utxos("addr1").unwrap();
    assert_eq!(stored.len(), 2);

    // Sync with one removed (txid1 spent externally)
    let utxos = vec![
        ("txid2".to_string(), 1u32, 50000u64, "lbtc".to_string()),
        ("txid3".to_string(), 0u32, 75000u64, "lbtc".to_string()),
    ];
    db.sync_utxos("addr1", &utxos).unwrap();

    let stored = db.get_unspent_utxos("addr1").unwrap();
    assert_eq!(stored.len(), 2);
    let txids: Vec<&str> = stored.iter().map(|u| u.txid.as_str()).collect();
    assert!(txids.contains(&"txid2"));
    assert!(txids.contains(&"txid3"));
    assert!(!txids.contains(&"txid1"));
}
