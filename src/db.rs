//! SQLite database module for Samplicity
//!
//! Handles storage of pubkeys, addresses, UTXOs, and witness data.

use rusqlite::{params, Connection, Result};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Database wrapper for thread-safe access
#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

/// Stored public key information
#[derive(Debug, Clone)]
pub struct StoredPubkey {
    pub id: i64,
    pub pubkey: Vec<u8>,
    pub pubkey_sha2: String,
    pub mnemonic: String,
    pub created_at: String,
}

/// Stored address information
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredAddress {
    pub id: i64,
    pub address: String,
    pub pubkey_id: i64,
    #[serde(skip)]
    pub witness_pk: Vec<u8>,
    pub balance: u64,
    pub deployed_at: String,
    pub pk_hash: String,
}

/// Stored UTXO information
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredUtxo {
    pub id: i64,
    pub address_id: i64,
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub asset: String,
    pub spent: bool,
}

impl Database {
    /// Open or create a new database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing)
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Initialize the database schema
    fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS pubkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pubkey BLOB NOT NULL,
                pubkey_sha2 TEXT NOT NULL UNIQUE,
                mnemonic TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address TEXT NOT NULL UNIQUE,
                pubkey_id INTEGER NOT NULL,
                witness_pk BLOB NOT NULL,
                balance INTEGER DEFAULT 0,
                deployed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(pubkey_id) REFERENCES pubkeys(id)
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS utxos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address_id INTEGER NOT NULL,
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                asset TEXT NOT NULL,
                spent INTEGER DEFAULT 0,
                FOREIGN KEY(address_id) REFERENCES addresses(id),
                UNIQUE(txid, vout)
            )",
            [],
        )?;

        Ok(())
    }

    /// Insert a new pubkey and return its ID
    pub fn insert_pubkey(&self, pubkey: &[u8], pubkey_sha2: &str, mnemonic: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO pubkeys (pubkey, pubkey_sha2, mnemonic) VALUES (?1, ?2, ?3)",
            params![pubkey, pubkey_sha2, mnemonic],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Insert a new address and return its ID
    pub fn insert_address(&self, address: &str, pubkey_id: i64, witness_pk: &[u8]) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO addresses (address, pubkey_id, witness_pk, balance) VALUES (?1, ?2, ?3, 0)",
            params![address, pubkey_id, witness_pk],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get all addresses with their pubkey hashes
    pub fn get_all_addresses(&self) -> Result<Vec<StoredAddress>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT a.id, a.address, a.pubkey_id, a.witness_pk, a.balance, a.deployed_at, p.pubkey_sha2
             FROM addresses a
             JOIN pubkeys p ON a.pubkey_id = p.id
             ORDER BY a.deployed_at DESC"
        )?;

        let addresses = stmt.query_map([], |row| {
            Ok(StoredAddress {
                id: row.get(0)?,
                address: row.get(1)?,
                pubkey_id: row.get(2)?,
                witness_pk: row.get(3)?,
                balance: row.get::<_, i64>(4)? as u64,
                deployed_at: row.get(5)?,
                pk_hash: row.get(6)?,
            })
        })?;

        addresses.collect()
    }

    /// Get a single address by its string representation
    pub fn get_address(&self, address: &str) -> Result<Option<StoredAddress>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT a.id, a.address, a.pubkey_id, a.witness_pk, a.balance, a.deployed_at, p.pubkey_sha2
             FROM addresses a
             JOIN pubkeys p ON a.pubkey_id = p.id
             WHERE a.address = ?1"
        )?;

        let mut rows = stmt.query(params![address])?;

        if let Some(row) = rows.next()? {
            Ok(Some(StoredAddress {
                id: row.get(0)?,
                address: row.get(1)?,
                pubkey_id: row.get(2)?,
                witness_pk: row.get(3)?,
                balance: row.get::<_, i64>(4)? as u64,
                deployed_at: row.get(5)?,
                pk_hash: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Update the balance for an address, returns true if balance changed
    pub fn update_balance(&self, address: &str, new_balance: u64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();

        // Get current balance
        let current: Option<i64> = conn
            .query_row(
                "SELECT balance FROM addresses WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .ok();

        if let Some(current_balance) = current {
            if current_balance as u64 != new_balance {
                conn.execute(
                    "UPDATE addresses SET balance = ?1 WHERE address = ?2",
                    params![new_balance as i64, address],
                )?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get the pubkey for an address (for signing)
    pub fn get_pubkey_for_address(&self, address: &str) -> Result<Option<StoredPubkey>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT p.id, p.pubkey, p.pubkey_sha2, p.mnemonic, p.created_at
             FROM pubkeys p
             JOIN addresses a ON a.pubkey_id = p.id
             WHERE a.address = ?1",
        )?;

        let mut rows = stmt.query(params![address])?;

        if let Some(row) = rows.next()? {
            Ok(Some(StoredPubkey {
                id: row.get(0)?,
                pubkey: row.get(1)?,
                pubkey_sha2: row.get(2)?,
                mnemonic: row.get(3)?,
                created_at: row.get(4)?,
            }))
        } else {
            Ok(None)
        }
    }

    // ==================== UTXO Methods ====================

    /// Insert or update a UTXO (upsert based on txid+vout)
    pub fn upsert_utxo(
        &self,
        address_id: i64,
        txid: &str,
        vout: u32,
        amount: u64,
        asset: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO utxos (address_id, txid, vout, amount, asset, spent)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)
             ON CONFLICT(txid, vout) DO UPDATE SET
                amount = excluded.amount,
                asset = excluded.asset",
            params![address_id, txid, vout as i64, amount as i64, asset],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get all unspent UTXOs for an address
    pub fn get_unspent_utxos(&self, address: &str) -> Result<Vec<StoredUtxo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT u.id, u.address_id, u.txid, u.vout, u.amount, u.asset, u.spent
             FROM utxos u
             JOIN addresses a ON u.address_id = a.id
             WHERE a.address = ?1 AND u.spent = 0",
        )?;

        let utxos = stmt.query_map(params![address], |row| {
            Ok(StoredUtxo {
                id: row.get(0)?,
                address_id: row.get(1)?,
                txid: row.get(2)?,
                vout: row.get::<_, i64>(3)? as u32,
                amount: row.get::<_, i64>(4)? as u64,
                asset: row.get(5)?,
                spent: row.get::<_, i64>(6)? != 0,
            })
        })?;

        utxos.collect()
    }

    /// Get all unspent UTXOs for an address by address_id
    pub fn get_unspent_utxos_by_id(&self, address_id: i64) -> Result<Vec<StoredUtxo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, address_id, txid, vout, amount, asset, spent
             FROM utxos
             WHERE address_id = ?1 AND spent = 0",
        )?;

        let utxos = stmt.query_map(params![address_id], |row| {
            Ok(StoredUtxo {
                id: row.get(0)?,
                address_id: row.get(1)?,
                txid: row.get(2)?,
                vout: row.get::<_, i64>(3)? as u32,
                amount: row.get::<_, i64>(4)? as u64,
                asset: row.get(5)?,
                spent: row.get::<_, i64>(6)? != 0,
            })
        })?;

        utxos.collect()
    }

    /// Mark a UTXO as spent
    pub fn mark_utxo_spent(&self, txid: &str, vout: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE utxos SET spent = 1 WHERE txid = ?1 AND vout = ?2",
            params![txid, vout as i64],
        )?;
        Ok(rows_affected > 0)
    }

    /// Remove UTXOs that no longer exist (for cleanup during sync)
    pub fn remove_utxos_not_in_list(&self, address_id: i64, keep_utxos: &[(String, u32)]) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        
        if keep_utxos.is_empty() {
            // Remove all UTXOs for this address
            let removed = conn.execute(
                "DELETE FROM utxos WHERE address_id = ?1",
                params![address_id],
            )?;
            return Ok(removed);
        }

        // Build a list of (txid, vout) pairs to keep
        let placeholders: Vec<String> = keep_utxos
            .iter()
            .map(|(txid, vout)| format!("('{}', {})", txid, vout))
            .collect();
        let values_list = placeholders.join(", ");

        let sql = format!(
            "DELETE FROM utxos WHERE address_id = ?1 AND (txid, vout) NOT IN (VALUES {})",
            values_list
        );

        let removed = conn.execute(&sql, params![address_id])?;
        Ok(removed)
    }

    /// Sync UTXOs from esplora data for an address
    pub fn sync_utxos(
        &self,
        address: &str,
        utxos: &[(String, u32, u64, String)], // (txid, vout, amount, asset)
    ) -> Result<()> {
        // Get address ID
        let addr = self.get_address(address)?;
        let address_id = match addr {
            Some(a) => a.id,
            None => return Ok(()), // Address not found, skip
        };

        // Upsert each UTXO
        for (txid, vout, amount, asset) in utxos {
            self.upsert_utxo(address_id, txid, *vout, *amount, asset)?;
        }

        // Remove UTXOs that are no longer present
        let keep_list: Vec<(String, u32)> = utxos
            .iter()
            .map(|(txid, vout, _, _)| (txid.clone(), *vout))
            .collect();
        self.remove_utxos_not_in_list(address_id, &keep_list)?;

        Ok(())
    }

    /// Get address ID by address string
    pub fn get_address_id(&self, address: &str) -> Result<Option<i64>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<i64> = conn
            .query_row(
                "SELECT id FROM addresses WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .ok();
        Ok(result)
    }

    /// Delete an address and its associated UTXOs
    /// Returns true if the address was deleted, false if it wasn't found
    pub fn delete_address(&self, address: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();

        // Get address ID and pubkey_id first
        let addr_info: Option<(i64, i64)> = conn
            .query_row(
                "SELECT id, pubkey_id FROM addresses WHERE address = ?1",
                params![address],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .ok();

        let (address_id, pubkey_id) = match addr_info {
            Some(info) => info,
            None => return Ok(false), // Address not found
        };

        // Delete associated UTXOs
        conn.execute(
            "DELETE FROM utxos WHERE address_id = ?1",
            params![address_id],
        )?;

        // Delete the address
        conn.execute(
            "DELETE FROM addresses WHERE id = ?1",
            params![address_id],
        )?;

        // Check if the pubkey is still referenced by any other address
        let pubkey_in_use: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM addresses WHERE pubkey_id = ?1",
                params![pubkey_id],
                |row| row.get(0),
            )
            .unwrap_or(0);

        // If no other address uses this pubkey, delete it
        if pubkey_in_use == 0 {
            conn.execute(
                "DELETE FROM pubkeys WHERE id = ?1",
                params![pubkey_id],
            )?;
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_creation() {
        let db = Database::open_in_memory().unwrap();
        let addresses = db.get_all_addresses().unwrap();
        assert!(addresses.is_empty());
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
        db.upsert_utxo(addr_id, "txid1", 0, 100000, "lbtc_asset").unwrap();
        db.upsert_utxo(addr_id, "txid2", 1, 50000, "lbtc_asset").unwrap();

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
}
