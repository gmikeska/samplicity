//! SQLite database module for Samplicity
//!
//! Handles storage of pubkeys, addresses, and witness data.

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
}
