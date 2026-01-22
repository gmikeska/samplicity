//! `SQLite` database module for Samplicity
//!
//! Handles storage of pubkeys, addresses, UTXOs, and witness data.

#![allow(clippy::missing_panics_doc)] // All panics are from mutex unwrap which shouldn't fail
#![allow(clippy::missing_errors_doc)] // Error conditions are self-explanatory from Result type
#![allow(clippy::significant_drop_tightening)] // Mutex lock needs to be held for prepared statements

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
#[allow(dead_code)] // Fields used in tests and future expansion
pub struct StoredPubkey {
    pub id: i64,
    pub pubkey: Vec<u8>,
    pub pubkey_sha2: String,
    pub mnemonic: String,
    pub created_at: String,
}

/// Stored address information
#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)] // witness_pk used in future expansion
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
    /// Amount blinding factor (32 bytes) - for confidential UTXOs
    #[serde(skip)]
    pub amount_blinder: Option<Vec<u8>>,
    /// Asset blinding factor (32 bytes) - for confidential UTXOs
    #[serde(skip)]
    pub asset_blinder: Option<Vec<u8>>,
    /// Amount commitment (33 bytes) - for confidential UTXOs
    #[serde(skip)]
    pub amount_commitment: Option<Vec<u8>>,
    /// Asset commitment (33 bytes) - for confidential UTXOs
    #[serde(skip)]
    pub asset_commitment: Option<Vec<u8>>,
}

impl StoredUtxo {
    /// Check if this UTXO is from a confidential transaction
    #[must_use]
    pub fn is_confidential(&self) -> bool {
        if let Some(blinder) = &self.amount_blinder {
            if blinder.iter().any(|&b| b != 0) {
                return true;
            }
        }
        false
    }
}

/// UTXO data from RPC for sync operations (includes blinding data)
#[derive(Debug, Clone)]
pub struct UtxoSyncData {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub asset: String,
    pub amount_blinder: Option<Vec<u8>>,
    pub asset_blinder: Option<Vec<u8>>,
    pub amount_commitment: Option<Vec<u8>>,
    pub asset_commitment: Option<Vec<u8>>,
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
    #[allow(dead_code)] // Used in tests
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
                blinding_sk BLOB,
                balance INTEGER DEFAULT 0,
                deployed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(pubkey_id) REFERENCES pubkeys(id)
            )",
            [],
        )?;

        // Migration: add blinding_sk column if it doesn't exist (for existing databases)
        let has_blinding_sk: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('addresses') WHERE name = 'blinding_sk'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !has_blinding_sk {
            conn.execute("ALTER TABLE addresses ADD COLUMN blinding_sk BLOB", [])?;
        }

        conn.execute(
            "CREATE TABLE IF NOT EXISTS utxos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                address_id INTEGER NOT NULL,
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                asset TEXT NOT NULL,
                spent INTEGER DEFAULT 0,
                amount_blinder BLOB,
                asset_blinder BLOB,
                amount_commitment BLOB,
                asset_commitment BLOB,
                FOREIGN KEY(address_id) REFERENCES addresses(id),
                UNIQUE(txid, vout)
            )",
            [],
        )?;

        // Migration: add blinding columns to utxos if they don't exist (for existing databases)
        let has_amount_blinder: bool = conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('utxos') WHERE name = 'amount_blinder'",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if !has_amount_blinder {
            conn.execute("ALTER TABLE utxos ADD COLUMN amount_blinder BLOB", [])?;
            conn.execute("ALTER TABLE utxos ADD COLUMN asset_blinder BLOB", [])?;
            conn.execute("ALTER TABLE utxos ADD COLUMN amount_commitment BLOB", [])?;
            conn.execute("ALTER TABLE utxos ADD COLUMN asset_commitment BLOB", [])?;
        }

        drop(conn);
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
    ///
    /// For confidential addresses, pass the blinding secret key so the wallet
    /// can unblind outputs sent to this address.
    pub fn insert_address(
        &self,
        address: &str,
        pubkey_id: i64,
        witness_pk: &[u8],
        blinding_sk: Option<&[u8]>,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO addresses (address, pubkey_id, witness_pk, blinding_sk, balance) VALUES (?1, ?2, ?3, ?4, 0)",
            params![address, pubkey_id, witness_pk, blinding_sk],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get the blinding secret key for a confidential address
    ///
    /// Returns None if the address is not found or is not a confidential address.
    pub fn get_blinding_sk(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let result: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT blinding_sk FROM addresses WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .ok();
        Ok(result.flatten())
    }

    /// Get all addresses with their pubkey hashes
    #[allow(clippy::cast_sign_loss)]
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
    #[allow(clippy::cast_sign_loss)]
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
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
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
                drop(conn);
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
    ///
    /// For confidential UTXOs, pass the blinding data which is needed when spending.
    #[allow(clippy::cast_possible_wrap, clippy::too_many_arguments)]
    pub fn upsert_utxo(
        &self,
        address_id: i64,
        txid: &str,
        vout: u32,
        amount: u64,
        asset: &str,
        amount_blinder: Option<&[u8]>,
        asset_blinder: Option<&[u8]>,
        amount_commitment: Option<&[u8]>,
        asset_commitment: Option<&[u8]>,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO utxos (address_id, txid, vout, amount, asset, spent, amount_blinder, asset_blinder, amount_commitment, asset_commitment)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?9)
             ON CONFLICT(txid, vout) DO UPDATE SET
                amount = excluded.amount,
                asset = excluded.asset,
                amount_blinder = excluded.amount_blinder,
                asset_blinder = excluded.asset_blinder,
                amount_commitment = excluded.amount_commitment,
                asset_commitment = excluded.asset_commitment",
            params![address_id, txid, i64::from(vout), amount as i64, asset, amount_blinder, asset_blinder, amount_commitment, asset_commitment],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Get all unspent UTXOs for an address
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn get_unspent_utxos(&self, address: &str) -> Result<Vec<StoredUtxo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT u.id, u.address_id, u.txid, u.vout, u.amount, u.asset, u.spent,
                    u.amount_blinder, u.asset_blinder, u.amount_commitment, u.asset_commitment
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
                amount_blinder: row.get(7)?,
                asset_blinder: row.get(8)?,
                amount_commitment: row.get(9)?,
                asset_commitment: row.get(10)?,
            })
        })?;

        utxos.collect()
    }

    /// Get all unspent UTXOs for an address by `address_id`
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    #[allow(dead_code)] // Used in tests
    pub fn get_unspent_utxos_by_id(&self, address_id: i64) -> Result<Vec<StoredUtxo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, address_id, txid, vout, amount, asset, spent,
                    amount_blinder, asset_blinder, amount_commitment, asset_commitment
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
                amount_blinder: row.get(7)?,
                asset_blinder: row.get(8)?,
                amount_commitment: row.get(9)?,
                asset_commitment: row.get(10)?,
            })
        })?;

        utxos.collect()
    }

    /// Mark a UTXO as spent
    pub fn mark_utxo_spent(&self, txid: &str, vout: u32) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE utxos SET spent = 1 WHERE txid = ?1 AND vout = ?2",
            params![txid, i64::from(vout)],
        )?;
        Ok(rows_affected > 0)
    }

    /// Remove UTXOs that no longer exist (for cleanup during sync)
    pub fn remove_utxos_not_in_list(
        &self,
        address_id: i64,
        keep_utxos: &[(String, u32)],
    ) -> Result<usize> {
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
            .map(|(txid, vout)| format!("('{txid}', {vout})"))
            .collect();
        let values_list = placeholders.join(", ");

        let sql = format!(
            "DELETE FROM utxos WHERE address_id = ?1 AND (txid, vout) NOT IN (VALUES {values_list})"
        );

        let removed = conn.execute(&sql, params![address_id])?;
        drop(conn);
        Ok(removed)
    }

    /// Sync UTXOs from RPC data for an address
    ///
    /// This method accepts UTXO data including blinding information for confidential transactions.
    pub fn sync_utxos_with_blinding(&self, address: &str, utxos: &[UtxoSyncData]) -> Result<()> {
        // Get address ID
        let addr = self.get_address(address)?;
        let address_id = match addr {
            Some(a) => a.id,
            None => return Ok(()), // Address not found, skip
        };

        // Upsert each UTXO with blinding data
        for utxo in utxos {
            self.upsert_utxo(
                address_id,
                &utxo.txid,
                utxo.vout,
                utxo.amount,
                &utxo.asset,
                utxo.amount_blinder.as_deref(),
                utxo.asset_blinder.as_deref(),
                utxo.amount_commitment.as_deref(),
                utxo.asset_commitment.as_deref(),
            )?;
        }

        // Remove UTXOs that are no longer present
        let keep_list: Vec<(String, u32)> =
            utxos.iter().map(|u| (u.txid.clone(), u.vout)).collect();
        self.remove_utxos_not_in_list(address_id, &keep_list)?;

        Ok(())
    }

    /// Sync UTXOs from RPC data for an address (legacy method without blinding)
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

        // Upsert each UTXO (without blinding data)
        for (txid, vout, amount, asset) in utxos {
            self.upsert_utxo(
                address_id, txid, *vout, *amount, asset, None, None, None, None,
            )?;
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
    #[allow(dead_code)] // Used in tests
    #[allow(clippy::unnecessary_wraps)] // Consistent with other methods that return Result
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

        let Some((address_id, pubkey_id)) = addr_info else {
            return Ok(false);
        };

        // Delete associated UTXOs
        conn.execute(
            "DELETE FROM utxos WHERE address_id = ?1",
            params![address_id],
        )?;

        // Delete the address
        conn.execute("DELETE FROM addresses WHERE id = ?1", params![address_id])?;

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
            conn.execute("DELETE FROM pubkeys WHERE id = ?1", params![pubkey_id])?;
        }

        drop(conn);
        Ok(true)
    }
}
