//! Balance checking module for Samplicity
//!
//! Uses esplora-rs to check address balances via the Blockstream Esplora API.

use esplora_rs::{Client as EsploraClient, Error as EsploraError, Utxo};
use std::sync::Arc;

/// L-BTC asset ID for Liquid Testnet
pub const LBTC_TESTNET_ASSET_ID: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// L-BTC asset ID for Liquid Mainnet
pub const LBTC_MAINNET_ASSET_ID: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

/// Default Esplora URL for Liquid Testnet
pub const ESPLORA_TESTNET_URL: &str = "https://blockstream.info/liquidtestnet/api/";

/// Default Esplora URL for Liquid Mainnet
pub const ESPLORA_MAINNET_URL: &str = "https://blockstream.info/liquid/api/";

/// Result of a balance check
#[derive(Debug, Clone)]
pub struct BalanceResult {
    pub address: String,
    pub balance_sats: u64,
    pub utxo_count: usize,
    pub utxos: Vec<UtxoInfo>,
}

/// Simplified UTXO info
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub confirmed: bool,
}

impl From<&Utxo> for UtxoInfo {
    fn from(utxo: &Utxo) -> Self {
        Self {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            value: utxo.value,
            confirmed: utxo.status.confirmed,
        }
    }
}

/// Error type for balance operations
#[derive(Debug)]
pub enum BalanceError {
    EsploraError(String),
    InvalidAddress(String),
}

impl std::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BalanceError::EsploraError(msg) => write!(f, "Esplora error: {}", msg),
            BalanceError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
        }
    }
}

impl std::error::Error for BalanceError {}

impl From<EsploraError> for BalanceError {
    fn from(err: EsploraError) -> Self {
        BalanceError::EsploraError(err.to_string())
    }
}

/// Balance checker using Esplora API
#[derive(Clone)]
pub struct BalanceChecker {
    client: EsploraClient,
    lbtc_asset_id: String,
}

impl BalanceChecker {
    /// Create a new balance checker for Liquid Testnet
    pub fn new_testnet() -> Result<Self, BalanceError> {
        let client = EsploraClient::new_public(ESPLORA_TESTNET_URL)?;
        Ok(Self {
            client,
            lbtc_asset_id: LBTC_TESTNET_ASSET_ID.to_string(),
        })
    }

    /// Create a new balance checker for Liquid Mainnet
    pub fn new_mainnet() -> Result<Self, BalanceError> {
        let client = EsploraClient::new_public(ESPLORA_MAINNET_URL)?;
        Ok(Self {
            client,
            lbtc_asset_id: LBTC_MAINNET_ASSET_ID.to_string(),
        })
    }

    /// Create a new balance checker with a custom Esplora URL
    pub fn new_custom(esplora_url: &str, lbtc_asset_id: &str) -> Result<Self, BalanceError> {
        let client = EsploraClient::new_public(esplora_url)?;
        Ok(Self {
            client,
            lbtc_asset_id: lbtc_asset_id.to_string(),
        })
    }

    /// Check the L-BTC balance of an address
    pub async fn check_balance(&self, address: &str) -> Result<BalanceResult, BalanceError> {
        let utxos = self.client.get_address_utxos(address).await?;

        // Filter to only L-BTC UTXOs (asset field matches L-BTC or is None for native)
        let lbtc_utxos: Vec<&Utxo> = utxos
            .iter()
            .filter(|utxo| {
                match &utxo.asset {
                    Some(asset_id) => asset_id == &self.lbtc_asset_id,
                    None => true, // Native asset (shouldn't happen on Liquid, but handle gracefully)
                }
            })
            .collect();

        let balance_sats: u64 = lbtc_utxos.iter().map(|utxo| utxo.value).sum();
        let utxo_infos: Vec<UtxoInfo> = lbtc_utxos.iter().map(|u| UtxoInfo::from(*u)).collect();

        Ok(BalanceResult {
            address: address.to_string(),
            balance_sats,
            utxo_count: lbtc_utxos.len(),
            utxos: utxo_infos,
        })
    }

    /// Check balances for multiple addresses
    pub async fn check_balances(
        &self,
        addresses: &[String],
    ) -> Vec<Result<BalanceResult, BalanceError>> {
        let mut results = Vec::with_capacity(addresses.len());
        for addr in addresses {
            results.push(self.check_balance(addr).await);
        }
        results
    }

    /// Get all UTXOs for an address (all assets, not just L-BTC)
    pub async fn get_all_utxos(&self, address: &str) -> Result<Vec<Utxo>, BalanceError> {
        let utxos = self.client.get_address_utxos(address).await?;
        Ok(utxos)
    }
}

/// Shared balance checker for use across threads
pub type SharedBalanceChecker = Arc<BalanceChecker>;

impl BalanceChecker {
    /// Check balance and sync UTXOs to database
    ///
    /// This fetches the balance and UTXOs from Esplora, updates the balance in the DB,
    /// and syncs the UTXOs to the database.
    pub async fn check_and_sync_balance(
        &self,
        address: &str,
        db: &crate::db::Database,
    ) -> Result<(BalanceResult, bool), BalanceError> {
        let result = self.check_balance(address).await?;

        // Sync UTXOs to database
        let utxo_data: Vec<(String, u32, u64, String)> = result
            .utxos
            .iter()
            .map(|u| (u.txid.clone(), u.vout, u.value, self.lbtc_asset_id.clone()))
            .collect();

        db.sync_utxos(address, &utxo_data)
            .map_err(|e| BalanceError::EsploraError(format!("DB sync error: {}", e)))?;

        // Update balance
        let balance_changed = db
            .update_balance(address, result.balance_sats)
            .map_err(|e| BalanceError::EsploraError(format!("DB balance update error: {}", e)))?;

        Ok((result, balance_changed))
    }

    /// Sync all addresses in the database
    ///
    /// Returns addresses that had balance changes.
    pub async fn sync_all_addresses(
        &self,
        db: &crate::db::Database,
    ) -> Vec<(String, u64)> {
        let addresses = match db.get_all_addresses() {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("Failed to get addresses from DB: {}", e);
                return vec![];
            }
        };

        let mut changes = Vec::new();

        for addr in addresses {
            match self.check_and_sync_balance(&addr.address, db).await {
                Ok((result, changed)) => {
                    if changed {
                        println!("Balance changed for {}: {} sats", addr.address, result.balance_sats);
                        changes.push((addr.address.clone(), result.balance_sats));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check balance for {}: {}", addr.address, e);
                }
            }
        }

        changes
    }

    /// Get the genesis block hash for Liquid Testnet via Esplora
    pub async fn get_genesis_hash(&self) -> Result<musk::elements::BlockHash, BalanceError> {
        let hash_str = self.client.get_block_hash_from_height(0).await?;
        musk::elements::BlockHash::from_str(&hash_str)
            .map_err(|e| BalanceError::EsploraError(format!("Invalid genesis hash: {}", e)))
    }

    /// Get inner client reference for broadcasting
    pub fn client(&self) -> &EsploraClient {
        &self.client
    }

    /// Get the L-BTC asset ID
    pub fn lbtc_asset_id(&self) -> &str {
        &self.lbtc_asset_id
    }
}

// Import for BlockHash::from_str
use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_balance_checker_creation() {
        let checker = BalanceChecker::new_testnet();
        assert!(checker.is_ok());
    }

    #[tokio::test]
    async fn test_check_balance_invalid_address() {
        let checker = BalanceChecker::new_testnet().unwrap();
        let result = checker.check_balance("invalid_address").await;
        // Should return an error for invalid address
        assert!(result.is_err());
    }
}
