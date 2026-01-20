//! Samplicity - A Simplicity Sample Web Application Library
//!
//! This library provides components for deploying and managing
//! Simplicity p2pkh addresses.

pub mod balance;
pub mod db;
pub mod deploy;
pub mod websocket;

pub use balance::{BalanceChecker, BalanceResult};
pub use db::{Database, StoredAddress, StoredPubkey};
pub use deploy::{deploy_new_address, get_address_params, DeployedAddress};

