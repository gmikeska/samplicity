//! Samplicity - A Simplicity Sample Web Application Library
//!
//! This library provides components for deploying and managing
//! Simplicity p2pkh addresses with balance monitoring via Elements RPC.

pub mod db;
pub mod deploy;
pub mod spend;
pub mod websocket;

pub use db::{Database, StoredAddress, StoredPubkey, StoredUtxo};
pub use deploy::{deploy_new_address, get_address_params, AddressType, DeployedAddress};
