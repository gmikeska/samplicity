//! Samplicity - A Simplicity Sample Web Application
//!
//! This application demonstrates deploying and managing Simplicity p2pkh addresses
//! with a web interface, WebSocket updates, and balance monitoring via Elements RPC.

#![allow(clippy::significant_drop_tightening)] // State locks need to be held for the entire scope
#![allow(clippy::too_many_lines)] // Complex callback functions
#![allow(clippy::type_complexity)] // Complex callback types

mod db;
mod deploy;
mod spend;
mod websocket;

use actix::{Actor, Addr};
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use db::Database;
use deploy::{
    deploy_change_address, deploy_new_address, get_address_params, get_script_pubkey_for_pk_hash,
};
use musk::{NodeClient, NodeConfig, RpcClient};
use spend::{calculate_spend_preview, transaction_to_hex, SpendOrchestrator};
use websocket::{
    ws_index, AddressInfo, BroadcastMessage, ServerMessage, SpendPreviewData, WsBroadcaster,
};

/// Application state shared across handlers
struct AppState {
    db: Database,
    broadcaster: Addr<WsBroadcaster>,
    network: String,
    program_path: String,
    rpc_client: Arc<RpcClient>,
}

/// Deploy a new address endpoint
async fn deploy_address(state: web::Data<Arc<Mutex<AppState>>>) -> impl Responder {
    let state = state.lock().unwrap();

    let address_params = get_address_params(&state.network);

    match deploy_new_address(&state.program_path, address_params) {
        Ok(deployed) => {
            // Store in database
            match state
                .db
                .insert_pubkey(&deployed.pubkey, &deployed.pk_hash, &deployed.mnemonic)
            {
                Ok(pubkey_id) => {
                    match state
                        .db
                        .insert_address(&deployed.address, pubkey_id, &deployed.pubkey)
                    {
                        Ok(_) => {
                            // Import address to Elements wallet for UTXO tracking
                            // Use rescan=false for speed (new addresses won't have history)
                            if let Err(e) = state.rpc_client.import_address(
                                &deployed.address,
                                Some("samplicity"),
                                false,
                            ) {
                                eprintln!("Warning: Failed to import address to wallet: {e}");
                                // Continue anyway - address is stored, just won't show in listunspent
                            } else {
                                println!("Imported address to wallet: {}", deployed.address);
                            }

                            // Broadcast to all WebSocket clients
                            state.broadcaster.do_send(BroadcastMessage(
                                ServerMessage::NewAddress {
                                    address: deployed.address.clone(),
                                    pk_hash: deployed.pk_hash.clone(),
                                },
                            ));

                            HttpResponse::Ok().json(serde_json::json!({
                                "success": true,
                                "address": deployed.address,
                                "pk_hash": deployed.pk_hash
                            }))
                        }
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                            "success": false,
                            "error": format!("Failed to store address: {e}")
                        })),
                    }
                }
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to store pubkey: {e}")
                })),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to deploy address: {e}")
        })),
    }
}

/// Get all addresses endpoint
async fn get_addresses(state: web::Data<Arc<Mutex<AppState>>>) -> impl Responder {
    let state = state.lock().unwrap();

    match state.db.get_all_addresses() {
        Ok(addresses) => {
            let infos: Vec<AddressInfo> = addresses.into_iter().map(AddressInfo::from).collect();
            HttpResponse::Ok().json(infos)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to get addresses: {e}")
        })),
    }
}

/// Serve the main HTML page
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

/// Background task for checking balances and syncing UTXOs using Elements RPC
async fn balance_polling_task(
    db: Database,
    rpc_client: Arc<RpcClient>,
    broadcaster: Addr<WsBroadcaster>,
) {
    // Sleep first to let the server start
    tokio::time::sleep(Duration::from_secs(10)).await;

    loop {
        // Get all addresses
        let addresses = match db.get_all_addresses() {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("Failed to get addresses for balance check: {e}");
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };

        // Check each address balance via RPC
        for addr in addresses {
            // Parse address string to Address type
            let address = match musk::elements::Address::from_str(&addr.address) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("Failed to parse address {}: {e}", addr.address);
                    continue;
                }
            };

            // Get UTXOs from Elements wallet via RPC
            match rpc_client.get_utxos(&address) {
                Ok(utxos) => {
                    // Calculate total balance
                    let balance_sats: u64 = utxos.iter().map(|u| u.amount).sum();
                    let utxo_count = utxos.len();

                    // Sync UTXOs to database
                    let utxo_data: Vec<(String, u32, u64, String)> = utxos
                        .iter()
                        .map(|u| {
                            (
                                u.txid.to_string(),
                                u.vout,
                                u.amount,
                                spend::LBTC_TESTNET_ASSET_ID.to_string(), // Assume L-BTC
                            )
                        })
                        .collect();

                    if let Err(e) = db.sync_utxos(&addr.address, &utxo_data) {
                        eprintln!("Failed to sync UTXOs for {}: {e}", addr.address);
                    }

                    // Update balance in DB and check if changed
                    match db.update_balance(&addr.address, balance_sats) {
                        Ok(changed) => {
                            if changed {
                                println!(
                                    "Balance updated for {}: {balance_sats} sats ({utxo_count} UTXOs)",
                                    addr.address
                                );

                                // Broadcast update to clients
                                broadcaster.do_send(BroadcastMessage(
                                    ServerMessage::BalanceUpdate {
                                        address: addr.address.clone(),
                                        balance: balance_sats,
                                    },
                                ));
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to update balance for {}: {e}", addr.address);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to get UTXOs for {} via RPC: {e}", addr.address);
                }
            }
        }

        // Wait before next poll
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// Load configuration from musk.conf and return network type
fn load_config() -> String {
    // Try to load from musk.conf
    let config_path = "musk.conf";

    musk::NodeConfig::from_file(config_path).map_or_else(
        |_| "testnet".to_string(),
        |config| {
            let network = match config.network() {
                musk::Network::Regtest => "regtest",
                musk::Network::Testnet => "testnet",
                musk::Network::Liquid => "liquidv1",
            };

            network.to_string()
        },
    )
}

/// Create spend preview callback
fn create_spend_preview_callback(
    db: Database,
) -> Box<dyn Fn(String, String, u64) -> Option<SpendPreviewData> + Send + Sync> {
    Box::new(move |source_address, destination, amount_sats| {
        // Get UTXOs for the source address
        let utxos = match db.get_unspent_utxos(&source_address) {
            Ok(utxos) => utxos,
            Err(e) => {
                eprintln!("Failed to get UTXOs: {e}");
                return None;
            }
        };

        // Calculate preview using only the first UTXO
        // (we only spend one UTXO at a time for simplicity)
        if utxos.is_empty() {
            eprintln!("No UTXOs available for preview");
            return None;
        }
        match calculate_spend_preview(&source_address, &destination, amount_sats, &utxos[..1]) {
            Ok(preview) => Some(SpendPreviewData {
                source_address: preview.source_address,
                destination: preview.destination,
                amount: preview.amount,
                fee: preview.fee,
                change_amount: preview.change_amount,
                has_change: preview.has_change,
                total_input: preview.total_input,
            }),
            Err(e) => {
                eprintln!("Failed to calculate preview: {e}");
                None
            }
        }
    })
}

/// Create spend confirm callback
fn create_spend_confirm_callback(
    db: Database,
    rpc_client: Arc<RpcClient>,
    program_path: String,
    network: String,
) -> Box<
    dyn Fn(String, String, u64) -> Result<(String, Option<String>, Option<u64>, u64), String>
        + Send
        + Sync,
> {
    Box::new(
        move |source_address,
              destination,
              amount_sats|
              -> Result<(String, Option<String>, Option<u64>, u64), String> {
            let address_params = get_address_params(&network);

            // 1. Get address info and pubkey from DB
            let source_addr = db
                .get_address(&source_address)
                .map_err(|e| format!("DB error: {e}"))?
                .ok_or_else(|| "Source address not found".to_string())?;

            let pubkey_info = db
                .get_pubkey_for_address(&source_address)
                .map_err(|e| format!("DB error: {e}"))?
                .ok_or_else(|| "Pubkey not found for address".to_string())?;

            // 2. Get UTXOs
            let utxos = db
                .get_unspent_utxos(&source_address)
                .map_err(|e| format!("Failed to get UTXOs: {e}"))?;

            if utxos.is_empty() {
                return Err("No UTXOs available to spend".to_string());
            }

            // === UTXO VERIFICATION ===
            println!("=== UTXO DATA FROM DATABASE ===");
            println!("  Source address: {source_address}");
            println!("  Total UTXOs: {}", utxos.len());
            for (i, u) in utxos.iter().enumerate() {
                println!(
                    "  UTXO[{i}]: txid={}, vout={}, amount={} sats, asset={}",
                    u.txid,
                    u.vout,
                    u.amount,
                    &u.asset[..16]
                );
            }
            println!(
                "  Using UTXO[0] with {} sats for this spend",
                utxos[0].amount
            );
            println!("================================");

            // 3. Calculate spend preview to get fee and change info
            // Only use the first UTXO (we spend one UTXO at a time for simplicity)
            let preview =
                calculate_spend_preview(&source_address, &destination, amount_sats, &utxos[..1])
                    .map_err(|e| format!("Preview calculation failed: {e}"))?;

            // Log the preview
            println!("=== SPEND PREVIEW ===");
            println!("  Requested amount: {amount_sats} sats");
            println!("  Calculated fee:   {} sats", preview.fee);
            println!(
                "  Change amount:    {} sats (has_change={})",
                preview.change_amount, preview.has_change
            );
            println!("  Total input:      {} sats", preview.total_input);
            println!(
                "  Sum of outputs:   {} sats",
                amount_sats + preview.fee + preview.change_amount
            );
            println!("=====================");

            // 4. Deploy change address if needed
            let (change_address_str, change_amount) = if preview.has_change {
                let change_deployed = deploy_change_address(&program_path, address_params)
                    .map_err(|e| format!("Failed to deploy change address: {e}"))?;

                // Store change address in DB
                let change_pubkey_id = db
                    .insert_pubkey(
                        &change_deployed.pubkey,
                        &change_deployed.pk_hash,
                        &change_deployed.mnemonic,
                    )
                    .map_err(|e| format!("Failed to store change pubkey: {e}"))?;

                db.insert_address(
                    &change_deployed.address,
                    change_pubkey_id,
                    &change_deployed.pubkey,
                )
                .map_err(|e| format!("Failed to store change address: {e}"))?;

                // Import change address to Elements wallet for balance tracking
                if let Err(e) =
                    rpc_client.import_address(&change_deployed.address, Some("samplicity"), false)
                {
                    eprintln!("Warning: Failed to import change address to wallet: {e}");
                    // Continue anyway - address is stored, balance polling may be delayed
                }

                println!("Deployed change address: {}", change_deployed.address);
                (Some(change_deployed.address), Some(preview.change_amount))
            } else {
                (None, None)
            };

            // 5. Get genesis hash for testnet (we'll use a hardcoded value for now)
            // Liquid Testnet genesis hash
            let genesis_hash_hex =
                "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
            let genesis_hash = musk::elements::BlockHash::from_str(genesis_hash_hex)
                .map_err(|e| format!("Invalid genesis hash: {e}"))?;

            // 6. Get source script pubkey
            let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr.pk_hash)
                .map_err(|e| format!("Invalid pk_hash hex: {e}"))?
                .try_into()
                .map_err(|_| "Invalid pk_hash length")?;

            let source_script =
                get_script_pubkey_for_pk_hash(&program_path, &pk_hash_bytes, address_params)
                    .map_err(|e| format!("Failed to get source script: {e}"))?;

            // 7. Create spend orchestrator and execute
            let orchestrator = SpendOrchestrator::new(&program_path, address_params, genesis_hash);

            // Only use the first UTXO (we spend one UTXO at a time)
            let (tx, _) = orchestrator
                .execute_spend(
                    &source_address,
                    &source_script,
                    &pk_hash_bytes,
                    &pubkey_info.mnemonic,
                    &utxos[..1],
                    &destination,
                    amount_sats,
                    change_address_str.as_deref(),
                )
                .map_err(|e| format!("Spend execution failed: {e}"))?;

            // 8. Broadcast transaction via Elements node RPC
            let tx_hex = transaction_to_hex(&tx);
            println!(
                "Broadcasting transaction ({} bytes): {}",
                tx_hex.len() / 2,
                &tx_hex[..100.min(tx_hex.len())]
            );
            println!("Full tx hex for debugging: {tx_hex}");

            // Use the Elements RPC client to broadcast (synchronous, immediate response)
            let rpc = rpc_client.clone();
            let txid = rpc
                .broadcast(&tx)
                .map_err(|e| {
                    eprintln!("Broadcast error from Elements RPC: {e}");
                    format!("Broadcast failed: {e}")
                })?
                .to_string();

            println!("Transaction broadcast! TXID: {txid}");

            // 9. Mark spent UTXOs in DB (just the first one for now since we only use one)
            let spent_utxo = &utxos[0];
            db.mark_utxo_spent(&spent_utxo.txid, spent_utxo.vout)
                .map_err(|e| format!("Failed to mark UTXO as spent: {e}"))?;

            // 10. Update source address balance (set to 0 since we spent all)
            db.update_balance(&source_address, 0)
                .map_err(|e| format!("Failed to update balance: {e}"))?;

            Ok((txid, change_address_str, change_amount, preview.fee))
        },
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging with tracing-subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .init();

    // Load configuration
    let network = load_config();
    println!("Loaded configuration for network: {network}");

    // Initialize database
    let db = Database::open("samplicity.db").expect("Failed to open database");
    println!("Database initialized");

    // Create RPC client for broadcasting transactions via Elements node
    let rpc_config = NodeConfig::from_file("musk.conf")
        .expect("Failed to load musk.conf - make sure it exists and has valid RPC settings");
    let rpc_client = Arc::new(
        RpcClient::new(rpc_config)
            .expect("Failed to create RPC client - check Elements node is running"),
    );
    println!("RPC client created for transaction broadcasting");

    // Import existing addresses to Elements wallet (no rescan since they're likely recent)
    if let Ok(existing_addrs) = db.get_all_addresses() {
        println!(
            "Importing {} existing addresses to Elements wallet...",
            existing_addrs.len()
        );
        for addr in existing_addrs {
            if let Err(e) = rpc_client.import_address(&addr.address, Some("samplicity"), false) {
                eprintln!("  Warning: Failed to import {}: {e}", &addr.address[..20]);
            }
        }
        println!("Address import complete");
    }

    // Create callbacks for spend operations
    let spend_preview_cb = create_spend_preview_callback(db.clone());
    let spend_confirm_cb = create_spend_confirm_callback(
        db.clone(),
        rpc_client.clone(),
        "musk/p2pkh.simf".to_string(),
        network.clone(),
    );

    // Start the broadcaster actor with spend callbacks
    let broadcaster = WsBroadcaster::new()
        .with_spend_preview_callback(spend_preview_cb)
        .with_spend_confirm_callback(spend_confirm_cb)
        .start();

    // Clone for background task
    let db_clone = db.clone();
    let rpc_client_clone = rpc_client.clone();
    let broadcaster_clone = broadcaster.clone();

    // Start balance poller as async task using Elements RPC
    tokio::spawn(async move {
        balance_polling_task(db_clone, rpc_client_clone, broadcaster_clone).await;
    });
    println!("Balance poller started (using Elements RPC for UTXO sync)");

    // Create app state
    let app_state = Arc::new(Mutex::new(AppState {
        db: db.clone(),
        broadcaster: broadcaster.clone(),
        network,
        program_path: "musk/p2pkh.simf".to_string(),
        rpc_client: rpc_client.clone(),
    }));

    println!("Starting server at http://127.0.0.1:8080");

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(web::Data::new(app_state.clone()))
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(broadcaster.clone()))
            .route("/", web::get().to(index))
            .route("/ws", web::get().to(ws_index))
            .route("/api/deploy", web::post().to(deploy_address))
            .route("/api/addresses", web::get().to(get_addresses))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
