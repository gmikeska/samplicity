//! Samplicity - A Simplicity Sample Web Application
//!
//! This application demonstrates deploying and managing Simplicity p2pkh addresses
//! with a web interface, WebSocket updates, and balance monitoring via esplora-rs.

mod balance;
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

use balance::BalanceChecker;
use db::Database;
use deploy::{deploy_change_address, deploy_new_address, get_address_params, get_script_pubkey_for_pk_hash};
use spend::{calculate_spend_preview, SpendOrchestrator, transaction_to_hex};
use websocket::{
    ws_index, AddressInfo, BroadcastMessage, ServerMessage, SpendPreviewData, WsBroadcaster,
};

/// Application state shared across handlers
struct AppState {
    db: Database,
    broadcaster: Addr<WsBroadcaster>,
    network: String,
    program_path: String,
    balance_checker: BalanceChecker,
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
                            "error": format!("Failed to store address: {}", e)
                        })),
                    }
                }
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to store pubkey: {}", e)
                })),
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to deploy address: {}", e)
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
            "error": format!("Failed to get addresses: {}", e)
        })),
    }
}

/// Serve the main HTML page
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

/// Background task for checking balances and syncing UTXOs
async fn balance_polling_task(
    db: Database,
    balance_checker: BalanceChecker,
    broadcaster: Addr<WsBroadcaster>,
) {
    // Sleep first to let the server start
    tokio::time::sleep(Duration::from_secs(10)).await;

    loop {
        // Get all addresses
        let addresses = match db.get_all_addresses() {
            Ok(addrs) => addrs,
            Err(e) => {
                eprintln!("Failed to get addresses for balance check: {}", e);
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };

        // Check each address balance and sync UTXOs
        for addr in addresses {
            match balance_checker.check_and_sync_balance(&addr.address, &db).await {
                Ok((result, changed)) => {
                    if changed {
                        println!(
                            "Balance updated for {}: {} sats ({} UTXOs)",
                            addr.address, result.balance_sats, result.utxo_count
                        );

                        // Broadcast update to clients
                        broadcaster.do_send(BroadcastMessage(ServerMessage::BalanceUpdate {
                            address: addr.address,
                            balance: result.balance_sats,
                        }));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check/sync balance for {}: {}", addr.address, e);
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

    if let Ok(config) = musk::NodeConfig::from_file(config_path) {
        let network = match config.network() {
            musk::Network::Regtest => "regtest",
            musk::Network::Testnet => "testnet",
            musk::Network::Liquid => "liquidv1",
        };

        network.to_string()
    } else {
        // Fallback to testnet
        "testnet".to_string()
    }
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
                eprintln!("Failed to get UTXOs: {}", e);
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
                eprintln!("Failed to calculate preview: {}", e);
                None
            }
        }
    })
}

/// Create spend confirm callback
fn create_spend_confirm_callback(
    db: Database,
    balance_checker: BalanceChecker,
    program_path: String,
    network: String,
) -> Box<dyn Fn(String, String, u64) -> Result<(String, Option<String>, Option<u64>, u64), String> + Send + Sync>
{
    Box::new(
        move |source_address, destination, amount_sats| -> Result<
            (String, Option<String>, Option<u64>, u64),
            String,
        > {
            let address_params = get_address_params(&network);

            // 1. Get address info and pubkey from DB
            let source_addr = db
                .get_address(&source_address)
                .map_err(|e| format!("DB error: {}", e))?
                .ok_or_else(|| "Source address not found".to_string())?;

            let pubkey_info = db
                .get_pubkey_for_address(&source_address)
                .map_err(|e| format!("DB error: {}", e))?
                .ok_or_else(|| "Pubkey not found for address".to_string())?;

            // 2. Get UTXOs
            let utxos = db
                .get_unspent_utxos(&source_address)
                .map_err(|e| format!("Failed to get UTXOs: {}", e))?;

            if utxos.is_empty() {
                return Err("No UTXOs available to spend".to_string());
            }

            // 3. Calculate spend preview to get fee and change info
            // Only use the first UTXO (we spend one UTXO at a time for simplicity)
            let preview = calculate_spend_preview(&source_address, &destination, amount_sats, &utxos[..1])
                .map_err(|e| format!("Preview calculation failed: {}", e))?;

            // 4. Deploy change address if needed
            let (change_address_str, change_amount) = if preview.has_change {
                let change_deployed = deploy_change_address(&program_path, address_params)
                    .map_err(|e| format!("Failed to deploy change address: {}", e))?;

                // Store change address in DB
                let change_pubkey_id = db
                    .insert_pubkey(
                        &change_deployed.pubkey,
                        &change_deployed.pk_hash,
                        &change_deployed.mnemonic,
                    )
                    .map_err(|e| format!("Failed to store change pubkey: {}", e))?;

                db.insert_address(
                    &change_deployed.address,
                    change_pubkey_id,
                    &change_deployed.pubkey,
                )
                .map_err(|e| format!("Failed to store change address: {}", e))?;

                println!("Deployed change address: {}", change_deployed.address);
                (Some(change_deployed.address), Some(preview.change_amount))
            } else {
                (None, None)
            };

            // 5. Get genesis hash for testnet (we'll use a hardcoded value for now)
            // Liquid Testnet genesis hash
            let genesis_hash_hex = "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1";
            let genesis_hash = musk::elements::BlockHash::from_str(genesis_hash_hex)
                .map_err(|e| format!("Invalid genesis hash: {}", e))?;

            // 6. Get source script pubkey
            let pk_hash_bytes: [u8; 32] = hex::decode(&source_addr.pk_hash)
                .map_err(|e| format!("Invalid pk_hash hex: {}", e))?
                .try_into()
                .map_err(|_| "Invalid pk_hash length")?;

            let source_script = get_script_pubkey_for_pk_hash(&program_path, &pk_hash_bytes, address_params)
                .map_err(|e| format!("Failed to get source script: {}", e))?;

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
                .map_err(|e| format!("Spend execution failed: {}", e))?;

            // 8. Broadcast transaction via esplora
            let tx_hex = transaction_to_hex(&tx);
            println!("Broadcasting transaction ({} bytes): {}", tx_hex.len() / 2, &tx_hex[..100.min(tx_hex.len())]);
            println!("Full tx hex for debugging: {}", tx_hex);

            // Spawn a new thread with its own runtime for the blocking broadcast
            // (can't use block_on from within an async context)
            let balance_checker_clone = balance_checker.clone();
            let txid = std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| format!("Failed to create runtime: {}", e))?;
                rt.block_on(async {
                    // Add a 30 second timeout
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(30),
                        balance_checker_clone.client().broadcast_tx(&tx_hex)
                    ).await {
                        Ok(Ok(txid)) => Ok(txid),
                        Ok(Err(e)) => {
                            eprintln!("Broadcast error from Esplora: {}", e);
                            Err(format!("Broadcast failed: {}", e))
                        },
                        Err(_) => {
                            eprintln!("Broadcast timed out after 30 seconds");
                            Err("Broadcast timed out after 30 seconds".to_string())
                        },
                    }
                })
            })
            .join()
            .map_err(|_| "Thread panicked during broadcast".to_string())??;

            println!("Transaction broadcast! TXID: {}", txid);

            // 9. Mark spent UTXOs in DB (just the first one for now since we only use one)
            let spent_utxo = &utxos[0];
            db.mark_utxo_spent(&spent_utxo.txid, spent_utxo.vout)
                .map_err(|e| format!("Failed to mark UTXO as spent: {}", e))?;

            // 10. Update source address balance (set to 0 since we spent all)
            db.update_balance(&source_address, 0)
                .map_err(|e| format!("Failed to update balance: {}", e))?;

            Ok((txid, change_address_str, change_amount, preview.fee))
        },
    )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Load configuration
    let network = load_config();
    println!("Loaded configuration for network: {}", network);

    // Initialize database
    let db = Database::open("samplicity.db").expect("Failed to open database");
    println!("Database initialized");

    // Initialize balance checker using esplora-rs
    let balance_checker = match network.as_str() {
        "liquidv1" => {
            println!("Using Liquid Mainnet Esplora API");
            BalanceChecker::new_mainnet().expect("Failed to create mainnet balance checker")
        }
        _ => {
            println!(
                "Using Liquid Testnet Esplora API: {}",
                balance::ESPLORA_TESTNET_URL
            );
            BalanceChecker::new_testnet().expect("Failed to create testnet balance checker")
        }
    };

    // Create callbacks for spend operations
    let spend_preview_cb = create_spend_preview_callback(db.clone());
    let spend_confirm_cb = create_spend_confirm_callback(
        db.clone(),
        balance_checker.clone(),
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
    let balance_checker_clone = balance_checker.clone();
    let broadcaster_clone = broadcaster.clone();

    // Start balance poller as async task
    tokio::spawn(async move {
        balance_polling_task(db_clone, balance_checker_clone, broadcaster_clone).await;
    });
    println!("Balance poller started (using esplora-rs with UTXO sync)");

    // Create app state
    let app_state = Arc::new(Mutex::new(AppState {
        db: db.clone(),
        broadcaster: broadcaster.clone(),
        network,
        program_path: "musk/p2pkh.simf".to_string(),
        balance_checker: balance_checker.clone(),
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
