//! Samplicity - A Simplicity Sample Web Application
//!
//! This application demonstrates deploying and managing Simplicity p2pkh addresses
//! with a web interface, WebSocket updates, and balance monitoring via esplora-rs.

mod balance;
mod db;
mod deploy;
mod websocket;

use actix::{Actor, Addr};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_web::middleware::Logger;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use balance::BalanceChecker;
use db::Database;
use deploy::{deploy_new_address, get_address_params};
use websocket::{ws_index, BroadcastMessage, ServerMessage, WsBroadcaster, AddressInfo};

/// Application state shared across handlers
struct AppState {
    db: Database,
    broadcaster: Addr<WsBroadcaster>,
    network: String,
    program_path: String,
}

/// Deploy a new address endpoint
async fn deploy_address(state: web::Data<Arc<Mutex<AppState>>>) -> impl Responder {
    let state = state.lock().unwrap();
    
    let address_params = get_address_params(&state.network);
    
    match deploy_new_address(&state.program_path, address_params) {
        Ok(deployed) => {
            // Store in database
            match state.db.insert_pubkey(&deployed.pubkey, &deployed.pk_hash, &deployed.mnemonic) {
                Ok(pubkey_id) => {
                    match state.db.insert_address(&deployed.address, pubkey_id, &deployed.pubkey) {
                        Ok(_) => {
                            // Broadcast to all WebSocket clients
                            state.broadcaster.do_send(BroadcastMessage(ServerMessage::NewAddress {
                                address: deployed.address.clone(),
                                pk_hash: deployed.pk_hash.clone(),
                            }));
                            
                            HttpResponse::Ok().json(serde_json::json!({
                                "success": true,
                                "address": deployed.address,
                                "pk_hash": deployed.pk_hash
                            }))
                        }
                        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                            "success": false,
                            "error": format!("Failed to store address: {}", e)
                        }))
                    }
                }
                Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to store pubkey: {}", e)
                }))
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "error": format!("Failed to deploy address: {}", e)
        }))
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
        }))
    }
}

/// Serve the main HTML page
async fn index() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(include_str!("../static/index.html"))
}

/// Background task for checking balances using esplora-rs
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

        // Check each address balance
        for addr in addresses {
            match balance_checker.check_balance(&addr.address).await {
                Ok(result) => {
                    // Update balance if changed
                    match db.update_balance(&addr.address, result.balance_sats) {
                        Ok(changed) => {
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
                            eprintln!("Failed to update balance for {}: {}", addr.address, e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check balance for {}: {}", addr.address, e);
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Load configuration
    let network = load_config();
    println!("Loaded configuration for network: {}", network);

    // Initialize database
    let db = Database::open("samplicity.db")
        .expect("Failed to open database");
    println!("Database initialized");

    // Initialize balance checker using esplora-rs
    let balance_checker = match network.as_str() {
        "liquidv1" => {
            println!("Using Liquid Mainnet Esplora API");
            BalanceChecker::new_mainnet().expect("Failed to create mainnet balance checker")
        }
        _ => {
            println!("Using Liquid Testnet Esplora API: {}", balance::ESPLORA_TESTNET_URL);
            BalanceChecker::new_testnet().expect("Failed to create testnet balance checker")
        }
    };

    // Start the broadcaster actor
    let broadcaster = WsBroadcaster::new().start();
    
    // Clone for background task
    let db_clone = db.clone();
    let balance_checker_clone = balance_checker.clone();
    let broadcaster_clone = broadcaster.clone();

    // Start balance poller as async task
    tokio::spawn(async move {
        balance_polling_task(db_clone, balance_checker_clone, broadcaster_clone).await;
    });
    println!("Balance poller started (using esplora-rs)");

    // Create app state
    let app_state = Arc::new(Mutex::new(AppState {
        db: db.clone(),
        broadcaster: broadcaster.clone(),
        network,
        program_path: "musk/p2pkh.simf".to_string(),
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
