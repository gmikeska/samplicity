//! WebSocket handler for Samplicity
//!
//! Handles real-time communication between frontend and backend.

use actix::{Actor, ActorContext, Addr, AsyncContext, Handler, Message, StreamHandler};
use actix_web::{web, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::db::{Database, StoredAddress};

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Messages from client to server
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    #[serde(rename = "deploy")]
    Deploy,
    #[serde(rename = "refresh")]
    Refresh,
}

/// Messages from server to client
#[derive(Debug, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ServerMessage {
    #[serde(rename = "new_address")]
    NewAddress { address: String, pk_hash: String },
    #[serde(rename = "balance_update")]
    BalanceUpdate { address: String, balance: u64 },
    #[serde(rename = "address_list")]
    AddressList { addresses: Vec<AddressInfo> },
    #[serde(rename = "error")]
    Error { message: String },
}

/// Address info for frontend display
#[derive(Debug, Serialize, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub pk_hash: String,
    pub balance: u64,
    pub deployed_at: String,
}

impl From<StoredAddress> for AddressInfo {
    fn from(stored: StoredAddress) -> Self {
        Self {
            address: stored.address,
            pk_hash: stored.pk_hash,
            balance: stored.balance,
            deployed_at: stored.deployed_at,
        }
    }
}

/// Message type for broadcasting to all connected clients
#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct BroadcastMessage(pub ServerMessage);

/// WebSocket session actor
pub struct WsSession {
    /// Unique session id
    pub id: usize,
    /// Client must send ping at least once per 10 seconds
    pub hb: Instant,
    /// Database handle
    pub db: Database,
    /// Broadcaster address (optional, set after connection)
    pub broadcaster: Option<Addr<WsBroadcaster>>,
}

impl WsSession {
    pub fn new(db: Database, broadcaster: Option<Addr<WsBroadcaster>>) -> Self {
        Self {
            id: rand_id(),
            hb: Instant::now(),
            db,
            broadcaster,
        }
    }

    /// Helper method that sends heartbeat ping to client every second
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // Check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // Heartbeat timed out
                println!("WebSocket client heartbeat failed, disconnecting!");
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }

    /// Send current address list to client
    fn send_address_list(&self, ctx: &mut ws::WebsocketContext<Self>) {
        match self.db.get_all_addresses() {
            Ok(addresses) => {
                let msg = ServerMessage::AddressList {
                    addresses: addresses.into_iter().map(AddressInfo::from).collect(),
                };
                if let Ok(json) = serde_json::to_string(&msg) {
                    ctx.text(json);
                }
            }
            Err(e) => {
                let msg = ServerMessage::Error {
                    message: format!("Failed to get addresses: {}", e),
                };
                if let Ok(json) = serde_json::to_string(&msg) {
                    ctx.text(json);
                }
            }
        }
    }
}

impl Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        // Start the heartbeat process
        self.hb(ctx);

        // Send initial address list
        self.send_address_list(ctx);

        // Register with broadcaster if available
        if let Some(broadcaster) = &self.broadcaster {
            let addr = ctx.address();
            broadcaster.do_send(RegisterSession { addr });
        }
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        // Unregister from broadcaster
        if let Some(broadcaster) = &self.broadcaster {
            broadcaster.do_send(UnregisterSession { id: self.id });
        }
    }
}

/// Handle messages from the client
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(text)) => {
                // Try to parse client message
                match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(ClientMessage::Deploy) => {
                        // Deploy request is handled by the main server
                        // We'll send a message to trigger deployment
                        if let Some(broadcaster) = &self.broadcaster {
                            broadcaster.do_send(DeployRequest);
                        }
                    }
                    Ok(ClientMessage::Refresh) => {
                        self.send_address_list(ctx);
                    }
                    Err(e) => {
                        let msg = ServerMessage::Error {
                            message: format!("Invalid message: {}", e),
                        };
                        if let Ok(json) = serde_json::to_string(&msg) {
                            ctx.text(json);
                        }
                    }
                }
            }
            Ok(ws::Message::Binary(_)) => {
                // We don't handle binary messages
            }
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

/// Handle broadcast messages
impl Handler<BroadcastMessage> for WsSession {
    type Result = ();

    fn handle(&mut self, msg: BroadcastMessage, ctx: &mut Self::Context) {
        if let Ok(json) = serde_json::to_string(&msg.0) {
            ctx.text(json);
        }
    }
}

/// Message to register a new session
#[derive(Message)]
#[rtype(result = "()")]
pub struct RegisterSession {
    pub addr: Addr<WsSession>,
}

/// Message to unregister a session
#[derive(Message)]
#[rtype(result = "()")]
pub struct UnregisterSession {
    pub id: usize,
}

/// Message to request a new address deployment
#[derive(Message)]
#[rtype(result = "()")]
pub struct DeployRequest;

/// Broadcaster actor that manages all WebSocket sessions
pub struct WsBroadcaster {
    sessions: Vec<Addr<WsSession>>,
    deploy_callback: Option<Box<dyn Fn() + Send + Sync>>,
}

impl WsBroadcaster {
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            deploy_callback: None,
        }
    }

    pub fn with_deploy_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.deploy_callback = Some(Box::new(callback));
        self
    }

    /// Broadcast a message to all connected sessions
    pub fn broadcast(&self, msg: ServerMessage) {
        for session in &self.sessions {
            session.do_send(BroadcastMessage(msg.clone()));
        }
    }
}

impl Default for WsBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl Actor for WsBroadcaster {
    type Context = actix::Context<Self>;
}

impl Handler<RegisterSession> for WsBroadcaster {
    type Result = ();

    fn handle(&mut self, msg: RegisterSession, _: &mut Self::Context) {
        self.sessions.push(msg.addr);
    }
}

impl Handler<UnregisterSession> for WsBroadcaster {
    type Result = ();

    fn handle(&mut self, _msg: UnregisterSession, _: &mut Self::Context) {
        // Remove session by ID - we don't have easy access to ID, so we keep all for now
        // In production, you'd want a HashMap<usize, Addr<WsSession>>
    }
}

impl Handler<DeployRequest> for WsBroadcaster {
    type Result = ();

    fn handle(&mut self, _: DeployRequest, _: &mut Self::Context) {
        if let Some(callback) = &self.deploy_callback {
            callback();
        }
    }
}

impl Handler<BroadcastMessage> for WsBroadcaster {
    type Result = ();

    fn handle(&mut self, msg: BroadcastMessage, _: &mut Self::Context) {
        self.broadcast(msg.0);
    }
}

/// Generate a random session ID
fn rand_id() -> usize {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos() as usize)
        .unwrap_or(0)
}

/// HTTP handler to upgrade to WebSocket
pub async fn ws_index(
    req: HttpRequest,
    stream: web::Payload,
    db: web::Data<Database>,
    broadcaster: web::Data<Addr<WsBroadcaster>>,
) -> Result<HttpResponse, actix_web::Error> {
    let session = WsSession::new(db.get_ref().clone(), Some(broadcaster.get_ref().clone()));
    ws::start(session, &req, stream)
}
