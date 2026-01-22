//! WebSocket tests for Samplicity

use samplicity::db::StoredAddress;
use samplicity::websocket::{
    AddressInfo, ClientMessage, ServerMessage, SpendPreviewData, WsBroadcaster,
};

#[test]
fn test_client_message_deserialization_deploy() {
    let json = r#"{"type":"deploy"}"#;
    let msg: ClientMessage = serde_json::from_str(json).unwrap();
    assert!(matches!(msg, ClientMessage::Deploy));
}

#[test]
fn test_client_message_deserialization_refresh() {
    let json = r#"{"type":"refresh"}"#;
    let msg: ClientMessage = serde_json::from_str(json).unwrap();
    assert!(matches!(msg, ClientMessage::Refresh));
}

#[test]
fn test_client_message_deserialization_spend_preview() {
    let json = r#"{
        "type": "spend_preview",
        "source_address": "src_addr",
        "destination": "dst_addr",
        "amount_sats": 50000
    }"#;
    let msg: ClientMessage = serde_json::from_str(json).unwrap();
    match msg {
        ClientMessage::SpendPreviewRequest {
            source_address,
            destination,
            amount_sats,
        } => {
            assert_eq!(source_address, "src_addr");
            assert_eq!(destination, "dst_addr");
            assert_eq!(amount_sats, 50000);
        }
        _ => panic!("Expected SpendPreviewRequest"),
    }
}

#[test]
fn test_client_message_deserialization_spend_confirm() {
    let json = r#"{
        "type": "spend_confirm",
        "source_address": "src_addr",
        "destination": "dst_addr",
        "amount_sats": 75000
    }"#;
    let msg: ClientMessage = serde_json::from_str(json).unwrap();
    match msg {
        ClientMessage::SpendConfirm {
            source_address,
            destination,
            amount_sats,
        } => {
            assert_eq!(source_address, "src_addr");
            assert_eq!(destination, "dst_addr");
            assert_eq!(amount_sats, 75000);
        }
        _ => panic!("Expected SpendConfirm"),
    }
}

#[test]
fn test_client_message_deserialization_delete_address() {
    let json = r#"{"type":"delete_address","address":"addr_to_delete"}"#;
    let msg: ClientMessage = serde_json::from_str(json).unwrap();
    match msg {
        ClientMessage::DeleteAddress { address } => {
            assert_eq!(address, "addr_to_delete");
        }
        _ => panic!("Expected DeleteAddress"),
    }
}

#[test]
fn test_server_message_serialization_new_address() {
    let msg = ServerMessage::NewAddress {
        address: "test_address".to_string(),
        pk_hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"new_address\""));
    assert!(json.contains("\"address\":\"test_address\""));
    assert!(json.contains("\"pk_hash\":\"abc123\""));
}

#[test]
fn test_server_message_serialization_balance_update() {
    let msg = ServerMessage::BalanceUpdate {
        address: "test_address".to_string(),
        balance: 100000,
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"balance_update\""));
    assert!(json.contains("\"address\":\"test_address\""));
    assert!(json.contains("\"balance\":100000"));
}

#[test]
fn test_server_message_serialization_address_list() {
    let addresses = vec![
        AddressInfo {
            address: "addr1".to_string(),
            pk_hash: "hash1".to_string(),
            balance: 1000,
            deployed_at: "2024-01-01".to_string(),
        },
        AddressInfo {
            address: "addr2".to_string(),
            pk_hash: "hash2".to_string(),
            balance: 2000,
            deployed_at: "2024-01-02".to_string(),
        },
    ];
    let msg = ServerMessage::AddressList { addresses };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"address_list\""));
    assert!(json.contains("\"addresses\""));
    assert!(json.contains("\"addr1\""));
    assert!(json.contains("\"addr2\""));
}

#[test]
fn test_server_message_serialization_error() {
    let msg = ServerMessage::Error {
        message: "Something went wrong".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"error\""));
    assert!(json.contains("\"message\":\"Something went wrong\""));
}

#[test]
fn test_server_message_serialization_spend_preview_result() {
    let msg = ServerMessage::SpendPreviewResult {
        source_address: "src".to_string(),
        destination: "dst".to_string(),
        amount: 50000,
        fee: 500,
        change_amount: 49500,
        has_change: true,
        total_input: 100000,
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"spend_preview\""));
    assert!(json.contains("\"amount\":50000"));
    assert!(json.contains("\"fee\":500"));
    assert!(json.contains("\"has_change\":true"));
}

#[test]
fn test_server_message_serialization_spend_success() {
    let msg = ServerMessage::SpendSuccess {
        txid: "abc123def456".to_string(),
        amount: 50000,
        fee: 500,
        change_address: Some("change_addr".to_string()),
        change_amount: Some(49000),
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"spend_success\""));
    assert!(json.contains("\"txid\":\"abc123def456\""));
    assert!(json.contains("\"change_address\":\"change_addr\""));
}

#[test]
fn test_server_message_serialization_spend_error() {
    let msg = ServerMessage::SpendError {
        message: "Insufficient funds".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"spend_error\""));
    assert!(json.contains("\"message\":\"Insufficient funds\""));
}

#[test]
fn test_server_message_serialization_address_deleted() {
    let msg = ServerMessage::AddressDeleted {
        address: "deleted_addr".to_string(),
    };
    let json = serde_json::to_string(&msg).unwrap();

    assert!(json.contains("\"type\":\"address_deleted\""));
    assert!(json.contains("\"address\":\"deleted_addr\""));
}

#[test]
fn test_address_info_from_stored_address() {
    let stored = StoredAddress {
        id: 1,
        pubkey_id: 1,
        address: "test_address".to_string(),
        pk_hash: "test_hash".to_string(),
        balance: 50000,
        deployed_at: "2024-01-15T10:00:00".to_string(),
        witness_pk: vec![1, 2, 3],
    };

    let info: AddressInfo = stored.into();

    assert_eq!(info.address, "test_address");
    assert_eq!(info.pk_hash, "test_hash");
    assert_eq!(info.balance, 50000);
    assert_eq!(info.deployed_at, "2024-01-15T10:00:00");
}

#[test]
fn test_spend_preview_data_serialization() {
    let preview = SpendPreviewData {
        source_address: "source".to_string(),
        destination: "dest".to_string(),
        amount: 25000,
        fee: 300,
        change_amount: 24700,
        has_change: true,
        total_input: 50000,
    };

    let json = serde_json::to_string(&preview).unwrap();

    assert!(json.contains("\"source_address\":\"source\""));
    assert!(json.contains("\"destination\":\"dest\""));
    assert!(json.contains("\"amount\":25000"));
    assert!(json.contains("\"fee\":300"));
    assert!(json.contains("\"has_change\":true"));
}

#[test]
fn test_ws_broadcaster_default() {
    // Test that WsBroadcaster can be created with default
    let broadcaster = WsBroadcaster::default();
    // Just verify it creates successfully
    drop(broadcaster);
}

#[test]
fn test_ws_broadcaster_new() {
    // Test that WsBroadcaster::new() works
    let broadcaster = WsBroadcaster::new();
    drop(broadcaster);
}

#[test]
fn test_address_info_clone() {
    let info = AddressInfo {
        address: "addr".to_string(),
        pk_hash: "hash".to_string(),
        balance: 1000,
        deployed_at: "2024-01-01".to_string(),
    };

    let cloned = info.clone();
    assert_eq!(cloned.address, info.address);
    assert_eq!(cloned.balance, info.balance);
}

#[test]
fn test_server_message_clone() {
    let msg = ServerMessage::NewAddress {
        address: "addr".to_string(),
        pk_hash: "hash".to_string(),
    };

    let cloned = msg.clone();
    match cloned {
        ServerMessage::NewAddress { address, pk_hash } => {
            assert_eq!(address, "addr");
            assert_eq!(pk_hash, "hash");
        }
        _ => panic!("Expected NewAddress"),
    }
}

#[test]
fn test_client_message_invalid_json() {
    let invalid_json = r#"{"type":"unknown_type"}"#;
    let result = serde_json::from_str::<ClientMessage>(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_client_message_missing_fields() {
    // spend_preview without required fields should fail
    let incomplete = r#"{"type":"spend_preview"}"#;
    let result = serde_json::from_str::<ClientMessage>(incomplete);
    assert!(result.is_err());
}
