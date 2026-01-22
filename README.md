# Samplicity

**A sample application demonstrating how to integrate Simplicity smart contracts using the [musk](https://github.com/gmikeska/musk) SDK.**

Samplicity is a web application that deploys and manages Simplicity-based Pay-to-Public-Key-Hash (P2PKH) addresses on Elements/Liquid networks. It serves as a reference implementation for developers building applications with Musk for Simplicity contracts.

## Features

- **Deploy Simplicity Addresses** — Generate explicit or confidential taproot addresses locked by Simplicity scripts
- **Real-time Balance Monitoring** — Track UTXOs via Elements RPC with WebSocket updates
- **Spend from Simplicity Addresses** — Build, sign, and broadcast transactions using the musk SDK
- **Transaction Validation Testing** — Comprehensive test suite for validating transaction formation

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [The musk Directory](#the-musk-directory)
- [The musk.conf File](#the-muskconf-file)
- [Writing Transaction Validation Tests](#writing-transaction-validation-tests)
- [Development](#development)
- [License](#license)

---

## Prerequisites

- **Rust** 1.70+ with Cargo
- **Elements/Liquid Node** running with RPC enabled
- **musk SDK** (included as a local dependency)

## Quick Start

1. **Configure the Elements node connection:**

   Copy or edit `musk.conf` with your node's RPC credentials:

   ```toml
   [network]
   network = "testnet"  # or "regtest" / "liquidv1"

   [rpc]
   url = "http://127.0.0.1:18891"
   wallet = "samplicity2"
   user = "elements"
   password = "elementspass"
   ```

2. **Create a wallet in Elements** (if not already done):

   ```bash
   elements-cli createwallet "samplicity2" false false "" false true
   ```

3. **Run the application:**

   ```bash
   cargo run
   ```

4. **Open the web interface:**

   Navigate to [http://127.0.0.1:8080](http://127.0.0.1:8080)

---

## Project Structure

```
samplicity/
├── musk/                    # Simplicity program files
│   └── p2pkh.simf          # Pay-to-Public-Key-Hash contract
├── musk.conf               # Node connection configuration
├── src/
│   ├── main.rs             # HTTP server, WebSocket, RPC integration
│   ├── deploy.rs           # Address deployment (key gen, compilation)
│   ├── spend.rs            # Transaction building and signing
│   ├── db.rs               # SQLite persistence layer
│   ├── websocket.rs        # Real-time client communication
│   └── lib.rs              # Public exports
├── static/
│   └── index.html          # Web UI
├── tests/
│   ├── transaction_validation.rs  # Integration tests with Elements node
│   ├── deploy.rs           # Unit tests for address deployment
│   ├── spend.rs            # Unit tests for spend logic
│   ├── db.rs               # Unit tests for database operations
│   └── websocket.rs        # Unit tests for WebSocket messages
└── Cargo.toml
```

---

## The musk Directory

The `musk/` directory contains **Simplicity program source files** (`.simf` extension). These are the smart contract definitions that get compiled into Simplicity programs and embedded into taproot addresses.

### `musk/p2pkh.simf`

The Pay-to-Public-Key-Hash contract is the cornerstone of Samplicity:

```simf
/*
 * PAY TO PUBLIC KEY HASH
 *
 * The coins move if the person with the public key that matches the given hash
 * signs the transaction.
 */
fn sha2(string: u256) -> u256 {
    let hasher: Ctx8 = jet::sha_256_ctx_8_init();
    let hasher: Ctx8 = jet::sha_256_ctx_8_add_32(hasher, string);
    jet::sha_256_ctx_8_finalize(hasher)
}

fn main() {
    let pk: Pubkey = witness::PK;
    let expected_pk_hash: u256 = param::PK_HASH;
    let pk_hash: u256 = sha2(pk);
    assert!(jet::eq_256(pk_hash, expected_pk_hash));

    let msg: u256 = jet::sig_all_hash();
    jet::bip_0340_verify((pk, msg), witness::SIG)
}
```

**Key concepts:**

| Element | Description |
|---------|-------------|
| `param::PK_HASH` | A compile-time parameter — the SHA256 hash of the authorized public key |
| `witness::PK` | Runtime witness data — the x-only public key provided when spending |
| `witness::SIG` | Runtime witness data — the Schnorr signature proving ownership |
| `jet::sha_256_*` | Simplicity jets for efficient SHA256 hashing |
| `jet::sig_all_hash()` | Computes the sighash for the entire transaction |
| `jet::bip_0340_verify` | Verifies a BIP-340 Schnorr signature |

### Adding New Contracts

To add a new Simplicity contract:

1. Create a new `.simf` file in the `musk/` directory
2. Define parameters using `param::NAME` syntax
3. Define witness data using `witness::NAME` syntax
4. Use `jet::` functions for cryptographic operations
5. Update the application code to load and instantiate your program

---

## The musk.conf File

The `musk.conf` file configures the connection to your Elements/Liquid node. It uses TOML syntax with three main sections:

### Configuration Reference

```toml
# =============================================================================
# Network Configuration
# =============================================================================
[network]
# Network type determines address formats and default ports
# Options: "regtest", "testnet", "liquidv1"
network = "testnet"

# =============================================================================
# RPC Connection
# =============================================================================
[rpc]
# Elements node RPC endpoint (include port)
url = "http://127.0.0.1:18891"

# Wallet name for address importing and UTXO tracking
wallet = "samplicity2"

# RPC authentication (must match elements.conf)
user = "elements"
password = "elementspass"

# =============================================================================
# Chain Configuration (Optional)
# =============================================================================
[chain]
# Genesis block hash - required for transaction signing
# If omitted, musk fetches it automatically from the node
#
# To find your genesis hash:
#   elements-cli getblockhash 0
#
# genesis_hash = "a771da8e52ee6ad581ed1e9a99825e5b3b7992225534eaa2ae23244fe26ab1c1"
```

### Network Types

| Network | Description | Address Prefix (Explicit) | Address Prefix (Confidential) |
|---------|-------------|---------------------------|-------------------------------|
| `regtest` | Local development | `ert1` | `el1` |
| `testnet` | Liquid Testnet | `tex1` | `tlq1` |
| `liquidv1` | Liquid Mainnet | `ex1` | `lq1` |

### Loading Configuration in Code

The musk SDK provides easy configuration loading:

```rust
use musk::{NodeConfig, RpcClient};

// Load from file
let config = NodeConfig::from_file("musk.conf")?;
let client = RpcClient::new(config)?;

// Or create programmatically
let config = NodeConfig::new()
    .network(musk::Network::Testnet)
    .rpc_url("http://127.0.0.1:18891")
    .rpc_credentials("elements", "elementspass")
    .wallet("samplicity2");
```

---

## Writing Transaction Validation Tests

One of Samplicity's key features is demonstrating how to write integration tests that validate Simplicity transaction formation using the Elements node's RPC methods.

### Test Architecture

Transaction validation tests should follow this pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Test Setup                                   │
│  1. Create RPC client from musk.conf                           │
│  2. Open database for address/UTXO lookup                      │
│  3. Find funded addresses with available UTXOs                 │
├─────────────────────────────────────────────────────────────────┤
│                    Transaction Building                         │
│  4. Deploy destination address                                 │
│  5. Calculate spend preview (fees, change)                     │
│  6. Build and sign transaction using SpendOrchestrator         │
├─────────────────────────────────────────────────────────────────┤
│                    Validation via RPC                          │
│  7. decoderawtransaction — Verify structure                    │
│  8. testmempoolaccept — Verify validity                        │
├─────────────────────────────────────────────────────────────────┤
│                    Assertions                                   │
│  9. Verify input/output counts                                 │
│ 10. Verify value conservation                                  │
│ 11. Verify mempool acceptance                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Example: Structure Validation Test

```rust
use musk::RpcClient;
use samplicity::spend::{calculate_spend_preview, build_and_sign_transaction, transaction_to_hex};
use serial_test::serial;

#[test]
#[ignore = "requires live Elements node"]
#[serial]
fn test_decode_raw_transaction_structure() {
    // 1. Setup
    let mut client = RpcClient::from_config_file("musk.conf")
        .expect("Failed to create RPC client");
    let genesis_hash = client.genesis_hash().expect("Failed to get genesis hash");
    let address_params = client.address_params();

    // 2. Find a funded address (from your database or test setup)
    let source_address = "tex1p...";  // Your funded address
    let utxos = vec![/* your UTXOs */];
    
    // 3. Build the transaction
    let tx = build_and_sign_transaction(
        "musk/p2pkh.simf",
        &utxos[0],
        source_script,
        &pk_hash,
        &mnemonic,
        dest_script,
        500,         // amount
        500,         // fee
        change_script,
        change_amount,
        genesis_hash,
    ).expect("Failed to build transaction");

    // 4. Validate structure via RPC
    let tx_hex = transaction_to_hex(&tx);
    let decoded = client.decode_raw_transaction(&tx_hex)
        .expect("Failed to decode transaction");

    // 5. Assertions
    let vin = decoded.get("vin").unwrap().as_array().unwrap();
    let vout = decoded.get("vout").unwrap().as_array().unwrap();

    assert_eq!(vin.len(), 1, "Should have exactly 1 input");
    assert!(vout.len() >= 2, "Should have destination + fee outputs");
}
```

### Example: Mempool Acceptance Test

```rust
#[test]
#[ignore = "requires live Elements node"]
#[serial]
fn test_mempool_accept_validates_spend() {
    let mut client = RpcClient::from_config_file("musk.conf").unwrap();
    
    // ... build transaction as above ...
    
    let tx_hex = transaction_to_hex(&tx);
    
    // Test mempool acceptance WITHOUT broadcasting
    let result = client.test_mempool_accept(&tx_hex)
        .expect("Failed to call testmempoolaccept");

    let allowed = result[0]
        .get("allowed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !allowed {
        let reason = result[0]
            .get("reject-reason")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        panic!("Transaction rejected: {}", reason);
    }

    println!("✓ Transaction accepted by mempool (not broadcast)");
}
```

### Example: Value Conservation Test

```rust
#[test]
#[ignore = "requires live Elements node"]
#[serial]
fn test_verify_output_values() {
    // ... setup and build transaction ...
    
    let decoded = client.decode_raw_transaction(&tx_hex).unwrap();
    let vout = decoded.get("vout").unwrap().as_array().unwrap();

    let mut total_output: u64 = 0;
    
    for output in vout {
        // Handle floating point precision carefully
        let value_btc = output.get("value")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let value_sats = (value_btc * 100_000_000.0).round() as u64;
        total_output += value_sats;
    }

    assert_eq!(
        input_amount, total_output,
        "Input must equal sum of outputs (conservation of value)"
    );
}
```

### Key RPC Methods for Testing

| Method | Purpose | Usage |
|--------|---------|-------|
| `decoderawtransaction` | Parse transaction structure | Verify inputs, outputs, scripts |
| `testmempoolaccept` | Validate without broadcasting | Check signatures, scripts, fees |
| `getblockhash 0` | Get genesis hash | Required for sighash computation |
| `listunspent` | Get available UTXOs | Find test inputs |

### Running the Tests

```bash
# Run unit tests
cargo test

# Run integration tests (requires running Elements node)
cargo test --test transaction_validation -- --ignored

# Run tests serially to avoid RPC conflicts
cargo test --test transaction_validation -- --ignored --test-threads=1
```

---

## Development

### Building

```bash
cargo build
```

### Linting

```bash
cargo clippy --all-features -- -D warnings -W clippy::pedantic
```

### Testing

```bash
# All unit tests
cargo test

# Specific test file
cargo test --test deploy

# Integration tests (requires Elements node)
cargo test --test transaction_validation -- --ignored --nocapture
```

### Database

Samplicity uses SQLite (`samplicity.db`) to store:

- Deployed addresses and their public keys
- Mnemonic phrases (for signing)
- UTXOs synced from the Elements node
- Transaction history

---

## Architecture Overview

```
┌──────────────┐     ┌───────────────┐     ┌─────────────────┐
│   Browser    │────▶│  Actix-Web    │────▶│  Elements Node  │
│   (index.html)     │  HTTP Server  │     │  (RPC)          │
└──────────────┘     └───────────────┘     └─────────────────┘
       │                    │                      │
       │ WebSocket          │                      │
       ▼                    ▼                      │
┌──────────────┐     ┌───────────────┐            │
│ WsBroadcaster│     │   Database    │            │
│ (real-time)  │     │  (SQLite)     │            │
└──────────────┘     └───────────────┘            │
                            │                      │
                            ▼                      │
                     ┌───────────────┐            │
                     │  musk SDK     │◀───────────┘
                     │  - Program    │
                     │  - SpendBuilder
                     │  - RpcClient  │
                     └───────────────┘
```

---

## License

This project is provided as a reference implementation for educational purposes.

---

## See Also

- [musk SDK](https://github.com/BlockstreamResearch/s-lang) — The Simplicity toolchain
- [Simplicity](https://github.com/BlockstreamResearch/simplicity) — The Simplicity language
- [Elements](https://github.com/ElementsProject/elements) — The Elements blockchain
- [Liquid Network](https://liquid.net) — The Liquid sidechain

