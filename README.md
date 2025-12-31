# async-snmp

[![CI](https://github.com/async-snmp/async-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/async-snmp/async-snmp/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/async-snmp.svg)](https://crates.io/crates/async-snmp)
[![Documentation](https://docs.rs/async-snmp/badge.svg)](https://docs.rs/async-snmp)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/async-snmp.svg)](LICENSE-MIT)

Modern, async-first SNMP client library for Rust.

## Features

- **Full protocol support**: SNMPv1, v2c, and v3 (USM)
- **Async-first**: Built on Tokio for high-performance async I/O
- **All operations**: GET, GETNEXT, GETBULK, SET, WALK, BULKWALK
- **SNMPv3 security**: MD5/SHA-1/SHA-2 authentication, DES/AES-128/192/256 privacy
- **Multiple transports**: UDP, TCP, and shared UDP for high-throughput polling
- **Zero-copy decoding**: Minimal allocations using `bytes` crate
- **Type-safe**: Compile-time OID validation with `oid!` macro

### Protocol Support Matrix

| Feature | v1 | v2c | v3 |
|---------|:--:|:---:|:--:|
| GET / GETNEXT | Y | Y | Y |
| GETBULK | - | Y | Y |
| SET | Y | Y | Y |
| WALK / BULKWALK | Y | Y | Y |
| Traps | Y | Y | Y |
| Informs | - | Y | Y |

### SNMPv3 Security

| Authentication | Privacy |
|----------------|---------|
| MD5, SHA-1 | DES |
| SHA-224, SHA-256 | AES-128 |
| SHA-384, SHA-512 | AES-192, AES-256 |

## Installation

```bash
cargo add async-snmp
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
async-snmp = "0.1"
```

## Quick Start

### SNMPv2c

```rust
use async_snmp::{Auth, Client, oid};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
        .timeout(Duration::from_secs(5))
        .connect()
        .await?;

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.value);

    Ok(())
}
```

### SNMPv3 with Authentication and Privacy

```rust
use async_snmp::{Auth, Client, oid, v3::{AuthProtocol, PrivProtocol}};

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    let client = Client::builder("192.168.1.1:161",
        Auth::usm("admin")
            .auth(AuthProtocol::Sha256, "authpass123")
            .privacy(PrivProtocol::Aes128, "privpass123"))
        .connect()
        .await?;

    let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
    println!("sysDescr: {:?}", result.value);

    Ok(())
}
```

### Walking a Subtree

```rust
use async_snmp::{Auth, Client, oid};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
        .connect()
        .await?;

    // Walk the system subtree
    let mut walk = client.walk(&oid!(1, 3, 6, 1, 2, 1, 1));
    while let Some(result) = walk.next().await {
        let vb = result?;
        println!("{}: {:?}", vb.oid, vb.value);
    }

    Ok(())
}
```

### High-Throughput Polling (Shared Transport)

For monitoring systems polling thousands of targets:

```rust
use async_snmp::{Auth, Client, SharedUdpTransport, oid};

#[tokio::main]
async fn main() -> Result<(), async_snmp::Error> {
    // Single socket shared across all clients
    let shared = SharedUdpTransport::bind("0.0.0.0:0").await?;

    let targets = vec!["192.168.1.1:161", "192.168.1.2:161", "192.168.1.3:161"];

    let clients: Vec<_> = targets.iter()
        .map(|t| {
            let addr = t.parse().unwrap();
            Client::builder(*t, Auth::v2c("public"))
                .build(shared.handle(addr))
        })
        .collect::<Result<_, _>>()?;

    // Poll all targets concurrently - sharing one UDP socket
    let results = futures::future::join_all(
        clients.iter().map(|c| c.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)))
    ).await;

    for (client, result) in clients.iter().zip(results) {
        match result {
            Ok(vb) => println!("{}: {:?}", client.target(), vb.value),
            Err(e) => eprintln!("{}: {}", client.target(), e),
        }
    }

    Ok(())
}
```

## Documentation

Full API documentation is available on [docs.rs](https://docs.rs/async-snmp).

## Feature Flags

| Feature | Description |
|---------|-------------|
| `testing` | Expose `MockTransport` for downstream testing |
| `serde` | Serialize/Deserialize support for configuration types |
| `cli` | CLI utilities (`asnmp-get`, `asnmp-walk`, `asnmp-set`) |

## Minimum Supported Rust Version

This crate requires Rust 1.88 or later. The MSRV may be increased in minor version releases.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
