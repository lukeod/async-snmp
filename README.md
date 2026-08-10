# async-snmp

[![CI](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeod/async-snmp/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/async-snmp.svg)](https://crates.io/crates/async-snmp)
[![Documentation](https://docs.rs/async-snmp/badge.svg)](https://docs.rs/async-snmp)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/async-snmp.svg)](#license)

An asynchronous SNMP library for Rust, built on Tokio.

## Status

The crate is pre-1.0 and its API may change between releases. This README
describes the `main` branch, which may differ from the latest published API.
For the published release, use the
[documentation on docs.rs](https://docs.rs/async-snmp/latest/async_snmp/).

## Supported operations

- SNMPv1, SNMPv2c, and SNMPv3 USM clients
- GET, GETNEXT, GETBULK, SET, WALK, and BULKWALK
- Trap and inform sending and receiving
- UDP, shared UDP, and TCP transports
- An optional SNMP agent framework
- Optional MIB integration through [mib-rs](https://github.com/lukeod/mib-rs)

GETBULK, BULKWALK, and informs require SNMPv2c or SNMPv3. SNMPv3 supports
MD5, SHA-1, and SHA-2 authentication and DES, 3DES, and AES privacy when the
corresponding crypto backend is enabled.

## Installation

Install the published release:

```bash
cargo add async-snmp
```

To use the API documented in this README, install the main branch:

```bash
cargo add async-snmp --git https://github.com/lukeod/async-snmp
cargo add tokio --features macros,rt
```

## Example

```rust
use async_snmp::{Auth, Client, oid};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(("192.168.1.1", 161), Auth::v2c("public"))
        .connect()
        .await?;

    let response = client
        .get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))
        .await?;

    for varbind in response.varbinds {
        println!("{}: {:?}", varbind.oid, varbind.value);
    }

    Ok(())
}
```

`get`, `get_next`, and `set` preserve received bindings in `varbinds` and
report response-shape issues in `anomalies`. Use `single()` when one
unambiguous binding is required.

The repository contains examples for:

- [basic client operations](examples/basic_client.rs)
- [walking a subtree](examples/walk_subtree.rs)
- [SNMPv3](examples/snmpv3_client.rs)
- [shared UDP transport](examples/shared_transport.rs)
- [TCP](examples/tcp_client.rs)
- [trap and inform sending](examples/notification_sender.rs) and
  [receiving](examples/notification_receiver.rs)
- [an agent with writable objects](examples/agent_with_set.rs)
- [calling the library from synchronous code](examples/sync_wrapper.rs)
- [MIB-backed queries](examples/mib_get.rs)

## Command-line tools

The `cli` feature provides `asnmp-get`, `asnmp-walk`, and `asnmp-set`:

```bash
cargo install --git https://github.com/lukeod/async-snmp --features cli
asnmp-get -v 2c -c public 192.0.2.10 sysDescr.0
asnmp-walk -v 2c -c public 192.0.2.10 1.3.6.1.2.1.1
asnmp-set -v 2c -c private 192.0.2.10 sysLocation.0 s rack-7
```

Run each command with `--help` for its options.

## Feature flags

| Feature | Default | Description |
|---------|:-------:|-------------|
| `agent` | No | SNMP agent support |
| `crypto-rustcrypto` | Yes | RustCrypto authentication and privacy backend |
| `crypto-fips` | No | AWS-LC FIPS backend; does not support MD5, DES, or 3DES |
| `rt-multi-thread` | No | Tokio multi-threaded runtime support |
| `cli` | No | Command-line tools |
| `mib` | No | MIB parsing and formatting through mib-rs |

SNMPv1, SNMPv2c, and SNMPv3 noAuthNoPriv work without a crypto backend. Cargo
features are additive; when both crypto backends are enabled, RustCrypto is the
default unless AWS-LC FIPS is selected in the USM configuration.

## Documentation

The [published API documentation](https://docs.rs/async-snmp/latest/async_snmp/)
covers the latest release. To build documentation for the main branch:

```bash
cargo doc --features agent,crypto-rustcrypto,cli,mib,rt-multi-thread --open
```

## Minimum supported Rust version

Rust 1.88 or later is required.

## License

Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
