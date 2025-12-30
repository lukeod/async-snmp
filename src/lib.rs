//! # async-snmp
//!
//! Modern, async-first SNMP client library for Rust.
//!
//! ## Features
//!
//! - Full SNMPv1, v2c, and v3 support
//! - Async-first API built on Tokio
//! - Zero-copy BER encoding/decoding
//! - Type-safe OID and value handling
//! - Compile-time safe builders (no runtime panics)
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use async_snmp::{Client, oid};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), async_snmp::Error> {
//!     // SNMPv2c client
//!     let client = Client::v2c("192.168.1.1:161")
//!         .community(b"public")
//!         .timeout(Duration::from_secs(5))
//!         .connect()
//!         .await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.value);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## SNMPv3 Example
//!
//! ```rust,no_run
//! use async_snmp::{Client, oid, v3::{AuthProtocol, PrivProtocol}};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), async_snmp::Error> {
//!     let client = Client::v3("192.168.1.1:161", "admin")
//!         .auth(AuthProtocol::Sha256, "authpass123")
//!         .privacy(PrivProtocol::Aes128, "privpass123")
//!         .connect()
//!         .await?;
//!
//!     let result = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await?;
//!     println!("sysDescr: {:?}", result.value);
//!
//!     Ok(())
//! }
//! ```

pub mod agent;
pub mod ber;
pub mod client;
pub mod error;
pub mod handler;
pub mod message;
pub mod notification;
pub mod oid;
pub mod pdu;
pub mod prelude;
pub mod transport;
pub mod v3;
pub mod value;
pub mod varbind;
pub mod version;

pub(crate) mod util;

// Re-exports for convenience
pub use agent::{Agent, AgentBuilder, VacmBuilder, VacmConfig, View};
pub use client::{
    BulkWalk, Client, ClientConfig, V1ClientBuilder, V2cClientBuilder, V3AuthClientBuilder,
    V3AuthPrivClientBuilder, V3ClientBuilder, V3SecurityConfig, Walk,
};
pub use error::{
    AuthErrorKind, CryptoErrorKind, DecodeErrorKind, EncodeErrorKind, Error, ErrorStatus,
    OidErrorKind, Result,
};
pub use handler::{
    BoxFuture, GetNextResult, GetResult, MibHandler, OidTable, RequestContext, Response,
    SecurityModel, SetResult,
};
pub use message::SecurityLevel;
pub use notification::{
    Notification, NotificationReceiver, NotificationReceiverBuilder, UsmUserConfig,
    validate_notification_varbinds,
};
pub use oid::Oid;
pub use pdu::{GenericTrap, Pdu, PduType, TrapV1Pdu};
pub use transport::{SharedUdpHandle, SharedUdpTransport, TcpTransport, Transport, UdpTransport};
pub use v3::{AuthProtocol, EngineCache, LocalizedKey, ParseProtocolError, PrivProtocol};
pub use value::Value;
pub use varbind::VarBind;
pub use version::Version;

/// Type alias for a client using the shared UDP transport.
///
/// This is useful for high-throughput scenarios where many clients share
/// a single UDP socket via [`SharedUdpTransport`].
pub type SharedClient = Client<SharedUdpHandle>;

/// Type alias for a client using a dedicated UDP socket.
///
/// This is the default transport type, suitable for most use cases
/// with up to ~100 concurrent targets.
pub type UdpClient = Client<UdpTransport>;

/// Type alias for a client using a TCP connection.
pub type TcpClient = Client<TcpTransport>;

/// Testing utilities exposed via the `testing` feature.
#[cfg(feature = "testing")]
pub mod testing {
    pub use crate::util::{HexDecodeError, decode_hex, encode_hex};
}
