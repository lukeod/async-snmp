//! SNMP Notification Receiver (RFC 3413).
//!
//! This module provides functionality for receiving SNMP notifications:
//! - TrapV1 (SNMPv1 format, different PDU structure)
//! - TrapV2/SNMPv2-Trap (SNMPv2c/v3 format)
//! - InformRequest (confirmed notification, requires response)
//!
//! # Example
//!
//! ```rust,no_run
//! use async_snmp::notification::{NotificationReceiver, Notification};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<async_snmp::Error>> {
//!     let receiver = NotificationReceiver::bind("0.0.0.0:162").await?;
//!
//!     loop {
//!         match receiver.recv().await {
//!             Ok((notification, source)) => {
//!                 println!("Received notification from {}: {:?}", source, notification);
//!             }
//!             Err(e) => {
//!                 eprintln!("Error receiving notification: {}", e);
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! # V3 Authenticated Informs
//!
//! To receive and respond to authenticated V3 InformRequests, configure USM credentials:
//!
//! ```rust,no_run
//! use async_snmp::notification::NotificationReceiver;
//! use async_snmp::{AuthProtocol, PrivProtocol};
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! let receiver = NotificationReceiver::builder()
//!     .bind("0.0.0.0:162")
//!     .usm_user("informuser", |u| {
//!         u.auth(AuthProtocol::Sha1, b"authpass123")
//!          .privacy(PrivProtocol::Aes128, b"privpass123")
//!     })
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```

mod handlers;
mod types;
mod varbind;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tracing::instrument;

use crate::ber::Decoder;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::oid::Oid;
use crate::pdu::TrapV1Pdu;
use crate::util::bind_udp_socket;
use crate::v3::SaltCounter;
use crate::varbind::VarBind;
use crate::version::Version;

// Re-exports
pub(crate) use types::DerivedKeys;
pub use types::UsmUserConfig;
pub use varbind::validate_notification_varbinds;

/// Well-known OIDs for notification varbinds.
pub mod oids {
    use crate::oid;

    /// sysUpTime.0 - first varbind in v2c/v3 notifications
    pub fn sys_uptime() -> crate::Oid {
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)
    }

    /// snmpTrapOID.0 - second varbind in v2c/v3 notifications (contains trap type)
    pub fn snmp_trap_oid() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
    }

    /// snmpTrapEnterprise.0 - optional, enterprise OID for enterprise-specific traps
    pub fn snmp_trap_enterprise() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0)
    }

    /// Standard trap OID prefix (snmpTraps)
    pub fn snmp_traps() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5)
    }

    /// coldStart trap OID (snmpTraps.1)
    pub fn cold_start() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)
    }

    /// warmStart trap OID (snmpTraps.2)
    pub fn warm_start() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2)
    }

    /// linkDown trap OID (snmpTraps.3)
    pub fn link_down() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)
    }

    /// linkUp trap OID (snmpTraps.4)
    pub fn link_up() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4)
    }

    /// authenticationFailure trap OID (snmpTraps.5)
    pub fn auth_failure() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5)
    }

    /// egpNeighborLoss trap OID (snmpTraps.6)
    pub fn egp_neighbor_loss() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 6)
    }
}

/// Builder for `NotificationReceiver`.
///
/// Allows configuration of bind address and USM credentials for V3 support.
pub struct NotificationReceiverBuilder {
    bind_addr: String,
    usm_users: HashMap<Bytes, UsmUserConfig>,
}

impl NotificationReceiverBuilder {
    /// Create a new builder with default settings.
    ///
    /// Defaults:
    /// - Bind address: `0.0.0.0:162` (UDP, standard SNMP trap port)
    /// - No USM users (v3 notifications rejected until users are added)
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:162".to_string(),
            usm_users: HashMap::new(),
        }
    }

    /// Set the UDP bind address.
    ///
    /// Default is `0.0.0.0:162` (UDP, standard SNMP trap port).
    pub fn bind(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Add a USM user for V3 authentication.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    /// use async_snmp::{AuthProtocol, PrivProtocol};
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .usm_user("trapuser", |u| {
    ///         u.auth(AuthProtocol::Sha1, b"authpassword")
    ///          .privacy(PrivProtocol::Aes128, b"privpassword")
    ///     })
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(UsmUserConfig) -> UsmUserConfig,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmUserConfig::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
    }

    /// Build the notification receiver.
    pub async fn build(self) -> Result<NotificationReceiver> {
        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(bind_addr, None)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        Ok(NotificationReceiver {
            inner: Arc::new(ReceiverInner {
                socket,
                local_addr,
                usm_users: self.usm_users,
                salt_counter: SaltCounter::new(),
            }),
        })
    }
}

impl Default for NotificationReceiverBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Received SNMP notification.
///
/// This enum represents all types of SNMP notifications that can be received:
/// - SNMPv1 Trap (different PDU structure)
/// - SNMPv2c/v3 Trap (standard PDU with sysUpTime.0 and snmpTrapOID.0)
/// - InformRequest (confirmed notification, response will be sent automatically)
#[derive(Debug, Clone)]
pub enum Notification {
    /// SNMPv1 Trap with unique PDU structure.
    TrapV1 {
        /// Community string used for authentication
        community: Bytes,
        /// The trap PDU
        trap: TrapV1Pdu,
    },

    /// SNMPv2c Trap (unconfirmed notification).
    TrapV2c {
        /// Community string used for authentication
        community: Bytes,
        /// sysUpTime.0 value (hundredths of seconds since agent init)
        uptime: u32,
        /// snmpTrapOID.0 value (trap type identifier)
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Original request ID (for logging/correlation)
        request_id: i32,
    },

    /// SNMPv3 Trap (unconfirmed notification).
    TrapV3 {
        /// Username from USM
        username: Bytes,
        /// Context engine ID
        context_engine_id: Bytes,
        /// Context name
        context_name: Bytes,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Original request ID
        request_id: i32,
    },

    /// InformRequest (confirmed notification) - v2c.
    ///
    /// A response is automatically sent when this notification is received.
    InformV2c {
        /// Community string
        community: Bytes,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Request ID (used in response)
        request_id: i32,
    },

    /// InformRequest (confirmed notification) - v3.
    ///
    /// A response is automatically sent when this notification is received.
    InformV3 {
        /// Username from USM
        username: Bytes,
        /// Context engine ID
        context_engine_id: Bytes,
        /// Context name
        context_name: Bytes,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Request ID
        request_id: i32,
    },
}

impl Notification {
    /// Get the trap/notification OID.
    ///
    /// For TrapV1, this is derived from enterprise + generic/specific trap.
    /// For v2c/v3, this is the snmpTrapOID.0 value.
    pub fn trap_oid(&self) -> &Oid {
        match self {
            Notification::TrapV1 { trap, .. } => &trap.enterprise,
            Notification::TrapV2c { trap_oid, .. }
            | Notification::TrapV3 { trap_oid, .. }
            | Notification::InformV2c { trap_oid, .. }
            | Notification::InformV3 { trap_oid, .. } => trap_oid,
        }
    }

    /// Get the uptime value (sysUpTime.0 or time_stamp for v1).
    pub fn uptime(&self) -> u32 {
        match self {
            Notification::TrapV1 { trap, .. } => trap.time_stamp,
            Notification::TrapV2c { uptime, .. }
            | Notification::TrapV3 { uptime, .. }
            | Notification::InformV2c { uptime, .. }
            | Notification::InformV3 { uptime, .. } => *uptime,
        }
    }

    /// Get the variable bindings.
    pub fn varbinds(&self) -> &[VarBind] {
        match self {
            Notification::TrapV1 { trap, .. } => &trap.varbinds,
            Notification::TrapV2c { varbinds, .. }
            | Notification::TrapV3 { varbinds, .. }
            | Notification::InformV2c { varbinds, .. }
            | Notification::InformV3 { varbinds, .. } => varbinds,
        }
    }

    /// Check if this is a confirmed notification (InformRequest).
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self,
            Notification::InformV2c { .. } | Notification::InformV3 { .. }
        )
    }

    /// Get the SNMP version of this notification.
    pub fn version(&self) -> Version {
        match self {
            Notification::TrapV1 { .. } => Version::V1,
            Notification::TrapV2c { .. } | Notification::InformV2c { .. } => Version::V2c,
            Notification::TrapV3 { .. } | Notification::InformV3 { .. } => Version::V3,
        }
    }
}

/// SNMP Notification Receiver.
///
/// Listens for incoming SNMP notifications (traps and informs) on a UDP socket.
/// For InformRequest notifications, automatically sends a Response-PDU.
///
/// # V3 Authentication
///
/// To receive authenticated V3 notifications, use the builder pattern to configure
/// USM credentials:
///
/// ```rust,no_run
/// use async_snmp::notification::NotificationReceiver;
/// use async_snmp::{AuthProtocol, PrivProtocol};
///
/// # async fn example() -> Result<(), Box<async_snmp::Error>> {
/// let receiver = NotificationReceiver::builder()
///     .bind("0.0.0.0:162")
///     .usm_user("trapuser", |u| {
///         u.auth(AuthProtocol::Sha1, b"authpassword")
///     })
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct NotificationReceiver {
    inner: Arc<ReceiverInner>,
}

struct ReceiverInner {
    socket: UdpSocket,
    local_addr: SocketAddr,
    /// Configured USM users for V3 authentication
    usm_users: HashMap<Bytes, UsmUserConfig>,
    /// Salt counter for privacy operations
    salt_counter: SaltCounter,
}

impl NotificationReceiver {
    /// Create a builder for configuring the notification receiver.
    ///
    /// Use this to configure USM credentials for V3 authentication.
    pub fn builder() -> NotificationReceiverBuilder {
        NotificationReceiverBuilder::new()
    }

    /// Bind to a local address.
    ///
    /// The standard SNMP notification port is 162.
    /// For V3 authentication support, use `NotificationReceiver::builder()` instead.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// // Bind to the standard trap port (requires root/admin on most systems)
    /// let receiver = NotificationReceiver::bind("0.0.0.0:162").await?;
    ///
    /// // Or use an unprivileged port for testing
    /// let receiver = NotificationReceiver::bind("0.0.0.0:1162").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bind(addr: impl AsRef<str>) -> Result<Self> {
        let addr_str = addr.as_ref();
        let bind_addr: SocketAddr = addr_str
            .parse()
            .map_err(|_| Error::Config(format!("invalid bind address: {}", addr_str).into()))?;

        let socket = bind_udp_socket(bind_addr, None)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        Ok(Self {
            inner: Arc::new(ReceiverInner {
                socket,
                local_addr,
                usm_users: HashMap::new(),
                salt_counter: SaltCounter::new(),
            }),
        })
    }

    /// Get the local address this receiver is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Receive a notification.
    ///
    /// This method blocks until a notification is received. For InformRequest
    /// notifications, a Response-PDU is automatically sent back to the sender.
    ///
    /// Returns the notification and the source address.
    #[instrument(skip(self), err, fields(snmp.local_addr = %self.local_addr()))]
    pub async fn recv(&self) -> Result<(Notification, SocketAddr)> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, source) =
                self.inner
                    .socket
                    .recv_from(&mut buf)
                    .await
                    .map_err(|e| Error::Network {
                        target: self.inner.local_addr,
                        source: e,
                    })?;

            let data = Bytes::copy_from_slice(&buf[..len]);

            match self.parse_and_respond(data, source).await {
                Ok(Some(notification)) => return Ok((notification, source)),
                Ok(None) => continue, // Not a notification PDU, ignore
                Err(e) => {
                    // Log parsing error but continue receiving
                    tracing::warn!(snmp.source = %source, error = %e, "failed to parse notification");
                    continue;
                }
            }
        }
    }

    /// Parse received data and send response if needed.
    ///
    /// Returns `None` if the message is not a notification PDU.
    async fn parse_and_respond(
        &self,
        data: Bytes,
        source: SocketAddr,
    ) -> Result<Option<Notification>> {
        // First, peek at the version to determine message type
        let mut decoder = Decoder::with_target(data.clone(), source);
        let mut seq = decoder.read_sequence()?;
        let version_num = seq.read_integer()?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            tracing::debug!(
                target: "async_snmp::notification",
                source = %source,
                kind = %DecodeErrorKind::UnknownVersion(version_num),
                "unknown SNMP version"
            );
            Error::MalformedResponse { target: source }.boxed()
        })?;
        drop(seq);
        drop(decoder);

        match version {
            Version::V1 => self.handle_v1(data, source).await,
            Version::V2c => self.handle_v2c(data, source).await,
            Version::V3 => self.handle_v3(data, source).await,
        }
    }
}

impl Clone for NotificationReceiver {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::SecurityLevel;
    use crate::oid;
    use crate::pdu::GenericTrap;
    use crate::v3::AuthProtocol;

    #[test]
    fn test_notification_trap_v1() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            vec![],
        );

        let notification = Notification::TrapV1 {
            community: Bytes::from_static(b"public"),
            trap,
        };

        assert!(!notification.is_confirmed());
        assert_eq!(notification.version(), Version::V1);
        assert_eq!(notification.uptime(), 12345);
    }

    #[test]
    fn test_notification_trap_v2c() {
        let notification = Notification::TrapV2c {
            community: Bytes::from_static(b"public"),
            uptime: 54321,
            trap_oid: oids::link_up(),
            varbinds: vec![],
            request_id: 1,
        };

        assert!(!notification.is_confirmed());
        assert_eq!(notification.version(), Version::V2c);
        assert_eq!(notification.uptime(), 54321);
        assert_eq!(notification.trap_oid(), &oids::link_up());
    }

    #[test]
    fn test_notification_inform() {
        let notification = Notification::InformV2c {
            community: Bytes::from_static(b"public"),
            uptime: 11111,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 42,
        };

        assert!(notification.is_confirmed());
        assert_eq!(notification.version(), Version::V2c);
    }

    #[test]
    fn test_notification_receiver_builder_default() {
        let builder = NotificationReceiverBuilder::new();
        assert_eq!(builder.bind_addr, "0.0.0.0:162");
        assert!(builder.usm_users.is_empty());
    }

    #[test]
    fn test_notification_receiver_builder_with_user() {
        let builder = NotificationReceiverBuilder::new()
            .bind("0.0.0.0:1162")
            .usm_user("trapuser", |u| u.auth(AuthProtocol::Sha1, b"authpass"));

        assert_eq!(builder.bind_addr, "0.0.0.0:1162");
        assert_eq!(builder.usm_users.len(), 1);

        let user = builder
            .usm_users
            .get(&Bytes::from_static(b"trapuser"))
            .unwrap();
        assert_eq!(user.security_level(), SecurityLevel::AuthNoPriv);
    }

    #[test]
    fn test_notification_v3_inform() {
        let notification = Notification::InformV3 {
            username: Bytes::from_static(b"testuser"),
            context_engine_id: Bytes::from_static(b"engine123"),
            context_name: Bytes::new(),
            uptime: 99999,
            trap_oid: oids::warm_start(),
            varbinds: vec![],
            request_id: 100,
        };

        assert!(notification.is_confirmed());
        assert_eq!(notification.version(), Version::V3);
        assert_eq!(notification.uptime(), 99999);
        assert_eq!(notification.trap_oid(), &oids::warm_start());
    }
}
