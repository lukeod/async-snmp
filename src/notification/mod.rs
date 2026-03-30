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
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

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
pub use types::{DerivedKeys, UsmConfig};
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
    usm_users: HashMap<Bytes, UsmConfig>,
    engine_id: Option<Vec<u8>>,
    engine_boots: u32,
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
            engine_id: None,
            engine_boots: 1,
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
        F: FnOnce(UsmConfig) -> UsmConfig,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmConfig::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
    }

    /// Set the engine ID for SNMPv3.
    ///
    /// If not set, a default engine ID will be generated based on the
    /// RFC 3411 format using enterprise number and timestamp.
    pub fn engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        self.engine_id = Some(engine_id.into());
        self
    }

    /// Set the initial engine boots value.
    ///
    /// This should be persisted across restarts and incremented each time
    /// the receiver starts. Default is 1.
    pub fn engine_boots(mut self, boots: u32) -> Self {
        self.engine_boots = boots;
        self
    }

    /// Build the notification receiver.
    pub async fn build(self) -> Result<NotificationReceiver> {
        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(bind_addr, None, None)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        let engine_id: Bytes = self.engine_id.map(Bytes::from).unwrap_or_else(|| {
            let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x01];
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            id.extend_from_slice(&timestamp.to_be_bytes());
            Bytes::from(id)
        });

        Ok(NotificationReceiver {
            inner: Arc::new(ReceiverInner {
                socket,
                local_addr,
                usm_users: self.usm_users,
                engine_id,
                salt_counter: SaltCounter::new(),
                engine_boots_base: self.engine_boots,
                engine_start: Instant::now(),
                usm_unknown_engine_ids: AtomicU32::new(0),
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
    pub fn trap_oid(&self) -> Result<Oid> {
        match self {
            Notification::TrapV1 { trap, .. } => trap.v2_trap_oid(),
            Notification::TrapV2c { trap_oid, .. }
            | Notification::TrapV3 { trap_oid, .. }
            | Notification::InformV2c { trap_oid, .. }
            | Notification::InformV3 { trap_oid, .. } => Ok(trap_oid.clone()),
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
    usm_users: HashMap<Bytes, UsmConfig>,
    /// Engine ID for V3 discovery responses
    engine_id: Bytes,
    /// Salt counter for privacy operations
    salt_counter: SaltCounter,
    /// Initial engine boots value at startup, used to compute overflow-adjusted boots.
    engine_boots_base: u32,
    /// Time when the receiver was started, used to compute engine time.
    engine_start: Instant,
    /// usmStatsUnknownEngineIDs counter
    usm_unknown_engine_ids: AtomicU32,
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

        let socket = bind_udp_socket(bind_addr, None, None)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        let engine_id: Bytes = {
            let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x01];
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            id.extend_from_slice(&timestamp.to_be_bytes());
            Bytes::from(id)
        };

        Ok(Self {
            inner: Arc::new(ReceiverInner {
                socket,
                local_addr,
                usm_users: HashMap::new(),
                engine_id,
                salt_counter: SaltCounter::new(),
                engine_boots_base: 1,
                engine_start: Instant::now(),
                usm_unknown_engine_ids: AtomicU32::new(0),
            }),
        })
    }

    /// Get the local address this receiver is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Get the engine ID.
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// Get the usmStatsUnknownEngineIDs counter value.
    pub fn usm_unknown_engine_ids(&self) -> u32 {
        self.inner.usm_unknown_engine_ids.load(Ordering::Relaxed)
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
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, error = %e }, "failed to parse notification");
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
            tracing::debug!(target: "async_snmp::notification", { source = %source, kind = %DecodeErrorKind::UnknownVersion(version_num) }, "unknown SNMP version");
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
        assert_eq!(notification.trap_oid().unwrap(), oids::link_down());
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
        assert_eq!(notification.trap_oid().unwrap(), oids::link_up());
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
        assert_eq!(notification.trap_oid().unwrap(), oids::warm_start());
    }

    #[test]
    fn test_notification_trap_v1_enterprise_specific_oid() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2),
            [192, 168, 1, 1],
            GenericTrap::EnterpriseSpecific,
            42,
            12345,
            vec![],
        );

        let notification = Notification::TrapV1 {
            community: Bytes::from_static(b"public"),
            trap,
        };

        assert_eq!(
            notification.trap_oid().unwrap(),
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2, 0, 42)
        );
    }

    #[test]
    fn test_compute_engine_boots_time_basic() {
        let (boots, time) = crate::v3::compute_engine_boots_time(1, 1000);
        assert_eq!(boots, 1);
        assert_eq!(time, 1000);
    }

    #[test]
    fn test_compute_engine_boots_time_zero_elapsed() {
        let (boots, time) = crate::v3::compute_engine_boots_time(1, 0);
        assert_eq!(boots, 1);
        assert_eq!(time, 0);
    }

    #[test]
    fn test_builder_engine_boots_default() {
        let builder = NotificationReceiverBuilder::new();
        assert_eq!(builder.engine_boots, 1);
    }

    #[test]
    fn test_builder_engine_boots_custom() {
        let builder = NotificationReceiverBuilder::new().engine_boots(5);
        assert_eq!(builder.engine_boots, 5);
    }

    /// Build an authenticated V3 InformRequest message with the given
    /// engine_boots and engine_time in the USM parameters.
    fn build_authed_v3_inform(
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        username: &[u8],
        auth_password: &[u8],
        auth_protocol: AuthProtocol,
    ) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::{Pdu, PduType};
        use crate::v3::auth::authenticate_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};
        use crate::value::Value;

        let auth_key =
            LocalizedKey::from_password(auth_protocol, auth_password, engine_id).unwrap();
        let mac_len = auth_key.mac_len();

        // Build an InformRequest PDU with sysUpTime.0 and snmpTrapOID.0
        let pdu = Pdu {
            pdu_type: PduType::InformRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(1000)),
                VarBind::new(oids::snmp_trap_oid(), Value::ObjectIdentifier(oids::cold_start())),
            ],
        };

        let global =
            MsgGlobalData::new(1, 65507, MsgFlags::new(SecurityLevel::AuthNoPriv, false));

        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            engine_boots,
            engine_time,
            Bytes::copy_from_slice(username),
        )
        .with_auth_placeholder(mac_len);

        let scoped = ScopedPdu::new(
            Bytes::copy_from_slice(engine_id),
            Bytes::new(),
            pdu,
        );
        let msg = V3Message::new(global, usm_params.encode(), scoped);
        let mut msg_bytes = msg.encode().to_vec();

        // Compute and insert HMAC
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&msg_bytes).unwrap();
        authenticate_message(&auth_key, &mut msg_bytes, auth_offset, auth_len).unwrap();

        Bytes::from(msg_bytes)
    }

    #[tokio::test]
    async fn test_v3_inform_outside_time_window_rejected() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();

        let engine_id = b"test-engine";
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Engine time far in the future (5000 seconds, well beyond 150-second window)
        let msg = build_authed_v3_inform(
            engine_id,
            1,    // correct boots
            5000, // way outside time window (receiver started ~0 seconds ago)
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        assert!(result.is_err(), "message with engine_time=5000 should be rejected (outside 150s window)");
    }

    #[tokio::test]
    async fn test_v3_inform_wrong_boots_rejected() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();

        let engine_id = b"test-engine";
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Wrong engine boots (receiver has boots=1)
        let msg = build_authed_v3_inform(
            engine_id,
            2, // wrong boots
            0, // time is fine
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        assert!(result.is_err(), "message with wrong engine_boots should be rejected");
    }

    #[tokio::test]
    async fn test_v3_inform_within_time_window_accepted() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();

        let engine_id = b"test-engine";
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Engine time within the window (receiver started ~0 seconds ago, engine_time=0 is fine)
        let msg = build_authed_v3_inform(
            engine_id,
            1, // correct boots
            0, // within window
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        // Should succeed (or at least not fail due to time window).
        // The Inform response send will fail since source is fake, but
        // the time window check itself should pass. The error if any
        // should be a network error from trying to send the response,
        // not an Auth error.
        match result {
            Ok(Some(_)) => {} // unexpected but ok (socket might succeed on loopback)
            Err(e) => {
                let err_str = format!("{}", e);
                assert!(
                    !err_str.contains("Auth"),
                    "should not be an auth error for valid time window, got: {}",
                    err_str
                );
            }
            Ok(None) => panic!("should not return None for a valid InformRequest"),
        }
    }

    /// Build a V3 discovery request message (empty engine ID, noAuthNoPriv).
    fn build_v3_discovery_request(msg_id: i32, reportable: bool) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::{Pdu, PduType};
        use crate::v3::UsmSecurityParams;

        let pdu = Pdu {
            pdu_type: PduType::GetRequest,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
        };

        let global = MsgGlobalData::new(
            msg_id,
            65507,
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, reportable),
        );

        let usm_params = UsmSecurityParams::new(
            Bytes::new(), // empty engine ID = discovery
            0,
            0,
            Bytes::new(), // empty username
        );

        let scoped = ScopedPdu::new(Bytes::new(), Bytes::new(), pdu);
        let msg = V3Message::new(global, usm_params.encode(), scoped);
        msg.encode()
    }

    #[tokio::test]
    async fn test_v3_discovery_gets_response() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-discovery-engine".to_vec())
            .build()
            .await
            .unwrap();

        let recv_addr = receiver.local_addr();

        // Bind a separate socket to send discovery and receive the response
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let discovery_msg = build_v3_discovery_request(42, true);
        client.send_to(&discovery_msg, recv_addr).await.unwrap();

        // The receiver needs to be running recv() to handle the message.
        // Instead, call handle_v3 directly with the client address as source.
        let result = receiver
            .handle_v3(discovery_msg, client_addr)
            .await;

        // Discovery should return Ok(None) - not a notification
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Counter should be incremented
        assert_eq!(receiver.usm_unknown_engine_ids(), 1);
    }

    #[tokio::test]
    async fn test_v3_discovery_non_reportable_ignored() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-discovery-engine".to_vec())
            .build()
            .await
            .unwrap();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let discovery_msg = build_v3_discovery_request(42, false);

        let result = receiver.handle_v3(discovery_msg, source).await;

        // Non-reportable discovery should return Ok(None) without incrementing counter
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(receiver.usm_unknown_engine_ids(), 0);
    }

    #[tokio::test]
    async fn test_v3_engine_id_mismatch_ignored() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();

        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Build a message with a DIFFERENT engine ID
        let msg = build_authed_v3_inform(
            b"wrong-engine-id",
            1,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none(), "engine ID mismatch should return None");
    }

    #[test]
    fn test_auto_generated_engine_id_non_empty() {
        let builder = NotificationReceiverBuilder::new();
        // engine_id field should be None (auto-generate on build)
        assert!(builder.engine_id.is_none());
    }

    #[tokio::test]
    async fn test_bind_generates_engine_id() {
        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        assert!(!receiver.engine_id().is_empty());
        // RFC 3411 format: starts with 0x80 enterprise indicator
        assert_eq!(receiver.engine_id()[0], 0x80);
    }

    #[tokio::test]
    async fn test_builder_generates_engine_id() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .build()
            .await
            .unwrap();
        assert!(!receiver.engine_id().is_empty());
        assert_eq!(receiver.engine_id()[0], 0x80);
    }

    #[tokio::test]
    async fn test_builder_custom_engine_id() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"custom-engine".to_vec())
            .build()
            .await
            .unwrap();
        assert_eq!(receiver.engine_id(), b"custom-engine");
    }
}
