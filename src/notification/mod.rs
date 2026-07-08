//! SNMP Notification Receiver (RFC 3413).
//!
//! This module provides functionality for receiving SNMP notifications:
//! - `TrapV1` (SNMP v1 format, different PDU structure)
//! - `TrapV2`/`SNMPv2-Trap` (SNMP v2c/v3 format)
//! - `InformRequest` (confirmed notification, requires response)
//!
//! # Example
//!
//! Receive v1/v2c notifications. A receiver constructed with `bind` has no
//! USM user table, so v3 notifications are rejected; see below for v3.
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
//! # V3 Notifications
//!
//! To receive V3 traps and `InformRequests`, configure USM credentials via
//! the builder. Only notifications from registered usernames are accepted,
//! at any security level including noAuthNoPriv:
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
//!
//! # Mixed Versions on One Port
//!
//! A single receiver on one UDP port handles v1, v2c, and v3 concurrently;
//! each datagram is dispatched by its version field. Community filtering
//! (v1/v2c) and USM users (v3) are independent and can be configured
//! together — configuring one does not disable the other:
//!
//! ```rust,no_run
//! use async_snmp::notification::NotificationReceiver;
//! use async_snmp::{AuthProtocol, PrivProtocol};
//!
//! # async fn example() -> Result<(), Box<async_snmp::Error>> {
//! let receiver = NotificationReceiver::builder()
//!     .bind("0.0.0.0:162")
//!     .communities(["public", "monitor"]) // gates v1/v2c
//!     .usm_user("trapuser", |u| {          // gates v3
//!         u.auth(AuthProtocol::Sha1, b"authpass123")
//!          .privacy(PrivProtocol::Aes128, b"privpass123")
//!     })
//!     .build()
//!     .await?;
//! # Ok(())
//! # }
//! ```
//!
//! The two mechanisms confer very different trust (a `public` v2c trap versus
//! an authPriv v3 trap arrive on the same socket). Each [`Notification`]
//! variant carries how it was authenticated — the community for v1/v2c, the
//! username and [`security_level`](Notification::security_level) for v3 — so
//! branch on the variant when `recv` returns to apply per-version policy.

mod handlers;
mod types;
mod varbind;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tracing::instrument;

use crate::ber::Decoder;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::message::SecurityLevel;
use crate::oid::Oid;
use crate::pdu::TrapV1Pdu;
use crate::util::bind_udp_socket;
use crate::v3::{EngineState, SaltCounter};
use crate::varbind::VarBind;
use crate::version::Version;

// Re-exports
pub use types::{DerivedKeys, UsmConfig};
pub use varbind::validate_notification_varbinds;

/// Maximum number of distinct remote authoritative engines whose timeliness
/// state is retained for trap senders. A peer holding one USM credential can
/// authenticate under arbitrarily many fabricated engine IDs (keys are
/// localized per engine ID), so the table is bounded and the
/// least-recently-updated engine is evicted when full.
const MAX_REMOTE_ENGINES: usize = 8192;

/// Decide whether a v1/v2c notification carrying `community` is accepted.
///
/// An empty `configured` list accepts any community (filtering is opt-in).
/// Otherwise the community must equal one of the configured strings. The
/// comparison runs against every configured entry without early-out and uses
/// constant-time equality (mirroring `Agent::validate_community`) so a timing
/// side channel cannot be used to recover a valid community byte by byte.
pub(super) fn community_allowed(configured: &[Vec<u8>], community: &[u8]) -> bool {
    if configured.is_empty() {
        return true;
    }
    let mut valid = false;
    for candidate in configured {
        if candidate.len() == community.len() && bool::from(candidate.as_slice().ct_eq(community)) {
            valid = true;
        }
    }
    valid
}

/// Well-known OIDs for notification varbinds.
pub mod oids {
    use crate::oid;

    /// sysUpTime.0 - first varbind in v2c/v3 notifications
    #[must_use]
    pub fn sys_uptime() -> crate::Oid {
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)
    }

    /// snmpTrapOID.0 - second varbind in v2c/v3 notifications (contains trap type)
    #[must_use]
    pub fn snmp_trap_oid() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
    }

    /// snmpTrapEnterprise.0 - optional, enterprise OID for enterprise-specific traps
    #[must_use]
    pub fn snmp_trap_enterprise() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0)
    }

    /// snmpTrapAddress.0 - agent address from v1 trap (RFC 3584 Section 3)
    #[must_use]
    pub fn snmp_trap_address() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 18, 1, 3, 0)
    }

    /// Standard trap OID prefix (snmpTraps)
    #[must_use]
    pub fn snmp_traps() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5)
    }

    /// coldStart trap OID (snmpTraps.1)
    #[must_use]
    pub fn cold_start() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)
    }

    /// warmStart trap OID (snmpTraps.2)
    #[must_use]
    pub fn warm_start() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2)
    }

    /// linkDown trap OID (snmpTraps.3)
    #[must_use]
    pub fn link_down() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)
    }

    /// linkUp trap OID (snmpTraps.4)
    #[must_use]
    pub fn link_up() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4)
    }

    /// authenticationFailure trap OID (snmpTraps.5)
    #[must_use]
    pub fn auth_failure() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5)
    }

    /// egpNeighborLoss trap OID (snmpTraps.6)
    #[must_use]
    pub fn egp_neighbor_loss() -> crate::Oid {
        oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 6)
    }
}

/// Builder for `NotificationReceiver`.
///
/// Configures the bind address, optional community filtering for v1/v2c, and
/// USM credentials for v3. Community filtering and USM users are independent
/// and may be combined; a single receiver then handles all versions on one
/// port. See the [module docs](crate::notification#mixed-versions-on-one-port).
pub struct NotificationReceiverBuilder {
    bind_addr: String,
    usm_users: HashMap<Bytes, UsmConfig>,
    communities: Vec<Vec<u8>>,
    engine_id: Option<Vec<u8>>,
    engine_boots: u32,
}

impl NotificationReceiverBuilder {
    /// Create a new builder with default settings.
    ///
    /// Defaults:
    /// - Bind address: `0.0.0.0:162` (UDP, standard SNMP trap port)
    /// - No USM users (v3 notifications rejected until users are added)
    #[must_use]
    pub fn new() -> Self {
        Self {
            bind_addr: "0.0.0.0:162".to_string(),
            usm_users: HashMap::new(),
            communities: Vec::new(),
            engine_id: None,
            engine_boots: 1,
        }
    }

    /// Set the UDP bind address.
    ///
    /// Default is `0.0.0.0:162` (UDP, standard SNMP trap port).
    #[must_use]
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
    #[must_use]
    pub fn usm_user<F>(mut self, username: impl Into<Bytes>, configure: F) -> Self
    where
        F: FnOnce(UsmConfig) -> UsmConfig,
    {
        let username_bytes: Bytes = username.into();
        let config = configure(UsmConfig::new(username_bytes.clone()));
        self.usm_users.insert(username_bytes, config);
        self
    }

    /// Restrict accepted v1/v2c notifications to the given community string.
    ///
    /// Community filtering is opt-in. With no community configured the
    /// receiver accepts v1/v2c notifications under any community and surfaces
    /// the community on the returned [`Notification`] for caller-side policy.
    /// Once one or more communities are configured, a v1/v2c notification
    /// whose community matches none of them is dropped and never returned
    /// from [`NotificationReceiver::recv`]; a dropped inform is not
    /// acknowledged. Comparison is constant-time. This does not affect v3,
    /// which is gated by USM.
    ///
    /// Call multiple times to accept several communities.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .community(b"public")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn community(mut self, community: &[u8]) -> Self {
        self.communities.push(community.to_vec());
        self
    }

    /// Restrict accepted v1/v2c notifications to any of the given communities.
    ///
    /// Convenience for calling [`Self::community`] once per entry. See that
    /// method for the filtering semantics.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use async_snmp::notification::NotificationReceiver;
    ///
    /// # async fn example() -> Result<(), Box<async_snmp::Error>> {
    /// let receiver = NotificationReceiver::builder()
    ///     .bind("0.0.0.0:162")
    ///     .communities(["public", "monitor"])
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn communities<I, C>(mut self, communities: I) -> Self
    where
        I: IntoIterator<Item = C>,
        C: AsRef<[u8]>,
    {
        for c in communities {
            self.communities.push(c.as_ref().to_vec());
        }
        self
    }

    /// Set the engine ID for `SNMPv3`.
    ///
    /// If not set, a default engine ID will be generated based on the
    /// RFC 3411 format using enterprise number and timestamp.
    #[must_use]
    pub fn engine_id(mut self, engine_id: impl Into<Vec<u8>>) -> Self {
        self.engine_id = Some(engine_id.into());
        self
    }

    /// Set the initial engine boots value.
    ///
    /// This should be persisted across restarts and incremented each time
    /// the receiver starts. Default is 1.
    #[must_use]
    pub fn engine_boots(mut self, boots: u32) -> Self {
        self.engine_boots = boots;
        self
    }

    /// Build the notification receiver.
    pub async fn build(self) -> Result<NotificationReceiver> {
        let bind_addr: SocketAddr = self.bind_addr.parse().map_err(|_| {
            Error::Config(format!("invalid bind address: {}", self.bind_addr).into())
        })?;

        let socket = bind_udp_socket(bind_addr, None, None, false)
            .await
            .map_err(|e| Error::Network {
                target: bind_addr,
                source: e,
            })?;

        let local_addr = socket.local_addr().map_err(|e| Error::Network {
            target: bind_addr,
            source: e,
        })?;

        let engine_id: Bytes = self.engine_id.map_or_else(
            || {
                let mut id = vec![0x80, 0x00, 0x00, 0x00, 0x01];
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                id.extend_from_slice(&timestamp.to_be_bytes());
                Bytes::from(id)
            },
            Bytes::from,
        );

        Ok(NotificationReceiver {
            inner: Arc::new(ReceiverInner {
                socket,
                local_addr,
                usm_users: self.usm_users,
                communities: self.communities,
                engine_id,
                salt_counter: SaltCounter::new(),
                engine_boots_base: self.engine_boots,
                engine_start: Instant::now(),
                usm_unknown_engine_ids: AtomicU32::new(0),
                usm_unknown_usernames: AtomicU32::new(0),
                usm_wrong_digests: AtomicU32::new(0),
                usm_not_in_time_windows: AtomicU32::new(0),
                usm_unsupported_sec_levels: AtomicU32::new(0),
                usm_decryption_errors: AtomicU32::new(0),
                remote_engines: Mutex::new(HashMap::new()),
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
/// - `SNMPv1` Trap (different PDU structure)
/// - SNMPv2c/v3 Trap (standard PDU with sysUpTime.0 and snmpTrapOID.0)
/// - `InformRequest` (confirmed notification, response will be sent automatically)
#[derive(Debug, Clone)]
pub enum Notification {
    /// `SNMPv1` Trap with unique PDU structure.
    TrapV1 {
        /// Community string used for authentication
        community: Bytes,
        /// The trap PDU
        trap: TrapV1Pdu,
    },

    /// `SNMPv2c` Trap (unconfirmed notification).
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

    /// `SNMPv3` Trap (unconfirmed notification).
    TrapV3 {
        /// Username from USM
        username: Bytes,
        /// Context engine ID
        context_engine_id: Bytes,
        /// Context name
        context_name: Bytes,
        /// Security level the message was received at. A `NoAuthNoPriv`
        /// notification is unauthenticated: its username is an unverified
        /// claim. Callers requiring authentication must check this.
        security_level: SecurityLevel,
        /// sysUpTime.0 value
        uptime: u32,
        /// snmpTrapOID.0 value
        trap_oid: Oid,
        /// Additional variable bindings
        varbinds: Vec<VarBind>,
        /// Original request ID
        request_id: i32,
    },

    /// `InformRequest` (confirmed notification) - v2c.
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

    /// `InformRequest` (confirmed notification) - v3.
    ///
    /// A response is automatically sent when this notification is received.
    InformV3 {
        /// Username from USM
        username: Bytes,
        /// Context engine ID
        context_engine_id: Bytes,
        /// Context name
        context_name: Bytes,
        /// Security level the message was received at. A `NoAuthNoPriv`
        /// notification is unauthenticated: its username is an unverified
        /// claim. Callers requiring authentication must check this.
        security_level: SecurityLevel,
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
    /// For `TrapV1`, this is derived from enterprise + generic/specific trap.
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

    /// Get the uptime value (sysUpTime.0 or `time_stamp` for v1).
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

    /// Get the security level the notification was received at.
    ///
    /// Returns `None` for v1/v2c notifications (community-based, no USM
    /// security level). For v3 notifications, `NoAuthNoPriv` means the
    /// message was not authenticated and its username is an unverified
    /// claim.
    pub fn security_level(&self) -> Option<SecurityLevel> {
        match self {
            Notification::TrapV1 { .. }
            | Notification::TrapV2c { .. }
            | Notification::InformV2c { .. } => None,
            Notification::TrapV3 { security_level, .. }
            | Notification::InformV3 { security_level, .. } => Some(*security_level),
        }
    }

    /// Check if this is a confirmed notification (`InformRequest`).
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
/// For `InformRequest` notifications, automatically sends a Response-PDU.
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
    /// Accepted v1/v2c community strings. Empty means accept any community
    /// (community filtering is opt-in); otherwise a v1/v2c notification whose
    /// community matches none of these is dropped.
    communities: Vec<Vec<u8>>,
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
    /// usmStatsUnknownUserNames counter
    usm_unknown_usernames: AtomicU32,
    /// usmStatsWrongDigests counter
    usm_wrong_digests: AtomicU32,
    /// usmStatsNotInTimeWindows counter
    usm_not_in_time_windows: AtomicU32,
    /// usmStatsUnsupportedSecLevels counter
    usm_unsupported_sec_levels: AtomicU32,
    /// usmStatsDecryptionErrors counter
    usm_decryption_errors: AtomicU32,
    /// Timeliness state for remote authoritative engines (trap senders),
    /// keyed by engine ID (RFC 3414 Section 2.3). Seeded from the first
    /// authenticated message from each engine, so only holders of configured
    /// credentials can add entries. Bounded to `MAX_REMOTE_ENGINES` with
    /// least-recently-updated eviction so a credential holder cannot grow it
    /// without limit by fabricating engine IDs.
    remote_engines: Mutex<HashMap<Bytes, EngineState>>,
}

impl NotificationReceiver {
    /// Create a builder for configuring the notification receiver.
    ///
    /// Use this to configure USM credentials for V3 authentication.
    #[must_use]
    pub fn builder() -> NotificationReceiverBuilder {
        NotificationReceiverBuilder::new()
    }

    /// Bind to a local address.
    ///
    /// The standard SNMP notification port is 162.
    ///
    /// A receiver constructed this way handles v1 and v2c notifications
    /// only: it has no USM user table, so every v3 notification (including
    /// noAuthNoPriv) is rejected with `usmStatsUnknownUserNames` (RFC 3414
    /// Section 3.2 Step 4). To receive v3 notifications, use
    /// [`NotificationReceiver::builder()`] and register users with
    /// `usm_user`.
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
            .map_err(|_| Error::Config(format!("invalid bind address: {addr_str}").into()))?;

        let socket = bind_udp_socket(bind_addr, None, None, false)
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
                communities: Vec::new(),
                engine_id,
                salt_counter: SaltCounter::new(),
                engine_boots_base: 1,
                engine_start: Instant::now(),
                usm_unknown_engine_ids: AtomicU32::new(0),
                usm_unknown_usernames: AtomicU32::new(0),
                usm_wrong_digests: AtomicU32::new(0),
                usm_not_in_time_windows: AtomicU32::new(0),
                usm_unsupported_sec_levels: AtomicU32::new(0),
                usm_decryption_errors: AtomicU32::new(0),
                remote_engines: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Get the local address this receiver is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Get the engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &[u8] {
        &self.inner.engine_id
    }

    /// Get the usmStatsUnknownEngineIDs counter value.
    #[must_use]
    pub fn usm_unknown_engine_ids(&self) -> u32 {
        self.inner.usm_unknown_engine_ids.load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnknownUserNames counter value.
    #[must_use]
    pub fn usm_unknown_usernames(&self) -> u32 {
        self.inner.usm_unknown_usernames.load(Ordering::Relaxed)
    }

    /// Get the usmStatsWrongDigests counter value.
    #[must_use]
    pub fn usm_wrong_digests(&self) -> u32 {
        self.inner.usm_wrong_digests.load(Ordering::Relaxed)
    }

    /// Get the usmStatsNotInTimeWindows counter value.
    #[must_use]
    pub fn usm_not_in_time_windows(&self) -> u32 {
        self.inner.usm_not_in_time_windows.load(Ordering::Relaxed)
    }

    /// Get the usmStatsUnsupportedSecLevels counter value.
    #[must_use]
    pub fn usm_unsupported_sec_levels(&self) -> u32 {
        self.inner
            .usm_unsupported_sec_levels
            .load(Ordering::Relaxed)
    }

    /// Get the usmStatsDecryptionErrors counter value.
    #[must_use]
    pub fn usm_decryption_errors(&self) -> u32 {
        self.inner.usm_decryption_errors.load(Ordering::Relaxed)
    }

    /// Receive a notification.
    ///
    /// This method blocks until a notification is received. For `InformRequest`
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
                Ok(None) => {} // Not a notification PDU, ignore
                Err(e) => {
                    // Log parsing error but continue receiving
                    tracing::warn!(target: "async_snmp::notification", { snmp.source = %source, error = %e }, "failed to parse notification");
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
            security_level: SecurityLevel::AuthNoPriv,
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
    fn test_notification_security_level_accessor() {
        let trap_v3 = Notification::TrapV3 {
            username: Bytes::from_static(b"testuser"),
            context_engine_id: Bytes::from_static(b"engine123"),
            context_name: Bytes::new(),
            security_level: SecurityLevel::AuthPriv,
            uptime: 1,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 1,
        };
        assert_eq!(trap_v3.security_level(), Some(SecurityLevel::AuthPriv));

        let inform_v3 = Notification::InformV3 {
            username: Bytes::from_static(b"testuser"),
            context_engine_id: Bytes::from_static(b"engine123"),
            context_name: Bytes::new(),
            security_level: SecurityLevel::NoAuthNoPriv,
            uptime: 1,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 1,
        };
        assert_eq!(
            inform_v3.security_level(),
            Some(SecurityLevel::NoAuthNoPriv)
        );

        let trap_v2c = Notification::TrapV2c {
            community: Bytes::from_static(b"public"),
            uptime: 1,
            trap_oid: oids::cold_start(),
            varbinds: vec![],
            request_id: 1,
        };
        assert_eq!(trap_v2c.security_level(), None);
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

    /// Build a V3 notification message of the given PDU type with the given
    /// `engine_boots` and `engine_time` in the USM parameters. With
    /// `auth: Some((password, protocol))` the message is AuthNoPriv with a
    /// valid HMAC; with `None` it is noAuthNoPriv.
    fn build_v3_notification(
        pdu_type: crate::pdu::PduType,
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        username: &[u8],
        auth: Option<(&[u8], AuthProtocol)>,
    ) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, V3Message};
        use crate::pdu::Pdu;
        use crate::v3::auth::authenticate_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};
        use crate::value::Value;

        let auth_key = auth.map(|(password, protocol)| {
            LocalizedKey::from_password(protocol, password, engine_id).unwrap()
        });

        // Build a notification PDU with sysUpTime.0 and snmpTrapOID.0
        let pdu = Pdu {
            pdu_type,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oids::sys_uptime(), Value::TimeTicks(1000)),
                VarBind::new(
                    oids::snmp_trap_oid(),
                    Value::ObjectIdentifier(oids::cold_start()),
                ),
            ],
        };

        let level = if auth_key.is_some() {
            SecurityLevel::AuthNoPriv
        } else {
            SecurityLevel::NoAuthNoPriv
        };
        // Informs are Confirmed Class and are sent with the reportableFlag
        // set; traps are Unconfirmed Class and are not (RFC 3412 Section 6.4).
        let reportable = pdu_type == crate::pdu::PduType::InformRequest;
        let global = MsgGlobalData::new(1, 65507, MsgFlags::new(level, reportable));

        let mut usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            engine_boots,
            engine_time,
            Bytes::copy_from_slice(username),
        );
        if let Some(key) = &auth_key {
            usm_params = usm_params.with_auth_placeholder(key.mac_len());
        }

        let scoped = ScopedPdu::new(Bytes::copy_from_slice(engine_id), Bytes::new(), pdu);
        let msg = V3Message::new(global, usm_params.encode(), scoped);
        let mut msg_bytes = msg.encode().to_vec();

        // Compute and insert HMAC
        if let Some(key) = &auth_key {
            let (auth_offset, auth_len) =
                UsmSecurityParams::find_auth_params_offset(&msg_bytes).unwrap();
            authenticate_message(key, &mut msg_bytes, auth_offset, auth_len).unwrap();
        }

        Bytes::from(msg_bytes)
    }

    /// Build an authenticated V3 `InformRequest` message with the given
    /// `engine_boots` and `engine_time` in the USM parameters.
    fn build_authed_v3_inform(
        engine_id: &[u8],
        engine_boots: u32,
        engine_time: u32,
        username: &[u8],
        auth_password: &[u8],
        auth_protocol: AuthProtocol,
    ) -> Bytes {
        build_v3_notification(
            crate::pdu::PduType::InformRequest,
            engine_id,
            engine_boots,
            engine_time,
            username,
            Some((auth_password, auth_protocol)),
        )
    }

    /// Build an authenticated V3 `SNMPv2-Trap` message with the given
    /// `engine_boots` and `engine_time` in the USM parameters.
    fn build_authed_v3_trap(engine_id: &[u8], engine_boots: u32, engine_time: u32) -> Bytes {
        build_v3_notification(
            crate::pdu::PduType::TrapV2,
            engine_id,
            engine_boots,
            engine_time,
            b"trapuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        )
    }

    /// Build an unauthenticated (noAuthNoPriv) V3 `SNMPv2-Trap` message.
    fn build_noauth_v3_trap(engine_id: &[u8], username: &[u8]) -> Bytes {
        build_v3_notification(crate::pdu::PduType::TrapV2, engine_id, 0, 0, username, None)
    }

    /// Build a receiver with its own engine ID and a `trapuser` configured,
    /// for tests exercising traps sent under a remote sender's engine ID.
    async fn remote_trap_receiver() -> NotificationReceiver {
        NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .engine_boots(1)
            .usm_user("trapuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap()
    }

    /// For traps the SENDER is the authoritative engine (RFC 3414 Section
    /// 1.5.1): a real remote agent sends under its own engine ID with its
    /// own boots/time. The receiver must accept it without being configured
    /// with the sender's engine ID or clock, and the delivered notification
    /// reports the security level it was received at (RFC 3411 Section
    /// 3.4.3: securityLevel accompanies every message up to the
    /// application).
    #[tokio::test]
    async fn test_v3_trap_from_remote_sender_engine_accepted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Sender's own engine ID, arbitrary boots and time
        let msg = build_authed_v3_trap(b"remote-sender-engine", 7, 123_456);

        let result = receiver.handle_v3(msg, source).await.unwrap();
        match result {
            Some(Notification::TrapV3 {
                username,
                security_level,
                ..
            }) => {
                assert_eq!(username.as_ref(), b"trapuser");
                assert_eq!(security_level, SecurityLevel::AuthNoPriv);
            }
            other => panic!("expected TrapV3, got {other:?}"),
        }
    }

    /// A noAuthNoPriv V3 trap from a configured user is delivered (no
    /// per-user minimum is enforced here) but must be distinguishable from
    /// an authenticated one via its security level.
    #[tokio::test]
    async fn test_v3_noauth_trap_carries_security_level() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_noauth_v3_trap(b"remote-sender-engine", b"trapuser");
        match receiver.handle_v3(msg, source).await.unwrap() {
            Some(Notification::TrapV3 {
                security_level,
                username,
                ..
            }) => {
                assert_eq!(security_level, SecurityLevel::NoAuthNoPriv);
                assert_eq!(username.as_ref(), b"trapuser");
            }
            other => panic!("expected TrapV3, got {other:?}"),
        }
    }

    /// RFC 3414 Section 3.2 Step 4 is unconditional: the user must exist in
    /// the local configuration regardless of security level, so a
    /// noAuthNoPriv message from an unknown user is dropped and counted,
    /// not delivered.
    #[tokio::test]
    async fn test_v3_noauth_trap_unknown_user_rejected_and_counted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_noauth_v3_trap(b"remote-sender-engine", b"nosuchuser");
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none(), "unknown user must not be delivered");
        assert_eq!(receiver.usm_unknown_usernames(), 1);
    }

    /// Each remote engine gets independent timeliness state: traps from
    /// multiple senders with unrelated boots/time are all accepted.
    #[tokio::test]
    async fn test_v3_traps_from_multiple_remote_engines_accepted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg_a = build_authed_v3_trap(b"sender-engine-a", 7, 123_456);
        let msg_b = build_authed_v3_trap(b"sender-engine-b", 2, 42);

        assert!(
            receiver.handle_v3(msg_a, source).await.unwrap().is_some(),
            "trap from first remote engine should be accepted"
        );
        assert!(
            receiver.handle_v3(msg_b, source).await.unwrap().is_some(),
            "trap from second remote engine should be accepted"
        );
    }

    /// The remote-engine table is bounded: once `MAX_REMOTE_ENGINES` entries
    /// exist, an authenticated trap under a new engine ID evicts an old entry
    /// rather than growing the map, so a credential holder cannot exhaust
    /// memory by fabricating engine IDs.
    #[tokio::test]
    async fn test_v3_remote_engines_table_bounded() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        // Pre-fill the table to capacity with cheap dummy entries.
        {
            let mut engines = receiver.inner.remote_engines.lock().unwrap();
            for i in 0..MAX_REMOTE_ENGINES {
                let id = Bytes::from(format!("dummy-engine-{i}"));
                engines.insert(id.clone(), EngineState::new(id, 1, 1));
            }
            assert_eq!(engines.len(), MAX_REMOTE_ENGINES);
        }

        // An authenticated trap under a not-yet-seen engine ID is accepted.
        let msg = build_authed_v3_trap(b"fresh-remote-engine", 7, 123_456);
        assert!(receiver.handle_v3(msg, source).await.unwrap().is_some());

        // The table stayed at capacity (an old entry was evicted) and the new
        // engine is now tracked.
        let engines = receiver.inner.remote_engines.lock().unwrap();
        assert_eq!(engines.len(), MAX_REMOTE_ENGINES);
        assert!(engines.contains_key(&Bytes::from_static(b"fresh-remote-engine")));
    }

    /// A replayed (stale) trap from a known remote engine is rejected:
    /// its engine time is more than 150 seconds behind the local notion
    /// established by an earlier authentic message (RFC 3414 Section 3.2
    /// Step 7b).
    #[tokio::test]
    async fn test_v3_trap_remote_engine_stale_time_rejected() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(fresh, source).await.unwrap().is_some());

        // Same boots, time far behind the notion just established
        let stale = build_authed_v3_trap(b"remote-sender-engine", 7, 5_000);
        assert!(
            receiver.handle_v3(stale, source).await.is_err(),
            "stale engine time should be rejected as outside the time window"
        );
    }

    /// A trap claiming an older boot cycle than previously seen is rejected.
    #[tokio::test]
    async fn test_v3_trap_remote_engine_old_boots_rejected() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(fresh, source).await.unwrap().is_some());

        let old_boots = build_authed_v3_trap(b"remote-sender-engine", 6, 99_999);
        assert!(
            receiver.handle_v3(old_boots, source).await.is_err(),
            "older boot cycle should be rejected"
        );
    }

    /// A sender reboot (higher boots, low time) is tolerated and updates
    /// the local notion; the previous boot cycle is then rejected.
    #[tokio::test]
    async fn test_v3_trap_remote_engine_reboot_accepted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let before = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(before, source).await.unwrap().is_some());

        let after_reboot = build_authed_v3_trap(b"remote-sender-engine", 8, 5);
        assert!(
            receiver
                .handle_v3(after_reboot, source)
                .await
                .unwrap()
                .is_some(),
            "trap after sender reboot should be accepted"
        );

        let from_old_cycle = build_authed_v3_trap(b"remote-sender-engine", 7, 20_000);
        assert!(
            receiver.handle_v3(from_old_cycle, source).await.is_err(),
            "trap from superseded boot cycle should be rejected"
        );
    }

    /// A trap with a bad HMAC from an unknown remote engine must not seed
    /// timeliness state or be accepted.
    #[tokio::test]
    async fn test_v3_trap_remote_engine_bad_auth_rejected() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"trapuser",
            Some((b"wrong-password-1234", AuthProtocol::Sha1)),
        );
        assert!(
            receiver.handle_v3(msg, source).await.is_err(),
            "trap with wrong auth key should be rejected"
        );

        // A correctly authenticated trap still works afterwards
        let good = build_authed_v3_trap(b"remote-sender-engine", 7, 123_456);
        assert!(receiver.handle_v3(good, source).await.unwrap().is_some());
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
        assert!(
            result.is_err(),
            "message with engine_time=5000 should be rejected (outside 150s window)"
        );
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
        assert!(
            result.is_err(),
            "message with wrong engine_boots should be rejected"
        );
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
                let err_str = format!("{e}");
                assert!(
                    !err_str.contains("Auth"),
                    "should not be an auth error for valid time window, got: {err_str}"
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
        use crate::message::V3Message;
        use crate::v3::UsmSecurityParams;
        use crate::value::Value;

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-discovery-engine".to_vec())
            .build()
            .await
            .unwrap();

        // Bind a separate socket to receive the Report; handle_v3 is called
        // directly with this socket's address as source.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let discovery_msg = build_v3_discovery_request(42, true);
        let result = receiver.handle_v3(discovery_msg, client_addr).await;

        // Discovery should return Ok(None) - not a notification
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Counter should be incremented
        assert_eq!(receiver.usm_unknown_engine_ids(), 1);

        // The Report must carry usmStatsUnknownEngineIDs with the counter
        // value and the receiver's engine ID (RFC 3414 Section 4).
        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a discovery Report")
        .unwrap();

        let report = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
        assert_eq!(report_usm.engine_id.as_ref(), b"test-discovery-engine");
        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(scoped.pdu.pdu_type, crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_engine_ids()
        );
        assert_eq!(scoped.pdu.varbinds[0].value, Value::Counter32(1));
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

        // A non-reportable message with an unknown (empty) engine ID gets no
        // response, but the counter tracks the occurrence like every other
        // usmStats counter.
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(receiver.usm_unknown_engine_ids(), 1);
    }

    /// A message under an engine ID other than the receiver's own is treated
    /// as coming from a remote authoritative engine (RFC 3414 Section 3.2
    /// Step 7b): authentication uses keys localized to that engine ID and
    /// timeliness uses per-engine state, so it is accepted rather than
    /// requiring the receiver to be configured with the sender's engine ID.
    #[tokio::test]
    async fn test_v3_inform_under_remote_engine_id_accepted() {
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
            b"remote-engine-id",
            1,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );

        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(
            matches!(result, Some(Notification::InformV3 { .. })),
            "authenticated inform under a remote engine ID should be accepted, got {result:?}"
        );
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

    #[tokio::test]
    async fn test_usm_counter_accessors_default_zero() {
        let receiver = remote_trap_receiver().await;
        assert_eq!(receiver.usm_unknown_engine_ids(), 0);
        assert_eq!(receiver.usm_unknown_usernames(), 0);
        assert_eq!(receiver.usm_wrong_digests(), 0);
        assert_eq!(receiver.usm_not_in_time_windows(), 0);
        assert_eq!(receiver.usm_unsupported_sec_levels(), 0);
        assert_eq!(receiver.usm_decryption_errors(), 0);
    }

    /// RFC 3414 Section 3.2 Step 6: a failed HMAC increments
    /// usmStatsWrongDigests.
    #[tokio::test]
    async fn test_v3_trap_wrong_digest_increments_counter() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"trapuser",
            Some((b"wrong-password-1234", AuthProtocol::Sha1)),
        );
        assert!(receiver.handle_v3(msg, source).await.is_err());
        assert_eq!(receiver.usm_wrong_digests(), 1);
    }

    /// RFC 3414 Section 3.2 Step 4: an authenticated message for a user not
    /// in the local configuration increments usmStatsUnknownUserNames.
    #[tokio::test]
    async fn test_v3_trap_unknown_user_increments_counter() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"nosuchuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none(), "unknown user must not be delivered");
        assert_eq!(receiver.usm_unknown_usernames(), 1);
        assert_eq!(receiver.usm_wrong_digests(), 0);
    }

    /// RFC 3414 Section 3.2 Step 5: an authenticated message for a user
    /// configured without an auth key increments
    /// usmStatsUnsupportedSecLevels.
    #[tokio::test]
    async fn test_v3_trap_user_without_auth_key_increments_counter() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .usm_user("plainuser", |u| u)
            .build()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"plainuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unsupported_sec_levels(), 1);
        assert_eq!(receiver.usm_unknown_usernames(), 0);
    }

    /// RFC 3414 Section 3.2 Step 7a: an inform under the receiver's engine ID
    /// outside the time window increments usmStatsNotInTimeWindows.
    #[tokio::test]
    async fn test_v3_inform_time_window_failure_increments_counter() {
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
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            1,
            5000,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        assert!(receiver.handle_v3(msg, source).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 1);
    }

    /// RFC 3414 Section 3.2 Step 7b: when the sender is the authoritative
    /// engine, a timeliness failure is a bare error indication.
    /// usmStatsNotInTimeWindows and its Report belong to the authoritative
    /// case (Step 7a) only, matching net-snmp's
    /// usm_check_and_update_timeliness.
    #[tokio::test]
    async fn test_v3_trap_remote_stale_not_counted() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let fresh = build_authed_v3_trap(b"remote-sender-engine", 7, 10_000);
        assert!(receiver.handle_v3(fresh, source).await.unwrap().is_some());

        let stale = build_authed_v3_trap(b"remote-sender-engine", 7, 5_000);
        assert!(receiver.handle_v3(stale, source).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 0);
    }

    /// A stale inform under a remote sender's engine ID (Step 7b) gets no
    /// notInTimeWindows Report even though its reportableFlag is set: the
    /// receiver is not authoritative for that engine's clock.
    #[tokio::test]
    async fn test_v3_inform_remote_stale_gets_no_report() {
        let receiver = remote_trap_receiver().await;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let fresh = build_v3_notification(
            crate::pdu::PduType::InformRequest,
            b"remote-sender-engine",
            7,
            10_000,
            b"trapuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        assert!(
            receiver
                .handle_v3(fresh, client_addr)
                .await
                .unwrap()
                .is_some()
        );

        // Drain the inform acknowledgement.
        let mut buf = vec![0u8; 4096];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected the inform response")
        .unwrap();

        let stale = build_v3_notification(
            crate::pdu::PduType::InformRequest,
            b"remote-sender-engine",
            7,
            5_000,
            b"trapuser",
            Some((b"authpass12345678", AuthProtocol::Sha1)),
        );
        assert!(receiver.handle_v3(stale, client_addr).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 0);

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(
            result.is_err(),
            "no Report may be sent for a Step 7b timeliness failure"
        );
    }

    /// Build an authPriv V3 trap for the given username, HMAC'd with the
    /// given password, with undecryptable privacy parameters (wrong salt
    /// length) and garbage ciphertext.
    fn build_v3_trap_bad_ciphertext(
        engine_id: &[u8],
        username: &[u8],
        auth_password: &[u8],
    ) -> Bytes {
        use crate::message::{MsgFlags, MsgGlobalData, V3Message};
        use crate::v3::auth::authenticate_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};

        let auth_key =
            LocalizedKey::from_password(AuthProtocol::Sha1, auth_password, engine_id).unwrap();

        let global = MsgGlobalData::new(1, 65507, MsgFlags::new(SecurityLevel::AuthPriv, false));
        let usm_params = UsmSecurityParams::new(
            Bytes::copy_from_slice(engine_id),
            7,
            123_456,
            Bytes::copy_from_slice(username),
        )
        .with_auth_placeholder(auth_key.mac_len())
        .with_priv_params(Bytes::from_static(b"bad"));

        let msg = V3Message::new_encrypted(
            global,
            usm_params.encode(),
            Bytes::from_static(b"not-a-valid-ciphertext"),
        );
        let mut msg_bytes = msg.encode().to_vec();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&msg_bytes).unwrap();
        authenticate_message(&auth_key, &mut msg_bytes, auth_offset, auth_len).unwrap();
        Bytes::from(msg_bytes)
    }

    /// RFC 3414 Section 3.2 Step 8: a decryption failure increments
    /// usmStatsDecryptionErrors.
    #[tokio::test]
    async fn test_v3_decryption_error_increments_counter() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"my-receiver-engine".to_vec())
            .usm_user("privuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
                    .privacy(crate::v3::PrivProtocol::Aes128, b"privpass12345678")
            })
            .build()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg =
            build_v3_trap_bad_ciphertext(b"remote-sender-engine", b"privuser", b"authpass12345678");
        assert!(receiver.handle_v3(msg, source).await.is_err());
        assert_eq!(receiver.usm_decryption_errors(), 1);
    }

    /// RFC 3414 Section 3.2 Step 5 precedes Step 6: an authPriv message for
    /// a user configured without privacy increments
    /// usmStatsUnsupportedSecLevels even when its HMAC is invalid, not
    /// usmStatsWrongDigests.
    #[tokio::test]
    async fn test_v3_authpriv_for_auth_only_user_counts_unsupported_sec_level() {
        let receiver = remote_trap_receiver().await;
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let msg = build_v3_trap_bad_ciphertext(
            b"remote-sender-engine",
            b"trapuser",
            b"wrong-password-1234",
        );
        let result = receiver.handle_v3(msg, source).await.unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unsupported_sec_levels(), 1);
        assert_eq!(receiver.usm_wrong_digests(), 0);
    }

    /// A USM-failed inform (Confirmed Class, reportableFlag set) gets a
    /// Report back (RFC 3412 Section 7.1 Step 3). The notInTimeWindows
    /// report carries the receiver's engine ID/boots/time for time
    /// resynchronization and is authenticated at authNoPriv
    /// (RFC 3414 Section 3.2 Step 7).
    #[tokio::test]
    async fn test_v3_failed_inform_gets_authenticated_time_window_report() {
        use crate::message::V3Message;
        use crate::v3::auth::verify_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};

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

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            1,
            5000, // outside the 150s window
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        assert!(receiver.handle_v3(msg, client_addr).await.is_err());

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a Report in response to the failed inform")
        .unwrap();
        let report_bytes = Bytes::copy_from_slice(&buf[..len]);

        let report = V3Message::decode(report_bytes.clone()).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::AuthNoPriv,
            "notInTimeWindows report must be authenticated (authNoPriv)"
        );
        assert!(!report.global_data.msg_flags.reportable);

        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
        assert_eq!(report_usm.engine_id.as_ref(), b"test-engine");

        // The HMAC must verify with the user's key localized to the
        // receiver's engine ID.
        let key =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"authpass12345678", b"test-engine")
                .unwrap();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&report_bytes).unwrap();
        assert!(verify_message(&key, &report_bytes, auth_offset, auth_len).unwrap());

        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(scoped.pdu.pdu_type, crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::not_in_time_windows()
        );
    }

    /// RFC 3414 Section 3.2 Step 7a lists latched engine boots as a Time
    /// Window failure and mandates the report be authenticated at
    /// authNoPriv, like the other notInTimeWindows reports.
    #[tokio::test]
    async fn test_v3_latched_boots_report_is_authenticated() {
        use crate::message::V3Message;
        use crate::v3::MAX_ENGINE_TIME;
        use crate::v3::auth::verify_message;
        use crate::v3::{LocalizedKey, UsmSecurityParams};

        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .engine_id(b"test-engine".to_vec())
            .engine_boots(MAX_ENGINE_TIME)
            .usm_user("informuser", |u| {
                u.auth(AuthProtocol::Sha1, b"authpass12345678")
            })
            .build()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            MAX_ENGINE_TIME,
            0,
            b"informuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        assert!(receiver.handle_v3(msg, client_addr).await.is_err());
        assert_eq!(receiver.usm_not_in_time_windows(), 1);

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a Report in response to the failed inform")
        .unwrap();
        let report_bytes = Bytes::copy_from_slice(&buf[..len]);

        let report = V3Message::decode(report_bytes.clone()).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::AuthNoPriv,
            "notInTimeWindows report must be authenticated (authNoPriv)"
        );
        let key =
            LocalizedKey::from_password(AuthProtocol::Sha1, b"authpass12345678", b"test-engine")
                .unwrap();
        let (auth_offset, auth_len) =
            UsmSecurityParams::find_auth_params_offset(&report_bytes).unwrap();
        assert!(verify_message(&key, &report_bytes, auth_offset, auth_len).unwrap());

        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::not_in_time_windows()
        );
    }

    /// A USM-failed inform for an unknown user gets an unauthenticated
    /// Report (no key exists to authenticate it with).
    #[tokio::test]
    async fn test_v3_failed_inform_unknown_user_gets_noauth_report() {
        use crate::message::V3Message;
        use crate::v3::UsmSecurityParams;

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

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_authed_v3_inform(
            b"test-engine",
            1,
            0,
            b"nosuchuser",
            b"authpass12345678",
            AuthProtocol::Sha1,
        );
        let result = receiver.handle_v3(msg, client_addr).await.unwrap();
        assert!(result.is_none());
        assert_eq!(receiver.usm_unknown_usernames(), 1);

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("expected a Report in response to the failed inform")
        .unwrap();

        let report = V3Message::decode(Bytes::copy_from_slice(&buf[..len])).unwrap();
        assert_eq!(
            report.global_data.msg_flags.security_level,
            SecurityLevel::NoAuthNoPriv
        );
        let report_usm = UsmSecurityParams::decode(report.security_params.clone()).unwrap();
        assert_eq!(report_usm.engine_id.as_ref(), b"test-engine");
        let scoped = report.scoped_pdu().expect("report should be plaintext");
        assert_eq!(scoped.pdu.pdu_type, crate::pdu::PduType::Report);
        assert_eq!(
            scoped.pdu.varbinds[0].oid,
            crate::v3::report_oids::unknown_user_names()
        );
    }

    /// A USM-failed trap must NOT get a Report: traps are Unconfirmed Class
    /// and carry reportableFlag=0 (RFC 3412 Sections 6.4 and 7.1 Step 3).
    #[tokio::test]
    async fn test_v3_failed_trap_gets_no_report() {
        let receiver = remote_trap_receiver().await;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let msg = build_v3_notification(
            crate::pdu::PduType::TrapV2,
            b"remote-sender-engine",
            7,
            123_456,
            b"trapuser",
            Some((b"wrong-password-1234", AuthProtocol::Sha1)),
        );
        assert!(receiver.handle_v3(msg, client_addr).await.is_err());
        assert_eq!(receiver.usm_wrong_digests(), 1);

        let mut buf = vec![0u8; 4096];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(result.is_err(), "no Report may be sent for a failed trap");
    }

    #[test]
    fn test_community_allowed() {
        // Empty allowlist accepts any community (opt-in filtering).
        assert!(community_allowed(&[], b"public"));
        assert!(community_allowed(&[], b""));

        let configured = vec![b"public".to_vec(), b"monitor".to_vec()];
        assert!(community_allowed(&configured, b"public"));
        assert!(community_allowed(&configured, b"monitor"));
        // Non-matching, prefix, and length-mismatch are all rejected.
        assert!(!community_allowed(&configured, b"private"));
        assert!(!community_allowed(&configured, b"pub"));
        assert!(!community_allowed(&configured, b"publicx"));
        assert!(!community_allowed(&configured, b""));
    }

    fn build_v2c_trap(community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;
        let pdu = Pdu::trap_v2(1, 100, &oids::cold_start(), vec![]);
        CommunityMessage::v2c(Bytes::copy_from_slice(community), pdu).encode()
    }

    fn build_v2c_inform(community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::Pdu;
        let pdu = Pdu::inform_request(1, 100, &oids::cold_start(), vec![]);
        CommunityMessage::v2c(Bytes::copy_from_slice(community), pdu).encode()
    }

    fn build_v1_trap(community: &[u8]) -> Bytes {
        use crate::message::CommunityMessage;
        use crate::pdu::GenericTrap;
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::ColdStart,
            0,
            12345,
            vec![],
        );
        CommunityMessage::v1_trap(Bytes::copy_from_slice(community), trap).encode()
    }

    #[tokio::test]
    async fn test_v2c_trap_matching_community_accepted() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"public"), source)
            .await
            .unwrap();
        assert!(matches!(result, Some(Notification::TrapV2c { .. })));
    }

    #[tokio::test]
    async fn test_v2c_trap_wrong_community_dropped() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"private"), source)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_v2c_trap_no_allowlist_accepts_any_community() {
        let receiver = NotificationReceiver::bind("127.0.0.1:0").await.unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_trap(b"anything"), source)
            .await
            .unwrap();
        assert!(matches!(result, Some(Notification::TrapV2c { .. })));
    }

    #[tokio::test]
    async fn test_v1_trap_wrong_community_dropped() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();
        let source: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        assert!(
            receiver
                .handle_v1(build_v1_trap(b"private"), source)
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            receiver
                .handle_v1(build_v1_trap(b"public"), source)
                .await
                .unwrap(),
            Some(Notification::TrapV1 { .. })
        ));
    }

    /// An inform rejected by the community filter is dropped before the ack is
    /// built, so no Response datagram is sent to the source.
    #[tokio::test]
    async fn test_v2c_inform_wrong_community_dropped_without_ack() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_inform(b"private"), client_addr)
            .await
            .unwrap();
        assert!(result.is_none());

        let mut buf = vec![0u8; 4096];
        let recv = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            client.recv_from(&mut buf),
        )
        .await;
        assert!(recv.is_err(), "a filtered inform must not be acknowledged");
    }

    /// A matching inform is still acknowledged (the filter does not suppress
    /// valid acks).
    #[tokio::test]
    async fn test_v2c_inform_matching_community_acked() {
        let receiver = NotificationReceiver::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .build()
            .await
            .unwrap();

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        let result = receiver
            .handle_v2c(build_v2c_inform(b"public"), client_addr)
            .await
            .unwrap();
        assert!(matches!(result, Some(Notification::InformV2c { .. })));

        let mut buf = vec![0u8; 4096];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client.recv_from(&mut buf),
        )
        .await
        .expect("a matching inform must be acknowledged")
        .unwrap();
        assert!(len > 0);
    }
}
