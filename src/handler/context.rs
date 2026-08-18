//! Request context for MIB handlers.
//!
//! [`RequestContext`] contains incoming request information for handler
//! authorization decisions and cooperative deadline and shutdown handling.

use std::net::SocketAddr;

use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

use crate::Community;
use crate::DecodeAnomaly;
use crate::message::SecurityLevel;
use crate::pdu::PduType;
use crate::version::{CommunityVersion, Version};

use super::SecurityModel;

/// A request's model-specific security name.
///
/// Community variants retain transitive Debug redaction, while USM usernames
/// remain visible in diagnostics.
#[derive(Debug, Clone)]
pub enum SecurityName {
    /// SNMPv1/v2c community identifier.
    Community(Community),
    /// SNMPv3 USM username.
    Usm(Bytes),
}

impl SecurityName {
    /// Return the protocol bytes for authorization and sizing.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Community(community) => community.as_bytes(),
            Self::Usm(username) => username,
        }
    }

    /// Return the length of the security name in octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    /// Return whether the security name is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Return whether `candidate` is the same kind of security name with the
    /// same protocol octets.
    ///
    /// Community names match only community names, and USM usernames match
    /// only USM usernames. For same-variant, equal-length inputs, comparison
    /// time does not depend on the octet values. Variant and length are not
    /// concealed and a mismatch in either may return sooner.
    ///
    /// This comparison alone is not a complete authorization decision. A
    /// handler must also check [`RequestContext::security_model`] to
    /// distinguish SNMPv1 communities, SNMPv2c communities, and USM users. USM
    /// authorization should additionally require the appropriate
    /// [`RequestContext::security_level`], because `noAuthNoPriv` usernames are
    /// not authenticated.
    #[must_use]
    pub fn matches(&self, candidate: &Self) -> bool {
        match (self, candidate) {
            (Self::Community(expected), Self::Community(actual)) => {
                expected.matches(actual.as_bytes())
            }
            (Self::Usm(expected), Self::Usm(actual)) => {
                expected.len() == actual.len()
                    && bool::from(expected.as_ref().ct_eq(actual.as_ref()))
            }
            (Self::Community(_), Self::Usm(_)) | (Self::Usm(_), Self::Community(_)) => false,
        }
    }
}

/// Request context passed to MIB handlers.
///
/// Contains information about the incoming request for authorization decisions,
/// including VACM-resolved access control information when VACM is enabled.
/// Receipt and admission timestamps expose concurrency queueing, while the
/// optional absolute deadline and level-triggered token let handlers propagate
/// cooperative cancellation into downstream work. Cancellation is advisory:
/// it does not itself drop a handler future.
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, HandlerResult, BoxFuture};
/// use async_snmp::{Oid, Value, oid};
///
/// struct LoggingHandler;
///
/// impl MibHandler for LoggingHandler {
///     fn get<'a>(&'a self, ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
///         Box::pin(async move {
///             // Log request details
///             println!(
///                 "GET {} from {} (user: {:?}, version: {:?})",
///                 oid, ctx.source(), ctx.security_name(), ctx.version()
///             );
///
///             if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
///                 Ok(GetResult::Value(Value::Integer(42)))
///             } else {
///                 Ok(GetResult::NoSuchObject)
///             }
///         })
///     }
///
///     fn get_next<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         _oid: &'a Oid,
///     ) -> BoxFuture<'a, HandlerResult<async_snmp::handler::GetNextResult>> {
///         Box::pin(async { Ok(async_snmp::handler::GetNextResult::EndOfMibView) })
///     }
/// }
/// ```
///
/// Authorization code should match both the security model and name, and for
/// USM should require a security level that authenticates the username:
///
/// ```rust
/// use async_snmp::{Community, RequestContext, SecurityLevel, SecurityModel, SecurityName};
///
/// fn may_read_v2c(ctx: &RequestContext) -> bool {
///     let reader = SecurityName::Community(Community::from(b"reader\xff"));
///     ctx.security_model() == SecurityModel::V2c && ctx.security_name().matches(&reader)
/// }
///
/// fn may_write(ctx: &RequestContext) -> bool {
///     let operator = SecurityName::Usm(bytes::Bytes::from_static(b"operator\xff"));
///     ctx.security_model() == SecurityModel::Usm
///         && matches!(ctx.security_level(), SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv)
///         && ctx.security_name().matches(&operator)
/// }
/// ```
///
/// A context is created by the agent from a validated incoming request. Its
/// fields cannot be replaced or combined into states that are impossible on
/// the wire:
///
/// ```compile_fail,E0616
/// use async_snmp::{RequestContext, Version};
///
/// fn change_version(ctx: &mut RequestContext) {
///     ctx.version = Version::V1;
/// }
/// ```
///
/// ```compile_fail,E0599
/// use async_snmp::RequestContext;
///
/// let _ctx = RequestContext::test_context();
/// ```
///
/// ```compile_fail,E0451
/// use async_snmp::RequestContext;
///
/// let _ctx = RequestContext {
///     source: "127.0.0.1:161".parse().unwrap(),
///     ..unimplemented!()
/// };
/// ```
///
/// # Testing handlers
///
/// `RequestContext` has no public constructor because the agent derives it
/// from a validated request and successful authorization. Keep pure handler
/// policy in helpers that take only the values they need. When a test needs a
/// complete context, run an in-process [`crate::Agent`] and capture the context
/// passed to a test handler.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Monotonic instant when the datagram was received.
    received_at: tokio::time::Instant,

    /// Monotonic instant when request processing was admitted.
    admitted_at: tokio::time::Instant,

    /// Absolute request deadline measured from receipt.
    deadline: Option<tokio::time::Instant>,

    /// Level-triggered advisory cancellation for this request.
    cancellation: CancellationToken,

    /// Agent-owned phase record used to protect mutation cleanup.
    phase: Arc<AtomicU8>,

    /// Source address of the request.
    ///
    /// Use this for logging or additional access control beyond VACM.
    source: SocketAddr,

    /// SNMP version (V1, V2c, or V3).
    version: Version,

    /// Security model used for this request.
    ///
    /// - `V1` for `SNMPv1` community-based
    /// - `V2c` for `SNMPv2c` community-based
    /// - `Usm` for `SNMPv3` User-based Security Model
    security_model: SecurityModel,

    /// Model-specific community identifier or USM username.
    security_name: SecurityName,

    /// Security level (v3 only, `NoAuthNoPriv` for v1/v2c).
    ///
    /// Indicates whether authentication and/or privacy were used.
    security_level: SecurityLevel,

    /// Context name (v3 only, empty for v1/v2c).
    ///
    /// `SNMPv3` contexts allow partitioning MIB views.
    context_name: Bytes,

    /// Request ID from the PDU.
    ///
    /// Useful for correlating requests with responses in logs.
    request_id: i32,

    /// PDU type (`GetRequest`, `GetNextRequest`, `SetRequest`, etc.).
    pdu_type: PduType,

    /// Resolved group name (if VACM enabled).
    ///
    /// Set when VACM successfully maps the security name to a group.
    group_name: Option<Bytes>,

    /// Read view name (if VACM enabled).
    ///
    /// The view that controls which OIDs can be read.
    read_view: Option<Bytes>,

    /// Write view name (if VACM enabled).
    ///
    /// The view that controls which OIDs can be written.
    write_view: Option<Bytes>,

    /// Client-advertised maximum message size (V3 only).
    ///
    /// For `SNMPv3` requests, this is the msgMaxSize from the V3 message header,
    /// indicating the largest message the client can accept. The agent should
    /// limit response sizes to `min(agent_max, msg_max_size)`.
    ///
    /// None for v1/v2c requests (no msgMaxSize field in those versions).
    msg_max_size: Option<usize>,

    /// Accepted non-canonical encodings in stable wire-processing order.
    ///
    /// Community request anomalies are unauthenticated. V3 anomalies within
    /// the declared envelope are exposed only after USM processing succeeds
    /// and are attributable to the configured user only at `authNoPriv` or
    /// `authPriv`. A top-level trailing-byte anomaly remains unauthenticated.
    decode_anomalies: Vec<DecodeAnomaly>,
}

impl RequestContext {
    #[cfg(test)]
    pub(crate) fn community(
        source: SocketAddr,
        version: CommunityVersion,
        community: Community,
        request_id: i32,
        pdu_type: PduType,
        decode_anomalies: Vec<DecodeAnomaly>,
    ) -> Self {
        Self::community_with_lifecycle(
            source,
            version,
            community,
            request_id,
            pdu_type,
            decode_anomalies,
            RequestLifecycle::for_test(pdu_type),
        )
    }

    pub(crate) fn community_with_lifecycle(
        source: SocketAddr,
        version: CommunityVersion,
        community: Community,
        request_id: i32,
        pdu_type: PduType,
        decode_anomalies: Vec<DecodeAnomaly>,
        lifecycle: RequestLifecycle,
    ) -> Self {
        let (version, security_model) = match version {
            CommunityVersion::V1 => (Version::V1, SecurityModel::V1),
            CommunityVersion::V2c => (Version::V2c, SecurityModel::V2c),
        };
        lifecycle.classify(pdu_type);
        Self {
            received_at: lifecycle.received_at,
            admitted_at: lifecycle.admitted_at,
            deadline: lifecycle.deadline,
            cancellation: lifecycle.cancellation,
            phase: lifecycle.phase,
            source,
            version,
            security_model,
            security_name: SecurityName::Community(community),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id,
            pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: None,
            decode_anomalies,
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn usm(
        source: SocketAddr,
        username: Bytes,
        security_level: SecurityLevel,
        context_name: Bytes,
        request_id: i32,
        pdu_type: PduType,
        msg_max_size: usize,
        decode_anomalies: Vec<DecodeAnomaly>,
    ) -> Self {
        Self::usm_with_lifecycle(
            source,
            username,
            security_level,
            context_name,
            request_id,
            pdu_type,
            msg_max_size,
            decode_anomalies,
            RequestLifecycle::for_test(pdu_type),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn usm_with_lifecycle(
        source: SocketAddr,
        username: Bytes,
        security_level: SecurityLevel,
        context_name: Bytes,
        request_id: i32,
        pdu_type: PduType,
        msg_max_size: usize,
        decode_anomalies: Vec<DecodeAnomaly>,
        lifecycle: RequestLifecycle,
    ) -> Self {
        lifecycle.classify(pdu_type);
        Self {
            received_at: lifecycle.received_at,
            admitted_at: lifecycle.admitted_at,
            deadline: lifecycle.deadline,
            cancellation: lifecycle.cancellation,
            phase: lifecycle.phase,
            source,
            version: Version::V3,
            security_model: SecurityModel::Usm,
            security_name: SecurityName::Usm(username),
            security_level,
            context_name,
            request_id,
            pdu_type,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: Some(msg_max_size),
            decode_anomalies,
        }
    }

    /// Return the monotonic instant when the request datagram was received.
    #[must_use]
    pub const fn received_at(&self) -> tokio::time::Instant {
        self.received_at
    }

    /// Return the monotonic instant when the request received an execution permit.
    #[must_use]
    pub const fn admitted_at(&self) -> tokio::time::Instant {
        self.admitted_at
    }

    /// Return the absolute request deadline, measured from receipt.
    #[must_use]
    pub const fn deadline(&self) -> Option<tokio::time::Instant> {
        self.deadline
    }

    /// Clone the level-triggered advisory cancellation signal.
    ///
    /// The token is cancelled when the request deadline expires or agent
    /// shutdown begins. Cancellation-aware handlers should return normally
    /// after releasing their own resources. For SET, cancellation is observed
    /// before commit; once commit begins, undo, free, and finalize callbacks
    /// remain protected and must run to completion even though this token stays
    /// cancelled.
    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    /// Return whether request cancellation has already been signalled.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Wait until request cancellation is signalled.
    ///
    /// This is advisory. In a protected SET terminal callback it remains
    /// signalled but does not authorize abandoning rollback or cleanup.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    pub(crate) fn protect_set(&self) {
        self.phase
            .store(RequestTaskPhase::SetProtected as u8, Ordering::Release);
    }

    pub(crate) fn set_vacm_access(
        &mut self,
        group_name: Bytes,
        read_view: Bytes,
        write_view: Bytes,
    ) {
        self.group_name = Some(group_name);
        self.read_view = Some(read_view);
        self.write_view = Some(write_view);
    }

    /// Return the source address of the request.
    #[must_use]
    pub const fn source(&self) -> SocketAddr {
        self.source
    }

    /// Return the SNMP version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Return the concrete security model used for the request.
    #[must_use]
    pub const fn security_model(&self) -> SecurityModel {
        self.security_model
    }

    /// Return the model-specific community identifier or USM username.
    #[must_use]
    pub const fn security_name(&self) -> &SecurityName {
        &self.security_name
    }

    /// Return the security level used for the request.
    #[must_use]
    pub const fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    /// Return the SNMPv3 context name as protocol octets.
    ///
    /// This is empty for community-based requests and need not be UTF-8.
    #[must_use]
    pub const fn context_name(&self) -> &Bytes {
        &self.context_name
    }

    /// Return the request ID from the PDU.
    #[must_use]
    pub const fn request_id(&self) -> i32 {
        self.request_id
    }

    /// Return the incoming PDU type.
    #[must_use]
    pub const fn pdu_type(&self) -> PduType {
        self.pdu_type
    }

    /// Return the VACM-resolved group name, if VACM was applied.
    #[must_use]
    pub const fn group_name(&self) -> Option<&Bytes> {
        self.group_name.as_ref()
    }

    /// Return the VACM-resolved read view name, if VACM was applied.
    #[must_use]
    pub const fn read_view(&self) -> Option<&Bytes> {
        self.read_view.as_ref()
    }

    /// Return the VACM-resolved write view name, if VACM was applied.
    #[must_use]
    pub const fn write_view(&self) -> Option<&Bytes> {
        self.write_view.as_ref()
    }

    /// Return the client-advertised maximum message size for SNMPv3.
    ///
    /// Community-based requests do not carry this field and return `None`.
    #[must_use]
    pub const fn msg_max_size(&self) -> Option<usize> {
        self.msg_max_size
    }

    /// Return accepted request decode anomalies in stable processing order.
    ///
    /// Community and `noAuthNoPriv` anomalies are not authenticated. On
    /// `authNoPriv` and `authPriv` requests, anomalies within the declared V3
    /// envelope are exposed only after successful USM authentication and can
    /// be attributed to the configured user. A top-level
    /// [`DecodeAnomaly::TrailingBytes`] describes bytes outside that envelope
    /// and remains unauthenticated.
    #[must_use]
    pub fn decode_anomalies(&self) -> &[DecodeAnomaly] {
        &self.decode_anomalies
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RequestTaskPhase {
    Unclassified,
    Retrieval,
    SetPreCommit,
    SetProtected,
    Other,
}

#[derive(Debug, Clone)]
pub(crate) struct RequestLifecycle {
    pub(crate) received_at: tokio::time::Instant,
    pub(crate) admitted_at: tokio::time::Instant,
    pub(crate) deadline: Option<tokio::time::Instant>,
    pub(crate) cancellation: CancellationToken,
    pub(crate) phase: Arc<AtomicU8>,
}

impl RequestLifecycle {
    pub(crate) fn new(
        received_at: tokio::time::Instant,
        admitted_at: tokio::time::Instant,
        deadline: Option<tokio::time::Instant>,
        cancellation: CancellationToken,
        phase: Arc<AtomicU8>,
    ) -> Self {
        Self {
            received_at,
            admitted_at,
            deadline,
            cancellation,
            phase,
        }
    }

    #[cfg(test)]
    fn for_test(pdu_type: PduType) -> Self {
        let lifecycle = Self::standalone();
        lifecycle.classify(pdu_type);
        lifecycle
    }

    #[cfg(test)]
    pub(crate) fn standalone() -> Self {
        let now = tokio::time::Instant::now();
        Self::new(
            now,
            now,
            None,
            CancellationToken::new(),
            Arc::new(AtomicU8::new(RequestTaskPhase::Unclassified as u8)),
        )
    }

    fn classify(&self, pdu_type: PduType) {
        let phase = match pdu_type {
            PduType::GetRequest | PduType::GetNextRequest | PduType::GetBulkRequest => {
                RequestTaskPhase::Retrieval
            }
            PduType::SetRequest => RequestTaskPhase::SetPreCommit,
            _ => RequestTaskPhase::Other,
        };
        self.phase.store(phase as u8, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(RequestContext: Send, Sync, Clone, std::fmt::Debug);

    #[test]
    fn community_accessors_cover_v1_v2c_and_non_utf8_names() {
        let source = "192.0.2.55:6161".parse().unwrap();
        let community = Community::from(b"reader\xff".as_slice());

        for (community_version, version, model) in [
            (CommunityVersion::V1, Version::V1, SecurityModel::V1),
            (CommunityVersion::V2c, Version::V2c, SecurityModel::V2c),
        ] {
            let context = RequestContext::community(
                source,
                community_version,
                community.clone(),
                416,
                PduType::GetNextRequest,
                Vec::new(),
            );

            assert_eq!(context.source(), source);
            assert_eq!(context.version(), version);
            assert_eq!(context.security_model(), model);
            assert!(
                context
                    .security_name()
                    .matches(&SecurityName::Community(community.clone()))
            );
            assert_eq!(context.security_level(), SecurityLevel::NoAuthNoPriv);
            assert!(context.context_name().is_empty());
            assert_eq!(context.request_id(), 416);
            assert_eq!(context.pdu_type(), PduType::GetNextRequest);
            assert_eq!(context.group_name(), None);
            assert_eq!(context.read_view(), None);
            assert_eq!(context.write_view(), None);
            assert_eq!(context.msg_max_size(), None);
        }
    }

    #[test]
    fn usm_accessors_cover_every_security_level_and_octet_fields() {
        let source = "[2001:db8::1]:6161".parse().unwrap();
        let username = Bytes::from_static(b"operator\xff");
        let context_name = Bytes::from_static(b"tenant\x80");

        for level in [
            SecurityLevel::NoAuthNoPriv,
            SecurityLevel::AuthNoPriv,
            SecurityLevel::AuthPriv,
        ] {
            let mut context = RequestContext::usm(
                source,
                username.clone(),
                level,
                context_name.clone(),
                -17,
                PduType::SetRequest,
                4096,
                Vec::new(),
            );
            context.set_vacm_access(
                Bytes::from_static(b"operators\xfe"),
                Bytes::from_static(b"read\xfd"),
                Bytes::from_static(b"write\xfc"),
            );

            assert_eq!(context.source(), source);
            assert_eq!(context.version(), Version::V3);
            assert_eq!(context.security_model(), SecurityModel::Usm);
            assert_eq!(context.security_name().as_bytes(), username);
            assert_eq!(context.security_level(), level);
            assert_eq!(context.context_name(), &context_name);
            assert_eq!(context.request_id(), -17);
            assert_eq!(context.pdu_type(), PduType::SetRequest);
            assert_eq!(context.group_name().unwrap(), b"operators\xfe".as_slice());
            assert_eq!(context.read_view().unwrap(), b"read\xfd".as_slice());
            assert_eq!(context.write_view().unwrap(), b"write\xfc".as_slice());
            assert_eq!(context.msg_max_size(), Some(4096));
        }
    }

    #[test]
    fn debug_redacts_community_and_keeps_usm_username() {
        let community = RequestContext::community(
            "192.0.2.55:6161".parse().unwrap(),
            CommunityVersion::V2c,
            Community::from("community-redaction-sentinel-4d91"),
            416,
            PduType::GetRequest,
            Vec::new(),
        );
        let rendered = format!("{community:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("community-redaction-sentinel-4d91"));
        assert!(rendered.contains("192.0.2.55:6161"));
        assert!(rendered.contains("416"));

        let usm = RequestContext::usm(
            "192.0.2.55:6161".parse().unwrap(),
            Bytes::from_static(b"visible-usm-user"),
            SecurityLevel::AuthNoPriv,
            Bytes::new(),
            417,
            PduType::GetRequest,
            4096,
            Vec::new(),
        );
        let rendered = format!("{usm:#?}");
        assert!(rendered.contains("visible-usm-user"));
        assert!(rendered.contains("192.0.2.55:6161"));
    }
}
