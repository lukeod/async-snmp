//! Request context for MIB handlers.
//!
//! This module provides [`RequestContext`], which contains information about
//! incoming SNMP requests for use in handler authorization decisions.

use std::net::SocketAddr;

use bytes::Bytes;
use subtle::ConstantTimeEq;

use crate::Community;
use crate::message::SecurityLevel;
use crate::pdu::PduType;
use crate::version::Version;

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
///
/// # Fields
///
/// The context provides:
/// - **Request origin**: Source address and request ID
/// - **Security info**: Version, model, level, and security name (community/username)
/// - **VACM info**: Group name and view names (when VACM is configured)
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
///                 oid, ctx.source, ctx.security_name, ctx.version
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
///     ctx.security_model == SecurityModel::V2c && ctx.security_name.matches(&reader)
/// }
///
/// fn may_write(ctx: &RequestContext) -> bool {
///     let operator = SecurityName::Usm(bytes::Bytes::from_static(b"operator\xff"));
///     ctx.security_model == SecurityModel::Usm
///         && matches!(ctx.security_level, SecurityLevel::AuthNoPriv | SecurityLevel::AuthPriv)
///         && ctx.security_name.matches(&operator)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Source address of the request.
    ///
    /// Use this for logging or additional access control beyond VACM.
    pub source: SocketAddr,

    /// SNMP version (V1, V2c, or V3).
    pub version: Version,

    /// Security model used for this request.
    ///
    /// - `V1` for `SNMPv1` community-based
    /// - `V2c` for `SNMPv2c` community-based
    /// - `Usm` for `SNMPv3` User-based Security Model
    pub security_model: SecurityModel,

    /// Model-specific community identifier or USM username.
    pub security_name: SecurityName,

    /// Security level (v3 only, `NoAuthNoPriv` for v1/v2c).
    ///
    /// Indicates whether authentication and/or privacy were used.
    pub security_level: SecurityLevel,

    /// Context name (v3 only, empty for v1/v2c).
    ///
    /// `SNMPv3` contexts allow partitioning MIB views.
    pub context_name: Bytes,

    /// Request ID from the PDU.
    ///
    /// Useful for correlating requests with responses in logs.
    pub request_id: i32,

    /// PDU type (`GetRequest`, `GetNextRequest`, `SetRequest`, etc.).
    pub pdu_type: PduType,

    /// Resolved group name (if VACM enabled).
    ///
    /// Set when VACM successfully maps the security name to a group.
    pub group_name: Option<Bytes>,

    /// Read view name (if VACM enabled).
    ///
    /// The view that controls which OIDs can be read.
    pub read_view: Option<Bytes>,

    /// Write view name (if VACM enabled).
    ///
    /// The view that controls which OIDs can be written.
    pub write_view: Option<Bytes>,

    /// Client-advertised maximum message size (V3 only).
    ///
    /// For `SNMPv3` requests, this is the msgMaxSize from the V3 message header,
    /// indicating the largest message the client can accept. The agent should
    /// limit response sizes to `min(agent_max, msg_max_size)`.
    ///
    /// None for v1/v2c requests (no msgMaxSize field in those versions).
    pub msg_max_size: Option<usize>,
}

impl RequestContext {
    /// Create a minimal context for unit testing.
    #[must_use]
    pub fn test_context() -> Self {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        Self {
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            version: Version::V2c,
            security_model: SecurityModel::V2c,
            security_name: SecurityName::Community(Community::from("public")),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: 1,
            pdu_type: PduType::GetRequest,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: None,
        }
    }
}
