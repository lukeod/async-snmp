//! Request context for MIB handlers.
//!
//! This module provides [`RequestContext`], which contains information about
//! incoming SNMP requests for use in handler authorization decisions.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::message::SecurityLevel;
use crate::pdu::PduType;
use crate::version::Version;

use super::SecurityModel;

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
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, BoxFuture};
/// use async_snmp::{Oid, Value, oid};
///
/// struct LoggingHandler;
///
/// impl MibHandler for LoggingHandler {
///     fn get<'a>(&'a self, ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
///         Box::pin(async move {
///             // Log request details
///             println!(
///                 "GET {} from {} (user: {:?}, version: {:?})",
///                 oid, ctx.source, ctx.security_name, ctx.version
///             );
///
///             if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
///                 GetResult::Value(Value::Integer(42))
///             } else {
///                 GetResult::NoSuchObject
///             }
///         })
///     }
///
///     fn get_next<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         _oid: &'a Oid,
///     ) -> BoxFuture<'a, async_snmp::handler::GetNextResult> {
///         Box::pin(async { async_snmp::handler::GetNextResult::EndOfMibView })
///     }
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
    /// - `V1` for SNMPv1 community-based
    /// - `V2c` for SNMPv2c community-based
    /// - `Usm` for SNMPv3 User-based Security Model
    pub security_model: SecurityModel,

    /// Security name (community string or USM username).
    ///
    /// For v1/v2c: the community string
    /// For v3: the USM username
    pub security_name: Bytes,

    /// Security level (v3 only, NoAuthNoPriv for v1/v2c).
    ///
    /// Indicates whether authentication and/or privacy were used.
    pub security_level: SecurityLevel,

    /// Context name (v3 only, empty for v1/v2c).
    ///
    /// SNMPv3 contexts allow partitioning MIB views.
    pub context_name: Bytes,

    /// Request ID from the PDU.
    ///
    /// Useful for correlating requests with responses in logs.
    pub request_id: i32,

    /// PDU type (GetRequest, GetNextRequest, SetRequest, etc.).
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
}
