//! Request context for MIB handlers.

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
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Source address of the request.
    pub source: SocketAddr,
    /// SNMP version.
    pub version: Version,
    /// Security model used.
    pub security_model: SecurityModel,
    /// Security name (community string or username).
    pub security_name: Bytes,
    /// Security level (v3 only, NoAuthNoPriv for v1/v2c).
    pub security_level: SecurityLevel,
    /// Context name (v3 only, empty for v1/v2c).
    pub context_name: Bytes,
    /// Request ID from the PDU.
    pub request_id: i32,
    /// PDU type (GetRequest, GetNextRequest, etc.).
    pub pdu_type: PduType,
    /// Resolved group name (if VACM enabled).
    pub group_name: Option<Bytes>,
    /// Read view name (if VACM enabled).
    pub read_view: Option<Bytes>,
    /// Write view name (if VACM enabled).
    pub write_view: Option<Bytes>,
}
