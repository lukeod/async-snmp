//! SNMP Protocol Data Units (PDUs).
//!
//! PDUs represent the different SNMP operations.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, ErrorStatus, Result};
use crate::oid::Oid;
use crate::value::Value;
use crate::varbind::{VarBind, decode_varbind_list, encode_varbind_list};
use crate::version::Version;

fn invalid_outbound(reason: impl Into<Box<str>>) -> Box<Error> {
    Error::InvalidMessage(reason.into()).boxed()
}

/// The protocol role of an outbound PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PduDirection {
    Request,
    Response,
    Notification,
}

pub(crate) fn pdu_type_valid_for_version(pdu_type: PduType, version: Version) -> bool {
    match version {
        Version::V1 => matches!(
            pdu_type,
            PduType::GetRequest | PduType::GetNextRequest | PduType::Response | PduType::SetRequest
        ),
        Version::V2c => matches!(
            pdu_type,
            PduType::GetRequest
                | PduType::GetNextRequest
                | PduType::Response
                | PduType::SetRequest
                | PduType::GetBulkRequest
                | PduType::InformRequest
                | PduType::TrapV2
        ),
        Version::V3 => pdu_type != PduType::TrapV1,
    }
}

fn validate_outbound_values(
    version: Version,
    direction: PduDirection,
    varbinds: &[VarBind],
) -> Result<()> {
    for varbind in varbinds {
        let value = &varbind.value;
        if matches!(value, Value::Unknown { .. }) {
            return Err(invalid_outbound(
                "Value::Unknown cannot be encoded by structured encoders",
            ));
        }
        if matches!(value, Value::UInteger32(_) | Value::Nsap(_)) {
            return Err(invalid_outbound(
                "historic receive-only value type cannot be encoded",
            ));
        }
        if version == Version::V1
            && matches!(
                value,
                Value::Counter64(_)
                    | Value::NoSuchObject
                    | Value::NoSuchInstance
                    | Value::EndOfMibView
            )
        {
            return Err(invalid_outbound("value type is not valid in SNMPv1"));
        }
        if direction != PduDirection::Response && value.is_exception() {
            return Err(invalid_outbound(
                "exception values are only valid in response PDUs",
            ));
        }
    }
    Ok(())
}

/// PDU type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PduType {
    /// GET request - retrieve specific OID values.
    GetRequest = 0xA0,
    /// GET-NEXT request - retrieve the next OID in the MIB tree.
    GetNextRequest = 0xA1,
    /// Response to a request from an agent.
    Response = 0xA2,
    /// SET request - modify OID values.
    SetRequest = 0xA3,
    /// `SNMPv1` trap - unsolicited notification from an agent.
    TrapV1 = 0xA4,
    /// GET-BULK request - efficient bulk retrieval of table data.
    GetBulkRequest = 0xA5,
    /// INFORM request - acknowledged notification.
    InformRequest = 0xA6,
    /// SNMPv2c/v3 trap - unsolicited notification from an agent.
    TrapV2 = 0xA7,
    /// Report - used in `SNMPv3` for engine discovery and error reporting.
    Report = 0xA8,
}

impl PduType {
    /// Create from tag byte.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0xA0 => Some(Self::GetRequest),
            0xA1 => Some(Self::GetNextRequest),
            0xA2 => Some(Self::Response),
            0xA3 => Some(Self::SetRequest),
            0xA4 => Some(Self::TrapV1),
            0xA5 => Some(Self::GetBulkRequest),
            0xA6 => Some(Self::InformRequest),
            0xA7 => Some(Self::TrapV2),
            0xA8 => Some(Self::Report),
            _ => None,
        }
    }

    /// Get the tag byte.
    #[must_use]
    pub fn tag(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for PduType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetRequest => write!(f, "GetRequest"),
            Self::GetNextRequest => write!(f, "GetNextRequest"),
            Self::Response => write!(f, "Response"),
            Self::SetRequest => write!(f, "SetRequest"),
            Self::TrapV1 => write!(f, "TrapV1"),
            Self::GetBulkRequest => write!(f, "GetBulkRequest"),
            Self::InformRequest => write!(f, "InformRequest"),
            Self::TrapV2 => write!(f, "TrapV2"),
            Self::Report => write!(f, "Report"),
        }
    }
}

/// PDU tags whose body uses the standard request/error/varbind layout.
///
/// GETBULK is deliberately absent because its two integer fields have different
/// meanings. The SNMPv1 Trap body remains envelope-specific.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandardPduType {
    /// GET request.
    GetRequest,
    /// GET-NEXT request.
    GetNextRequest,
    /// Response.
    Response,
    /// SET request.
    SetRequest,
    /// INFORM request.
    InformRequest,
    /// SNMPv2 trap.
    TrapV2,
    /// SNMPv3 report.
    Report,
}

impl StandardPduType {
    /// Return the corresponding wire PDU type.
    #[must_use]
    pub fn pdu_type(self) -> PduType {
        match self {
            Self::GetRequest => PduType::GetRequest,
            Self::GetNextRequest => PduType::GetNextRequest,
            Self::Response => PduType::Response,
            Self::SetRequest => PduType::SetRequest,
            Self::InformRequest => PduType::InformRequest,
            Self::TrapV2 => PduType::TrapV2,
            Self::Report => PduType::Report,
        }
    }
}

impl TryFrom<PduType> for StandardPduType {
    type Error = PduType;

    fn try_from(value: PduType) -> std::result::Result<Self, Self::Error> {
        match value {
            PduType::GetRequest => Ok(Self::GetRequest),
            PduType::GetNextRequest => Ok(Self::GetNextRequest),
            PduType::Response => Ok(Self::Response),
            PduType::SetRequest => Ok(Self::SetRequest),
            PduType::InformRequest => Ok(Self::InformRequest),
            PduType::TrapV2 => Ok(Self::TrapV2),
            PduType::Report => Ok(Self::Report),
            PduType::TrapV1 | PduType::GetBulkRequest => Err(value),
        }
    }
}

/// The typed body of a standard or GETBULK PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduBody {
    /// Standard request/response body fields.
    Standard {
        /// PDU tag, excluding GETBULK and SNMPv1 Trap.
        pdu_type: StandardPduType,
        /// Error status (zero for requests).
        error_status: i32,
        /// One-based error index, or zero.
        error_index: i32,
    },
    /// GETBULK-specific body fields.
    ///
    /// Encoding rejects either field above the RFC 3416 `Integer32` maximum.
    /// Use [`Pdu::get_bulk`] for checked construction.
    GetBulk {
        /// Number of non-repeating OIDs.
        non_repeaters: u32,
        /// Maximum repetitions for repeating OIDs.
        max_repetitions: u32,
    },
}

/// Largest valid value for either GETBULK parameter.
pub(crate) const MAX_GET_BULK_VALUE: u32 = i32::MAX as u32;

/// Canonical PDU representation for standard and GETBULK operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// Request ID for correlating requests and responses.
    pub request_id: i32,
    /// Typed fields that determine the PDU tag and integer meanings.
    pub body: PduBody,
    /// Variable bindings.
    pub varbinds: Vec<VarBind>,
}

impl Pdu {
    /// Construct a standard-layout PDU.
    #[must_use]
    pub fn standard(
        pdu_type: StandardPduType,
        request_id: i32,
        error_status: i32,
        error_index: i32,
        varbinds: Vec<VarBind>,
    ) -> Self {
        Self {
            request_id,
            body: PduBody::Standard {
                pdu_type,
                error_status,
                error_index,
            },
            varbinds,
        }
    }

    /// Construct a response PDU.
    #[must_use]
    pub fn response(
        request_id: i32,
        error_status: i32,
        error_index: i32,
        varbinds: Vec<VarBind>,
    ) -> Self {
        Self::standard(
            StandardPduType::Response,
            request_id,
            error_status,
            error_index,
            varbinds,
        )
    }

    /// Create a new GET request PDU.
    #[must_use]
    pub fn get_request(request_id: i32, oids: &[Oid]) -> Self {
        Self::standard(
            StandardPduType::GetRequest,
            request_id,
            0,
            0,
            oids.iter().map(|oid| VarBind::null(oid.clone())).collect(),
        )
    }

    /// Create a new GETNEXT request PDU.
    #[must_use]
    pub fn get_next_request(request_id: i32, oids: &[Oid]) -> Self {
        Self::standard(
            StandardPduType::GetNextRequest,
            request_id,
            0,
            0,
            oids.iter().map(|oid| VarBind::null(oid.clone())).collect(),
        )
    }

    /// Create a new SET request PDU.
    #[must_use]
    pub fn set_request(request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self::standard(StandardPduType::SetRequest, request_id, 0, 0, varbinds)
    }

    /// Create a SNMPv2c/v3 Trap PDU.
    ///
    /// Prepends the mandatory varbind prefix per RFC 3416 Section 4.2.6:
    /// 1. sysUpTime.0 (1.3.6.1.2.1.1.3.0) with `TimeTicks` value
    /// 2. snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) with the trap OID
    ///
    /// Caller-provided varbinds are appended after the prefix.
    #[must_use]
    pub fn trap_v2(request_id: i32, uptime: u32, trap_oid: &Oid, varbinds: Vec<VarBind>) -> Self {
        let mut all_varbinds = Vec::with_capacity(2 + varbinds.len());
        all_varbinds.push(VarBind::new(
            crate::notification::oids::sys_uptime(),
            crate::value::Value::TimeTicks(uptime),
        ));
        all_varbinds.push(VarBind::new(
            crate::notification::oids::snmp_trap_oid(),
            crate::value::Value::ObjectIdentifier(trap_oid.clone()),
        ));
        all_varbinds.extend(varbinds);
        Self::standard(StandardPduType::TrapV2, request_id, 0, 0, all_varbinds)
    }

    /// Create an `InformRequest` PDU.
    ///
    /// Same varbind structure as `trap_v2` (sysUpTime.0 + snmpTrapOID.0 prefix),
    /// but uses `InformRequest` PDU type which expects a Response from the receiver.
    #[must_use]
    pub fn inform_request(
        request_id: i32,
        uptime: u32,
        trap_oid: &Oid,
        varbinds: Vec<VarBind>,
    ) -> Self {
        let mut all_varbinds = Vec::with_capacity(2 + varbinds.len());
        all_varbinds.push(VarBind::new(
            crate::notification::oids::sys_uptime(),
            crate::value::Value::TimeTicks(uptime),
        ));
        all_varbinds.push(VarBind::new(
            crate::notification::oids::snmp_trap_oid(),
            crate::value::Value::ObjectIdentifier(trap_oid.clone()),
        ));
        all_varbinds.extend(varbinds);
        Self::standard(
            StandardPduType::InformRequest,
            request_id,
            0,
            0,
            all_varbinds,
        )
    }

    /// Create a GETBULK request PDU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`](crate::Error::InvalidMessage) when
    /// either GETBULK parameter exceeds the RFC 3416 `Integer32` maximum.
    pub fn get_bulk(
        request_id: i32,
        non_repeaters: u32,
        max_repetitions: u32,
        varbinds: Vec<VarBind>,
    ) -> Result<Self> {
        Self::checked_get_bulk_fields(non_repeaters, max_repetitions)?;
        Ok(Self {
            request_id,
            body: PduBody::GetBulk {
                non_repeaters,
                max_repetitions,
            },
            varbinds,
        })
    }

    pub(crate) fn checked_get_bulk_fields(non_repeaters: u32, max_repetitions: u32) -> Result<()> {
        Self::get_bulk_fields_for_wire(non_repeaters, max_repetitions)?;
        Ok(())
    }

    fn get_bulk_fields_for_wire(non_repeaters: u32, max_repetitions: u32) -> Result<(i32, i32)> {
        let non_repeaters = i32::try_from(non_repeaters)
            .map_err(|_| invalid_outbound("GETBULK non_repeaters exceeds i32::MAX"))?;
        let max_repetitions = i32::try_from(max_repetitions)
            .map_err(|_| invalid_outbound("GETBULK max_repetitions exceeds i32::MAX"))?;
        Ok((non_repeaters, max_repetitions))
    }

    pub(crate) fn outbound_direction(&self) -> PduDirection {
        match self.pdu_type() {
            PduType::Response | PduType::Report => PduDirection::Response,
            PduType::TrapV1 | PduType::TrapV2 => PduDirection::Notification,
            PduType::GetRequest
            | PduType::GetNextRequest
            | PduType::SetRequest
            | PduType::GetBulkRequest
            | PduType::InformRequest => PduDirection::Request,
        }
    }

    fn inferred_encode_version(&self) -> Version {
        match self.pdu_type() {
            PduType::Report => Version::V3,
            _ => Version::V2c,
        }
    }

    pub(crate) fn validate_outbound(
        &self,
        version: Version,
        direction: PduDirection,
    ) -> Result<()> {
        let pdu_type = self.pdu_type();
        if !pdu_type_valid_for_version(pdu_type, version) {
            return Err(invalid_outbound(format!(
                "{pdu_type} PDU is not valid for {version:?}"
            )));
        }
        if self.outbound_direction() != direction {
            return Err(invalid_outbound(format!(
                "{pdu_type} PDU is not valid in the {direction:?} direction"
            )));
        }

        match self.body {
            PduBody::GetBulk {
                non_repeaters,
                max_repetitions,
            } => {
                Self::get_bulk_fields_for_wire(non_repeaters, max_repetitions)?;
            }
            PduBody::Standard {
                pdu_type: StandardPduType::Response,
                error_status,
                error_index,
            } => {
                let maximum_status = if version == Version::V1 { 5 } else { 18 };
                if !(0..=maximum_status).contains(&error_status) {
                    return Err(invalid_outbound(
                        "Response error_status is not valid for the SNMP version",
                    ));
                }
                if error_index < 0
                    || usize::try_from(error_index)
                        .ok()
                        .is_none_or(|index| index > self.varbinds.len())
                {
                    return Err(invalid_outbound(
                        "Response error_index does not identify a variable binding",
                    ));
                }
                if matches!(error_status, 0 | 1 | 15) {
                    if error_index != 0 {
                        return Err(invalid_outbound(
                            "noError, tooBig, and undoFailed Responses require error_index zero",
                        ));
                    }
                } else if error_index == 0 {
                    return Err(invalid_outbound(
                        "this Response error_status requires a nonzero error_index",
                    ));
                }
            }
            PduBody::Standard {
                error_status,
                error_index,
                ..
            } => {
                if error_status != 0 || error_index != 0 {
                    return Err(invalid_outbound(
                        "request and notification PDUs require zero error fields",
                    ));
                }
            }
        }

        validate_outbound_values(version, direction, &self.varbinds)
    }

    pub(crate) fn encode_for(
        &self,
        buf: &mut EncodeBuf,
        version: Version,
        direction: PduDirection,
    ) -> Result<()> {
        self.validate_outbound(version, direction)?;
        self.encode_validated(buf)
    }

    fn encode_validated(&self, buf: &mut EncodeBuf) -> Result<()> {
        let (pdu_type, first_field, second_field) = match self.body {
            PduBody::Standard {
                pdu_type,
                error_status,
                error_index,
            } => (pdu_type.pdu_type(), error_status, error_index),
            PduBody::GetBulk {
                non_repeaters,
                max_repetitions,
            } => {
                let (non_repeaters, max_repetitions) =
                    Self::get_bulk_fields_for_wire(non_repeaters, max_repetitions)?;
                (PduType::GetBulkRequest, non_repeaters, max_repetitions)
            }
        };

        buf.try_push_constructed(pdu_type.tag(), |buf| {
            encode_varbind_list(buf, &self.varbinds)?;
            buf.push_integer(second_field);
            buf.push_integer(first_field);
            buf.push_integer(self.request_id);
            Ok(())
        })
    }

    /// Encode a structurally valid PDU to BER.
    ///
    /// Version-specific validation is repeated when the PDU is placed in a
    /// community or SNMPv3 message envelope.
    pub fn encode(&self, buf: &mut EncodeBuf) -> Result<()> {
        self.encode_for(
            buf,
            self.inferred_encode_version(),
            self.outbound_direction(),
        )
    }

    /// Decode from BER (after tag has been peeked).
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let tag = decoder.read_tag()?;
        let pdu_type = PduType::from_tag(tag).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::pdu", { offset = decoder.offset(), tag = tag, kind = %DecodeErrorKind::UnknownPduType(tag) }, "decode error");
            decoder.malformed()
        })?;

        // The SNMPv1 Trap PDU (tag 0xA4) has a distinct wire layout (RFC 1157
        // Section 4.1.6) that this generic decoder cannot parse correctly. It is
        // only ever carried in v1 messages and must be routed through
        // `TrapV1Pdu::decode`; reaching it here means a v2c/v3 message carried a
        // v1 Trap tag, which is rejected.
        if pdu_type == PduType::TrapV1 {
            tracing::debug!(target: "async_snmp::pdu", { offset = decoder.offset(), tag = tag }, "TrapV1 PDU tag not valid in generic PDU context");
            return Err(decoder.malformed());
        }

        let len = decoder.read_length()?;
        let mut pdu_decoder = decoder.sub_decoder(len)?;

        // These are protocol Integer32 fields, so decode the complete width
        // without consulting generic value-truncation compatibility.
        let request_id = pdu_decoder.read_bounded_integer(i32::MIN, i32::MAX)?;
        let mut first_field = pdu_decoder.read_bounded_integer(i32::MIN, i32::MAX)?;
        let mut second_field = pdu_decoder.read_bounded_integer(i32::MIN, i32::MAX)?;
        let varbinds = decode_varbind_list(&mut pdu_decoder)?;
        if !pdu_decoder.is_empty() {
            return Err(pdu_decoder.malformed());
        }

        let body = if pdu_type == PduType::GetBulkRequest {
            for (field, value) in [
                ("non_repeaters", &mut first_field),
                ("max_repetitions", &mut second_field),
            ] {
                if *value < 0 {
                    if !decoder
                        .compatibility_policy()
                        .normalize_negative_get_bulk_fields
                    {
                        return Err(decoder.malformed());
                    }
                    tracing::warn!(target: "async_snmp::pdu", anomaly = "negative_get_bulk_field", direction = "decode", field, value = *value, normalized = 0, "normalized negative GETBULK field");
                    *value = 0;
                }
            }
            let non_repeaters = u32::try_from(first_field).map_err(|_| pdu_decoder.malformed())?;
            let max_repetitions =
                u32::try_from(second_field).map_err(|_| pdu_decoder.malformed())?;
            PduBody::GetBulk {
                non_repeaters,
                max_repetitions,
            }
        } else {
            let standard_type =
                StandardPduType::try_from(pdu_type).map_err(|_| pdu_decoder.malformed())?;
            PduBody::Standard {
                pdu_type: standard_type,
                error_status: first_field,
                error_index: second_field,
            }
        };

        // For standard PDUs, error_index is not validated here. net-snmp
        // performs no bounds checking on this field.
        Ok(Pdu {
            request_id,
            body,
            varbinds,
        })
    }

    /// Return the wire PDU type.
    #[must_use]
    pub fn pdu_type(&self) -> PduType {
        match self.body {
            PduBody::Standard { pdu_type, .. } => pdu_type.pdu_type(),
            PduBody::GetBulk { .. } => PduType::GetBulkRequest,
        }
    }

    /// Return standard response fields, if this is a standard-layout PDU.
    #[must_use]
    pub fn error_fields(&self) -> Option<(i32, i32)> {
        match self.body {
            PduBody::Standard {
                error_status,
                error_index,
                ..
            } => Some((error_status, error_index)),
            PduBody::GetBulk { .. } => None,
        }
    }

    /// Return the unsigned GETBULK fields, if this is a GETBULK PDU.
    #[must_use]
    pub fn get_bulk_fields(&self) -> Option<(u32, u32)> {
        match self.body {
            PduBody::GetBulk {
                non_repeaters,
                max_repetitions,
            } => Some((non_repeaters, max_repetitions)),
            PduBody::Standard { .. } => None,
        }
    }

    /// Return the standard error status, or zero for GETBULK.
    #[must_use]
    pub fn error_status(&self) -> i32 {
        self.error_fields().map_or(0, |fields| fields.0)
    }

    /// Return the standard error index, or zero for GETBULK.
    #[must_use]
    pub fn error_index(&self) -> i32 {
        self.error_fields().map_or(0, |fields| fields.1)
    }

    /// Set the tag of a standard-layout PDU.
    ///
    /// Returns false for a GETBULK PDU.
    pub fn set_standard_pdu_type(&mut self, value: StandardPduType) -> bool {
        match &mut self.body {
            PduBody::Standard { pdu_type, .. } => {
                *pdu_type = value;
                true
            }
            PduBody::GetBulk { .. } => false,
        }
    }

    /// Set the standard error status.
    ///
    /// Returns false for a GETBULK PDU.
    pub fn set_error_status(&mut self, value: i32) -> bool {
        match &mut self.body {
            PduBody::Standard { error_status, .. } => {
                *error_status = value;
                true
            }
            PduBody::GetBulk { .. } => false,
        }
    }

    /// Set the standard error index.
    ///
    /// Returns false for a GETBULK PDU.
    pub fn set_error_index(&mut self, value: i32) -> bool {
        match &mut self.body {
            PduBody::Standard { error_index, .. } => {
                *error_index = value;
                true
            }
            PduBody::GetBulk { .. } => false,
        }
    }

    /// Check if this is an error response.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.pdu_type() == PduType::Response && self.error_status() != 0
    }

    /// Get the error status as an enum.
    #[must_use]
    pub fn error_status_enum(&self) -> ErrorStatus {
        ErrorStatus::from_i32(self.error_status())
    }

    /// Create a Response PDU from this PDU (for Inform handling).
    ///
    /// The response copies the `request_id` and variable bindings,
    /// sets `error_status` and `error_index` to 0, and changes the PDU type to Response.
    #[must_use]
    pub fn to_response(&self) -> Self {
        Self::response(self.request_id, 0, 0, self.varbinds.clone())
    }

    /// Create a Response PDU with specific error status.
    #[must_use]
    pub fn to_error_response(&self, error_status: ErrorStatus, error_index: i32) -> Self {
        Self::response(
            self.request_id,
            error_status.as_i32(),
            error_index,
            self.varbinds.clone(),
        )
    }

    /// Convert a v2 notification PDU to a v1 `TrapV1Pdu` (RFC 3584 Section 3.2).
    ///
    /// Extracts the v1 fields from the standard v2 notification varbind layout:
    /// - sysUpTime.0 (first varbind) -> `time_stamp`
    /// - snmpTrapOID.0 (second varbind) -> `generic_trap`, `specific_trap`, enterprise
    /// - snmpTrapAddress.0 varbind (if present) -> `agent_addr`
    /// - snmpTrapEnterprise.0 varbind (if present) -> enterprise (for standard traps)
    ///
    /// Per RFC 3584 Section 3.2: if any varbind is Counter64, the trap cannot be
    /// represented in v1 and `None` is returned.
    ///
    /// The `default_addr` parameter provides the `agent_addr` when no
    /// snmpTrapAddress.0 varbind is present (typically the local IP address,
    /// or `[0,0,0,0]` if unknown).
    ///
    /// Returns `None` if:
    /// - The PDU has fewer than 2 varbinds
    /// - The first varbind is not `TimeTicks`
    /// - The second varbind is not an OID
    /// - Any varbind contains a Counter64 value
    #[must_use]
    pub fn to_v1_trap(&self, default_addr: [u8; 4]) -> Option<TrapV1Pdu> {
        use crate::notification::oids;
        use crate::value::Value;

        if self.varbinds.len() < 2 {
            return None;
        }

        // Verify OID names per RFC 3416 Section 4.2.6: the first two varbinds
        // must be sysUpTime.0 and snmpTrapOID.0.
        if self.varbinds[0].oid != oids::sys_uptime() {
            return None;
        }
        if self.varbinds[1].oid != oids::snmp_trap_oid() {
            return None;
        }

        let time_stamp = match &self.varbinds[0].value {
            Value::TimeTicks(t) => *t,
            _ => return None,
        };

        let Value::ObjectIdentifier(trap_oid) = &self.varbinds[1].value else {
            return None;
        };

        // Check for Counter64 in any varbind (RFC 3584 Section 3.2, rule 6)
        for vb in &self.varbinds {
            if matches!(vb.value, Value::Counter64(_)) {
                return None;
            }
        }

        // Derive generic_trap, specific_trap, and enterprise from snmpTrapOID
        let snmp_traps_prefix = oids::snmp_traps();
        let (generic_trap, specific_trap, enterprise) = if trap_oid.starts_with(&snmp_traps_prefix)
            && trap_oid.len() == snmp_traps_prefix.len() + 1
            && (1..=6).contains(&trap_oid.arcs()[trap_oid.len() - 1])
        {
            // Standard trap: snmpTraps.{generic+1}
            let last_arc = trap_oid.arcs()[trap_oid.len() - 1];
            let generic = GenericTrap::from_i32((last_arc - 1) as i32);
            // For standard traps, enterprise comes from snmpTrapEnterprise.0
            // varbind if present, otherwise use snmpTraps
            let enterprise_oid = oids::snmp_trap_enterprise();
            let ent = self.varbinds[2..]
                .iter()
                .find(|vb| vb.oid == enterprise_oid)
                .and_then(|vb| match &vb.value {
                    Value::ObjectIdentifier(oid) => Some(oid.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| snmp_traps_prefix.clone());
            (generic, 0, ent)
        } else if trap_oid.len() >= 2 {
            // Enterprise-specific trap. RFC 3584 Section 3.2:
            // - If next-to-last sub-id is zero: enterprise = OID minus last 2 arcs
            // - If next-to-last sub-id is non-zero: enterprise = OID minus last arc
            let arcs = trap_oid.arcs();
            let specific = i32::try_from(arcs[arcs.len() - 1]).ok()?;
            let next_to_last = arcs[arcs.len() - 2];
            let enterprise = if next_to_last == 0 {
                Oid::from_slice(&arcs[..arcs.len() - 2])
            } else {
                Oid::from_slice(&arcs[..arcs.len() - 1])
            };
            (GenericTrap::EnterpriseSpecific, specific, enterprise)
        } else {
            return None;
        };

        // Extract agent_addr from snmpTrapAddress.0 varbind if present
        let trap_address_oid = oids::snmp_trap_address();
        let agent_addr = self.varbinds[2..]
            .iter()
            .find(|vb| vb.oid == trap_address_oid)
            .and_then(|vb| match &vb.value {
                Value::IpAddress(addr) => Some(*addr),
                _ => None,
            })
            .unwrap_or(default_addr);

        // RFC 3584 Section 3.2 rule (6): the SNMPv1 varbinds are the SNMPv2
        // varbinds minus only the sysUpTime.0/snmpTrapOID.0 prefix;
        // snmpTrapAddress.0 and snmpTrapEnterprise.0 are retained.
        let varbinds: Vec<VarBind> = self.varbinds[2..].to_vec();

        Some(TrapV1Pdu {
            enterprise,
            agent_addr,
            generic_trap,
            specific_trap,
            time_stamp,
            varbinds,
        })
    }

    /// Check if this is a notification PDU (Trap or Inform).
    #[must_use]
    pub fn is_notification(&self) -> bool {
        matches!(
            self.pdu_type(),
            PduType::TrapV1 | PduType::TrapV2 | PduType::InformRequest
        )
    }

    /// Check if this is a confirmed-class PDU (requires response).
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self.pdu_type(),
            PduType::GetRequest
                | PduType::GetNextRequest
                | PduType::GetBulkRequest
                | PduType::SetRequest
                | PduType::InformRequest
        )
    }
}

/// `SNMPv1` generic trap types (RFC 1157 Section 4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericTrap {
    /// coldStart(0) - agent is reinitializing, config may change
    ColdStart,
    /// warmStart(1) - agent is reinitializing, config unchanged
    WarmStart,
    /// linkDown(2) - communication link failure
    LinkDown,
    /// linkUp(3) - communication link came up
    LinkUp,
    /// authenticationFailure(4) - improperly authenticated message received
    AuthenticationFailure,
    /// egpNeighborLoss(5) - EGP peer marked down
    EgpNeighborLoss,
    /// enterpriseSpecific(6) - vendor-specific trap, see `specific_trap` field
    EnterpriseSpecific,
    /// An unrecognized generic trap value received on the wire.
    Unknown(i32),
}

impl std::fmt::Display for GenericTrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ColdStart => write!(f, "coldStart"),
            Self::WarmStart => write!(f, "warmStart"),
            Self::LinkDown => write!(f, "linkDown"),
            Self::LinkUp => write!(f, "linkUp"),
            Self::AuthenticationFailure => write!(f, "authenticationFailure"),
            Self::EgpNeighborLoss => write!(f, "egpNeighborLoss"),
            Self::EnterpriseSpecific => write!(f, "enterpriseSpecific"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

impl GenericTrap {
    /// Create from integer value.
    #[must_use]
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::ColdStart,
            1 => Self::WarmStart,
            2 => Self::LinkDown,
            3 => Self::LinkUp,
            4 => Self::AuthenticationFailure,
            5 => Self::EgpNeighborLoss,
            6 => Self::EnterpriseSpecific,
            _ => Self::Unknown(v),
        }
    }

    /// Get the integer value.
    #[must_use]
    pub fn as_i32(self) -> i32 {
        match self {
            Self::ColdStart => 0,
            Self::WarmStart => 1,
            Self::LinkDown => 2,
            Self::LinkUp => 3,
            Self::AuthenticationFailure => 4,
            Self::EgpNeighborLoss => 5,
            Self::EnterpriseSpecific => 6,
            Self::Unknown(v) => v,
        }
    }
}

/// `SNMPv1` Trap PDU (RFC 1157 Section 4.1.6).
///
/// This PDU type has a completely different structure from other PDUs.
/// It is only used in `SNMPv1` and is replaced by SNMPv2-Trap in v2c/v3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapV1Pdu {
    /// Enterprise OID (sysObjectID of the entity generating the trap)
    pub enterprise: Oid,
    /// Agent address (IP address of the agent generating the trap)
    pub agent_addr: [u8; 4],
    /// Generic trap type
    pub generic_trap: GenericTrap,
    /// Specific trap code (meaningful when `generic_trap` is enterpriseSpecific)
    pub specific_trap: i32,
    /// Time since the network entity was last (re)initialized (in hundredths of seconds)
    pub time_stamp: u32,
    /// Variable bindings containing "interesting" information
    pub varbinds: Vec<VarBind>,
}

impl TrapV1Pdu {
    /// Create a new `SNMPv1` Trap PDU.
    #[must_use]
    pub fn new(
        enterprise: Oid,
        agent_addr: [u8; 4],
        generic_trap: GenericTrap,
        specific_trap: i32,
        time_stamp: u32,
        varbinds: Vec<VarBind>,
    ) -> Self {
        Self {
            enterprise,
            agent_addr,
            generic_trap,
            specific_trap,
            time_stamp,
            varbinds,
        }
    }

    /// Check if this is an enterprise-specific trap.
    #[must_use]
    pub fn is_enterprise_specific(&self) -> bool {
        self.generic_trap == GenericTrap::EnterpriseSpecific
    }

    /// Convert to `SNMPv2` trap OID (RFC 3584 Section 3).
    ///
    /// RFC 3584 defines how to translate `SNMPv1` trap information to `SNMPv2`
    /// snmpTrapOID.0 format:
    ///
    /// - For generic traps 0-5 (coldStart through egpNeighborLoss):
    ///   The trap OID is `snmpTraps.{generic_trap + 1}` (1.3.6.1.6.3.1.1.5.{1-6})
    ///
    /// - For enterprise-specific traps (`generic_trap` = 6):
    ///   The trap OID is `enterprise.0.specific_trap`
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidOid`] if:
    /// - `generic_trap` is `Unknown` with a negative value (undefined per RFC 1157)
    /// - `generic_trap` is `Unknown` with value `i32::MAX` (would overflow when adding 1)
    /// - `specific_trap < 0` for enterprise-specific traps (OID arcs must be non-negative)
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_snmp::pdu::{TrapV1Pdu, GenericTrap};
    /// use async_snmp::oid;
    ///
    /// // Generic trap (linkDown = 2) -> snmpTraps.3
    /// let trap = TrapV1Pdu::new(
    ///     oid!(1, 3, 6, 1, 4, 1, 9999),
    ///     [192, 168, 1, 1],
    ///     GenericTrap::LinkDown,
    ///     0,
    ///     12345,
    ///     vec![],
    /// );
    /// assert_eq!(trap.v2_trap_oid().unwrap(), oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3));
    ///
    /// // Enterprise-specific trap -> enterprise.0.specific_trap
    /// let trap = TrapV1Pdu::new(
    ///     oid!(1, 3, 6, 1, 4, 1, 9999),
    ///     [192, 168, 1, 1],
    ///     GenericTrap::EnterpriseSpecific,
    ///     42,
    ///     12345,
    ///     vec![],
    /// );
    /// assert_eq!(trap.v2_trap_oid().unwrap(), oid!(1, 3, 6, 1, 4, 1, 9999, 0, 42));
    /// ```
    pub fn v2_trap_oid(&self) -> crate::Result<Oid> {
        if self.is_enterprise_specific() {
            if self.specific_trap < 0 {
                return Err(Error::InvalidOid("specific_trap cannot be negative".into()).boxed());
            }
            let mut arcs: Vec<u32> = self.enterprise.arcs().to_vec();
            arcs.push(0);
            arcs.push(self.specific_trap as u32);
            Ok(Oid::new(arcs))
        } else {
            let raw = self.generic_trap.as_i32();
            if raw < 0 {
                return Err(Error::InvalidOid("generic_trap cannot be negative".into()).boxed());
            }
            if raw == i32::MAX {
                return Err(Error::InvalidOid("generic_trap overflow".into()).boxed());
            }
            let trap_num = raw + 1;
            Ok(crate::oid!(1, 3, 6, 1, 6, 3, 1, 1, 5).child(trap_num as u32))
        }
    }

    /// Convert to a v2 notification PDU (RFC 3584 Section 3.1).
    ///
    /// Performs the originator (non-proxy) conversion: only the mandatory
    /// sysUpTime.0 and snmpTrapOID.0 prefix followed by the original varbinds.
    /// Per RFC 3584 Section 3.1(4), the additional proxy varbinds
    /// (snmpTrapAddress.0, snmpTrapCommunity.0, snmpTrapEnterprise.0) are only
    /// appended when a proxy forwards a received trap.
    ///
    /// The `request_id` is set to 0; callers should assign their own.
    ///
    /// # Errors
    ///
    /// Returns an error if the trap OID cannot be computed (see [`Self::v2_trap_oid`]).
    pub fn to_v2_pdu(&self) -> crate::Result<Pdu> {
        use crate::notification::oids;
        use crate::value::Value;

        let trap_oid = self.v2_trap_oid()?;

        let mut varbinds = Vec::with_capacity(2 + self.varbinds.len());
        varbinds.push(VarBind::new(
            oids::sys_uptime(),
            Value::TimeTicks(self.time_stamp),
        ));
        varbinds.push(VarBind::new(
            oids::snmp_trap_oid(),
            Value::ObjectIdentifier(trap_oid),
        ));
        varbinds.extend_from_slice(&self.varbinds);

        Ok(Pdu::standard(StandardPduType::TrapV2, 0, 0, 0, varbinds))
    }

    pub(crate) fn validate_outbound(&self) -> Result<()> {
        validate_outbound_values(Version::V1, PduDirection::Notification, &self.varbinds)
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) -> Result<()> {
        self.validate_outbound()?;
        buf.try_push_constructed(tag::pdu::TRAP_V1, |buf| {
            encode_varbind_list(buf, &self.varbinds)?;
            buf.push_unsigned32(tag::application::TIMETICKS, self.time_stamp);
            buf.push_integer(self.specific_trap);
            buf.push_integer(self.generic_trap.as_i32());
            // NetworkAddress is APPLICATION 0 IMPLICIT IpAddress
            // IpAddress is APPLICATION 0 IMPLICIT OCTET STRING (SIZE (4))
            buf.push_bytes(&self.agent_addr);
            buf.push_length(4);
            buf.push_tag(tag::application::IP_ADDRESS);
            buf.push_oid(&self.enterprise)
        })
    }

    /// Decode from BER (after tag has been peeked).
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut pdu = decoder.read_constructed(tag::pdu::TRAP_V1)?;

        // enterprise OBJECT IDENTIFIER
        let enterprise = pdu.read_oid()?;

        // agent-addr NetworkAddress (IpAddress)
        let agent_tag = pdu.read_tag()?;
        if agent_tag != tag::application::IP_ADDRESS {
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), expected = 0x40_u8, actual = agent_tag, kind = %DecodeErrorKind::UnexpectedTag {
                    expected: 0x40,
                    actual: agent_tag,
                } }, "decode error");
            return Err(pdu.malformed());
        }
        let agent_len = pdu.read_length()?;
        if agent_len != 4 {
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), length = agent_len, kind = %DecodeErrorKind::InvalidIpAddressLength { length: agent_len } }, "decode error");
            return Err(pdu.malformed());
        }
        let agent_bytes = pdu.read_bytes(4)?;
        let agent_addr = [
            agent_bytes[0],
            agent_bytes[1],
            agent_bytes[2],
            agent_bytes[3],
        ];

        // generic-trap and specific-trap are protocol Integer32 fields. Do not
        // apply the generic value-truncation compatibility behavior here.
        let generic_trap = GenericTrap::from_i32(pdu.read_bounded_integer(i32::MIN, i32::MAX)?);
        let specific_trap = pdu.read_bounded_integer(i32::MIN, i32::MAX)?;

        // time-stamp TimeTicks
        let ts_tag = pdu.read_tag()?;
        if ts_tag != tag::application::TIMETICKS {
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), expected = 0x43_u8, actual = ts_tag, kind = %DecodeErrorKind::UnexpectedTag {
                    expected: 0x43,
                    actual: ts_tag,
                } }, "decode error");
            return Err(pdu.malformed());
        }
        let ts_len = pdu.read_length()?;
        let time_stamp = pdu.read_bounded_unsigned32_value(ts_len)?;

        // variable-bindings
        let varbinds = decode_varbind_list(&mut pdu)?;
        if !pdu.is_empty() {
            return Err(pdu.malformed());
        }

        Ok(TrapV1Pdu {
            enterprise,
            agent_addr,
            generic_trap,
            specific_trap,
            time_stamp,
            varbinds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CompatibilityPolicy;
    use crate::oid;

    fn compatibility_without_negative_bulk_normalization() -> CompatibilityPolicy {
        CompatibilityPolicy {
            normalize_negative_get_bulk_fields: false,
            ..CompatibilityPolicy::DEFAULT
        }
    }

    /// Test helper for encoding PDUs with arbitrary field values.
    ///
    /// Unlike `Pdu`, this allows encoding invalid values (negative `error_index`,
    /// out-of-bounds indices, etc.) for testing decoder validation.
    struct RawPdu {
        pdu_type: u8,
        request_id: i32,
        error_status: i32,
        error_index: i32,
        varbinds: Vec<VarBind>,
    }

    impl RawPdu {
        fn response(
            request_id: i32,
            error_status: i32,
            error_index: i32,
            varbinds: Vec<VarBind>,
        ) -> Self {
            Self {
                pdu_type: PduType::Response.tag(),
                request_id,
                error_status,
                error_index,
                varbinds,
            }
        }

        fn encode(&self) -> bytes::Bytes {
            let mut buf = EncodeBuf::new();
            buf.push_constructed(self.pdu_type, |buf| {
                encode_varbind_list(buf, &self.varbinds).unwrap();
                buf.push_integer(self.error_index);
                buf.push_integer(self.error_status);
                buf.push_integer(self.request_id);
            });
            buf.finish()
        }
    }

    /// Test helper for encoding GETBULK PDUs with arbitrary field values.
    struct RawBulkWirePdu {
        request_id: i32,
        non_repeaters: i32,
        max_repetitions: i32,
        varbinds: Vec<VarBind>,
    }

    impl RawBulkWirePdu {
        fn new(
            request_id: i32,
            non_repeaters: i32,
            max_repetitions: i32,
            varbinds: Vec<VarBind>,
        ) -> Self {
            Self {
                request_id,
                non_repeaters,
                max_repetitions,
                varbinds,
            }
        }

        fn encode(&self) -> bytes::Bytes {
            let mut buf = EncodeBuf::new();
            buf.push_constructed(tag::pdu::GET_BULK_REQUEST, |buf| {
                encode_varbind_list(buf, &self.varbinds).unwrap();
                buf.push_integer(self.max_repetitions);
                buf.push_integer(self.non_repeaters);
                buf.push_integer(self.request_id);
            });
            buf.finish()
        }
    }

    #[test]
    fn test_get_request_roundtrip() {
        let pdu = Pdu::get_request(12345, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);

        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf).unwrap();
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.pdu_type(), PduType::GetRequest);
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.varbinds.len(), 1);
    }

    #[test]
    fn test_getbulk_roundtrip() {
        let pdu =
            Pdu::get_bulk(12345, 0, 10, vec![VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1))]).unwrap();

        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf).unwrap();
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.get_bulk_fields(), Some((0, 10)));
    }

    #[test]
    fn get_bulk_constructor_checks_both_parameter_ranges() {
        let varbinds = || vec![VarBind::null(oid!(1, 3, 6, 1))];

        for (non_repeaters, max_repetitions) in
            [(0, 0), (MAX_GET_BULK_VALUE, 0), (0, MAX_GET_BULK_VALUE)]
        {
            let pdu = Pdu::get_bulk(1, non_repeaters, max_repetitions, varbinds()).unwrap();
            assert_eq!(
                pdu.get_bulk_fields(),
                Some((non_repeaters, max_repetitions))
            );
        }

        for (non_repeaters, max_repetitions) in
            [(MAX_GET_BULK_VALUE + 1, 0), (0, MAX_GET_BULK_VALUE + 1)]
        {
            let error = Pdu::get_bulk(1, non_repeaters, max_repetitions, varbinds()).unwrap_err();
            assert!(matches!(*error, Error::InvalidMessage(_)));
        }
    }

    #[test]
    fn protocol_integer_fields_never_use_generic_truncation() {
        // request-id is encoded as 2^32. Generic value decoding can truncate
        // this to zero by policy, but protocol Integer32 fields must reject it.
        let encoded = bytes::Bytes::from_static(&[
            0xa0, 0x0f, 0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
            0x00, 0x30, 0x00,
        ]);
        let mut decoder = Decoder::new(encoded);
        assert!(Pdu::decode(&mut decoder).is_err());
    }

    #[test]
    fn test_trap_v1_roundtrip() {
        use crate::value::Value;
        use crate::varbind::VarBind;

        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999), // enterprise OID
            [192, 168, 1, 1],             // agent address
            GenericTrap::LinkDown,
            0,
            1234_5678, // time stamp
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1),
                Value::Integer(1),
            )],
        );

        let mut buf = EncodeBuf::new();
        trap.encode(&mut buf).unwrap();
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = TrapV1Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999));
        assert_eq!(decoded.agent_addr, [192, 168, 1, 1]);
        assert_eq!(decoded.generic_trap, GenericTrap::LinkDown);
        assert_eq!(decoded.specific_trap, 0);
        assert_eq!(decoded.time_stamp, 1234_5678);
        assert_eq!(decoded.varbinds.len(), 1);
    }

    #[test]
    fn trap_v1_decode_rejects_unconsumed_constructed_body() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 0, 2, 1],
            GenericTrap::ColdStart,
            0,
            1,
            vec![],
        );
        let mut buf = EncodeBuf::new();
        trap.encode(&mut buf).unwrap();
        let mut encoded = buf.finish().to_vec();
        assert_eq!(encoded[0], tag::pdu::TRAP_V1);
        assert!(encoded[1] < 0x80, "fixture uses short-form length");
        encoded[1] += 2;
        encoded.extend_from_slice(&[tag::universal::NULL, 0]);

        let mut decoder = Decoder::new(bytes::Bytes::from(encoded));
        assert!(TrapV1Pdu::decode(&mut decoder).is_err());
    }

    #[test]
    fn test_generic_pdu_decode_rejects_trap_v1_tag() {
        // The v1 Trap PDU (tag 0xA4) has a distinct wire layout and must only be
        // decoded via TrapV1Pdu. The generic Pdu decoder must reject the tag so a
        // v1 Trap cannot slip into a v2c/v3 (generic PDU) context.
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            vec![],
        );
        let mut buf = EncodeBuf::new();
        trap.encode(&mut buf).unwrap();
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let result = Pdu::decode(&mut decoder);
        assert!(
            result.is_err(),
            "generic Pdu::decode must reject TrapV1 tag, got {result:?}"
        );
    }

    #[test]
    fn test_trap_v1_enterprise_specific() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2),
            [10, 0, 0, 1],
            GenericTrap::EnterpriseSpecific,
            42, // specific trap number
            100,
            vec![],
        );

        assert!(trap.is_enterprise_specific());
        assert_eq!(trap.generic_trap, GenericTrap::EnterpriseSpecific);

        let mut buf = EncodeBuf::new();
        trap.encode(&mut buf).unwrap();
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = TrapV1Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.specific_trap, 42);
    }

    #[test]
    fn test_trap_v1_v2_trap_oid_generic_traps() {
        // Test all generic trap types translate to correct snmpTraps.X OIDs
        // RFC 3584 Section 3: snmpTraps.{generic_trap + 1}

        let test_cases = [
            (GenericTrap::ColdStart, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)),
            (GenericTrap::WarmStart, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2)),
            (GenericTrap::LinkDown, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3)),
            (GenericTrap::LinkUp, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4)),
            (
                GenericTrap::AuthenticationFailure,
                oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5),
            ),
            (
                GenericTrap::EgpNeighborLoss,
                oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 6),
            ),
        ];

        for (generic_trap, expected_oid) in test_cases {
            let trap = TrapV1Pdu::new(
                oid!(1, 3, 6, 1, 4, 1, 9999),
                [192, 168, 1, 1],
                generic_trap,
                0,
                12345,
                vec![],
            );
            assert_eq!(
                trap.v2_trap_oid().unwrap(),
                expected_oid,
                "Failed for {generic_trap:?}"
            );
        }
    }

    #[test]
    fn test_trap_v1_v2_trap_oid_enterprise_specific() {
        // RFC 3584 Section 3: enterprise.0.specific_trap
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2),
            [192, 168, 1, 1],
            GenericTrap::EnterpriseSpecific,
            42,
            12345,
            vec![],
        );

        // Expected: 1.3.6.1.4.1.9999.1.2.0.42
        assert_eq!(
            trap.v2_trap_oid().unwrap(),
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2, 0, 42)
        );
    }

    #[test]
    fn test_trap_v1_v2_trap_oid_enterprise_specific_zero() {
        // Edge case: specific_trap = 0
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 1234),
            [10, 0, 0, 1],
            GenericTrap::EnterpriseSpecific,
            0,
            100,
            vec![],
        );

        // Expected: 1.3.6.1.4.1.1234.0.0
        assert_eq!(
            trap.v2_trap_oid().unwrap(),
            oid!(1, 3, 6, 1, 4, 1, 1234, 0, 0)
        );
    }

    #[test]
    fn test_pdu_to_response() {
        use crate::value::Value;
        use crate::varbind::VarBind;

        let inform = Pdu::standard(
            crate::pdu::StandardPduType::InformRequest,
            99999,
            0,
            0,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345)),
                VarBind::new(
                    oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0),
                    Value::ObjectIdentifier(oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)),
                ),
            ],
        );

        let response = inform.to_response();

        assert_eq!(response.pdu_type(), PduType::Response);
        assert_eq!(response.request_id, 99999);
        assert_eq!(response.error_status(), 0);
        assert_eq!(response.error_index(), 0);
        assert_eq!(response.varbinds.len(), 2);
    }

    #[test]
    fn test_pdu_is_confirmed() {
        let get = Pdu::get_request(1, &[oid!(1, 3, 6, 1)]);
        assert!(get.is_confirmed());

        let inform = Pdu::standard(crate::pdu::StandardPduType::InformRequest, 1, 0, 0, vec![]);
        assert!(inform.is_confirmed());

        let trap = Pdu::standard(crate::pdu::StandardPduType::TrapV2, 1, 0, 0, vec![]);
        assert!(!trap.is_confirmed());
        assert!(trap.is_notification());
    }

    #[test]
    fn test_decode_accepts_negative_error_index() {
        // net-snmp does not validate error_index at parse time; validation code
        // that once existed in snmp_client.c is wrapped in #ifdef TEMPORARILY_DISABLED
        // and is never compiled. Buggy agents that send negative error_index values
        // are accepted by net-snmp and must be accepted here too, or users will
        // report "works with net-snmp but not your library".
        let raw = RawPdu::response(1, 0, -1, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);

        assert!(
            result.is_ok(),
            "negative error_index must be accepted to match net-snmp behavior, got {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().error_index(), -1);
    }

    #[test]
    fn test_decode_accepts_error_index_beyond_varbinds() {
        // net-snmp does not bounds-check error_index against the varbind list length.
        // RFC 3416 Section 3 defines error-index as INTEGER (0..max-bindings) and
        // annotates it "sometimes ignored"; it places no MUST/SHOULD obligation on
        // receivers to reject out-of-range values. Buggy agents that send an
        // error_index larger than the varbind count are accepted by net-snmp.
        let raw = RawPdu::response(1, 5, 5, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);

        assert!(
            result.is_ok(),
            "error_index beyond varbind count must be accepted to match net-snmp behavior, got {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().error_index(), 5);
    }

    #[test]
    fn test_decode_accepts_valid_error_index_zero() {
        // error_index=0 with no error is valid
        let raw = RawPdu::response(1, 0, 0, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let decoded = Pdu::decode(&mut decoder);
        assert!(decoded.is_ok(), "error_index=0 should be valid");
    }

    #[test]
    fn test_decode_accepts_error_index_within_bounds() {
        // error_index=1 with 1 varbind is valid (1-based indexing)
        let raw = RawPdu::response(1, 5, 1, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);
        assert!(
            result.is_ok(),
            "error_index=1 with 1 varbind should be valid"
        );
    }

    #[test]
    fn test_decode_clamps_negative_non_repeaters() {
        // RFC 3416 Section 4.2.3: non-repeaters is INTEGER (0..2147483647).
        // A negative value from a buggy peer is normalized to 0 (net-snmp
        // snmp_agent.c behavior) rather than rejected.
        let raw = RawBulkWirePdu::new(1, -1, 10, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded.clone());
        let decoded = Pdu::decode(&mut decoder).expect("negative non_repeaters clamps to 0");
        assert_eq!(decoded.get_bulk_fields(), Some((0, 10)));

        let mut strict = Decoder::new(encoded)
            .with_compatibility_policy(compatibility_without_negative_bulk_normalization());
        let error = Pdu::decode(&mut strict).unwrap_err();
        assert!(matches!(*error, Error::MalformedResponse { .. }));
    }

    #[test]
    fn test_decode_clamps_negative_max_repetitions() {
        let raw = RawBulkWirePdu::new(1, 0, -5, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded.clone());
        let decoded = Pdu::decode(&mut decoder).expect("negative max_repetitions clamps to 0");
        assert_eq!(decoded.get_bulk_fields(), Some((0, 0)));

        let mut strict = Decoder::new(encoded)
            .with_compatibility_policy(compatibility_without_negative_bulk_normalization());
        let error = Pdu::decode(&mut strict).unwrap_err();
        assert!(matches!(*error, Error::MalformedResponse { .. }));
    }

    #[test]
    fn test_pdu_decode_getbulk_clamps_negative_non_repeaters_repro() {
        // Regression (audit F06): production GETBULK decode goes through the
        // generic Pdu::decode path (community.rs / v3.rs), which must clamp the
        // typed non-repeaters/max-repetitions to 0 for negatives.
        // Repro packet: GETBULK, request_id=1, non_repeaters=-1 (0xff),
        // max_repetitions=1, empty varbinds.
        let packet = [
            0xa5, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff, 0x02, 0x01, 0x01, 0x30, 0x00,
        ];
        let encoded = bytes::Bytes::copy_from_slice(&packet);
        let mut decoder = Decoder::new(encoded.clone());
        let pdu = Pdu::decode(&mut decoder).expect("repro GETBULK packet must decode");
        assert_eq!(pdu.pdu_type(), PduType::GetBulkRequest);
        assert_eq!(pdu.request_id, 1);
        assert_eq!(pdu.get_bulk_fields(), Some((0, 1)));

        let mut strict = Decoder::new(encoded)
            .with_compatibility_policy(compatibility_without_negative_bulk_normalization());
        assert!(Pdu::decode(&mut strict).is_err());
    }

    #[test]
    fn test_decode_accepts_valid_getbulk_params() {
        let raw = RawBulkWirePdu::new(1, 0, 10, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);
        assert!(result.is_ok(), "valid GETBULK params should be accepted");

        let pdu = result.unwrap();
        assert_eq!(pdu.get_bulk_fields(), Some((0, 10)));
    }

    #[test]
    fn encode_rejects_out_of_range_get_bulk_fields_without_mutation() {
        for (non_repeaters, max_repetitions) in
            [(MAX_GET_BULK_VALUE + 1, 0), (0, MAX_GET_BULK_VALUE + 1)]
        {
            let pdu = Pdu {
                request_id: 1,
                body: PduBody::GetBulk {
                    non_repeaters,
                    max_repetitions,
                },
                varbinds: vec![VarBind::null(oid!(1, 3, 6, 1))],
            };
            let original = pdu.clone();
            let mut buf = EncodeBuf::new();

            assert!(pdu.encode(&mut buf).is_err());
            assert!(buf.is_empty());
            assert_eq!(pdu, original);
        }
    }

    #[test]
    fn test_encode_leaves_non_negative_non_repeaters_and_max_repetitions_unchanged() {
        let pdu = Pdu::get_bulk(1, 0, 10, vec![VarBind::null(oid!(1, 3, 6, 1))]).unwrap();

        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf).unwrap();
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Pdu::decode(&mut decoder).unwrap();
        assert_eq!(decoded.get_bulk_fields(), Some((0, 10)));
    }

    #[test]
    fn compatible_decode_constructs_encodable_canonical_body() {
        let raw = RawBulkWirePdu::new(1, -1, -5, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let mut decoder = Decoder::new(raw.encode());
        let decoded = Pdu::decode(&mut decoder).unwrap();
        assert_eq!(decoded.get_bulk_fields(), Some((0, 0)));

        let mut buf = EncodeBuf::new();
        decoded.encode(&mut buf).unwrap();
        let mut roundtrip_decoder = Decoder::new(buf.finish());
        let roundtrip = Pdu::decode(&mut roundtrip_decoder).unwrap();
        assert_eq!(roundtrip.get_bulk_fields(), Some((0, 0)));
    }

    #[test]
    fn test_pdu_decode_getbulk_with_large_max_repetitions() {
        // GETBULK PDU with max_repetitions (25) > varbinds.len() (1)
        // This is the normal case for GETBULK requests.
        // The canonical Pdu::decode must not reject this valid max-repetitions value.
        let raw = RawBulkWirePdu::new(12345, 0, 25, vec![VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);
        assert!(
            result.is_ok(),
            "Pdu::decode should accept GETBULK with max_repetitions > varbinds.len(), got {:?}",
            result.err()
        );

        let pdu = result.unwrap();
        assert_eq!(pdu.pdu_type(), PduType::GetBulkRequest);
        assert_eq!(pdu.request_id, 12345);
        assert_eq!(pdu.get_bulk_fields(), Some((0, 25)));
        assert_eq!(pdu.varbinds.len(), 1);
    }

    #[test]
    fn test_getbulk_request_is_not_treated_as_error() {
        let pdu = Pdu::get_bulk(
            12345,
            2,
            10,
            vec![
                VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1)),
                VarBind::null(oid!(1, 3, 6, 1, 2, 1, 2)),
            ],
        )
        .unwrap();

        assert!(!pdu.is_error());
    }

    #[test]
    fn test_response_with_error_status_is_treated_as_error() {
        let pdu = Pdu::response(
            12345,
            ErrorStatus::TooBig.as_i32(),
            1,
            vec![VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1))],
        );

        assert!(pdu.is_error());
    }

    #[test]
    fn outbound_validation_rejects_nonzero_request_error_fields() {
        for (status, index) in [(1, 0), (0, 1), (1, 1)] {
            let pdu = Pdu::standard(
                StandardPduType::GetRequest,
                1,
                status,
                index,
                vec![VarBind::null(oid!(1, 3, 6, 1))],
            );
            assert!(pdu.encode(&mut EncodeBuf::new()).is_err());
        }
    }

    #[test]
    fn outbound_validation_checks_response_status_and_index_combinations() {
        let varbinds = vec![VarBind::null(oid!(1, 3, 6, 1))];
        for (status, index) in [
            (0, 1),
            (1, 1),
            (-1, 0),
            (19, 0),
            (5, -1),
            (5, 0),
            (5, 2),
            (ErrorStatus::UndoFailed.as_i32(), 1),
        ] {
            let pdu = Pdu::response(1, status, index, varbinds.clone());
            assert!(
                pdu.encode(&mut EncodeBuf::new()).is_err(),
                "{status}/{index}"
            );
        }

        let gen_err = Pdu::response(1, ErrorStatus::GenErr.as_i32(), 1, varbinds.clone());
        assert!(gen_err.encode(&mut EncodeBuf::new()).is_ok());
        let undo_failed = Pdu::response(1, ErrorStatus::UndoFailed.as_i32(), 0, varbinds.clone());
        assert!(undo_failed.encode(&mut EncodeBuf::new()).is_ok());
        assert!(
            undo_failed
                .encode_for(&mut EncodeBuf::new(), Version::V1, PduDirection::Response,)
                .is_err()
        );
    }

    #[test]
    fn outbound_validation_allows_exceptions_only_in_v2_or_v3_responses() {
        let varbinds = vec![VarBind::new(oid!(1, 3, 6, 1), Value::NoSuchObject)];
        let request = Pdu::get_request(1, &[]);
        let mut request = Pdu {
            varbinds: varbinds.clone(),
            ..request
        };
        let original = request.clone();
        assert!(request.encode(&mut EncodeBuf::new()).is_err());
        assert_eq!(request, original);

        request.set_standard_pdu_type(StandardPduType::Response);
        assert!(request.encode(&mut EncodeBuf::new()).is_ok());
        assert!(
            request
                .encode_for(&mut EncodeBuf::new(), Version::V1, PduDirection::Response,)
                .is_err()
        );
    }

    #[test]
    fn outbound_validation_rejects_receive_only_values_without_mutation() {
        for value in [
            Value::UInteger32(1),
            Value::Nsap(bytes::Bytes::from_static(b"nsap")),
            Value::Unknown {
                tag: 0x48,
                data: bytes::Bytes::from_static(b"raw"),
            },
        ] {
            let pdu = Pdu::set_request(1, vec![VarBind::new(oid!(1, 3, 6, 1), value)]);
            let original = pdu.clone();
            assert!(pdu.encode(&mut EncodeBuf::new()).is_err());
            assert_eq!(pdu, original);
        }
    }

    #[test]
    fn pdu_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PduType::GetRequest);
        set.insert(PduType::GetNextRequest);
        assert_eq!(set.len(), 2);
        assert!(set.contains(&PduType::GetRequest));
    }

    // =========================================================================
    // V1 <-> V2 PDU conversion tests
    // =========================================================================

    #[test]
    fn test_v1_to_v2_generic_trap() {
        use crate::value::Value;
        use crate::varbind::VarBind;

        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1),
                Value::Integer(1),
            )],
        );

        let pdu = trap.to_v2_pdu().unwrap();

        assert_eq!(pdu.pdu_type(), PduType::TrapV2);
        assert_eq!(pdu.request_id, 0);
        // sysUpTime.0 + snmpTrapOID.0 + 1 original varbind (no proxy varbinds)
        assert_eq!(pdu.varbinds.len(), 3);

        // First varbind: sysUpTime.0
        assert_eq!(pdu.varbinds[0].oid, oid!(1, 3, 6, 1, 2, 1, 1, 3, 0));
        assert_eq!(pdu.varbinds[0].value, Value::TimeTicks(12345));

        // Second varbind: snmpTrapOID.0 = snmpTraps.3 (linkDown)
        assert_eq!(pdu.varbinds[1].oid, oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0));
        assert_eq!(
            pdu.varbinds[1].value,
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3))
        );

        // Third: original varbind
        assert_eq!(pdu.varbinds[2].oid, oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1));
    }

    #[test]
    fn test_v1_to_v2_no_proxy_varbinds() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::ColdStart,
            0,
            100,
            vec![],
        );

        let pdu = trap.to_v2_pdu().unwrap();
        // Only sysUpTime.0 and snmpTrapOID.0 - no proxy varbinds even with
        // non-zero agent_addr (RFC 3584 Section 3.1(4))
        assert_eq!(pdu.varbinds.len(), 2);
    }

    #[test]
    fn test_v1_to_v2_enterprise_specific() {
        use crate::value::Value;

        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2),
            [10, 0, 0, 1],
            GenericTrap::EnterpriseSpecific,
            42,
            5000,
            vec![],
        );

        let pdu = trap.to_v2_pdu().unwrap();

        // snmpTrapOID.0 should be enterprise.0.42
        assert_eq!(
            pdu.varbinds[1].value,
            Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2, 0, 42))
        );
    }

    #[test]
    fn test_v2_to_v1_standard_trap() {
        use crate::value::Value;
        use crate::varbind::VarBind;

        let pdu = Pdu::trap_v2(
            1,
            5000,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3), // linkDown
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1),
                Value::Integer(1),
            )],
        );

        let trap = pdu.to_v1_trap([10, 0, 0, 1]).unwrap();

        assert_eq!(trap.generic_trap, GenericTrap::LinkDown);
        assert_eq!(trap.specific_trap, 0);
        assert_eq!(trap.time_stamp, 5000);
        assert_eq!(trap.agent_addr, [10, 0, 0, 1]);
        // Enterprise defaults to snmpTraps when no snmpTrapEnterprise.0 varbind
        assert_eq!(trap.enterprise, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5));
        assert_eq!(trap.varbinds.len(), 1);
    }

    #[test]
    fn test_v2_to_v1_enterprise_specific_trap() {
        let pdu = Pdu::trap_v2(1, 100, &oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2, 0, 42), vec![]);

        let trap = pdu.to_v1_trap([0, 0, 0, 0]).unwrap();

        assert_eq!(trap.generic_trap, GenericTrap::EnterpriseSpecific);
        assert_eq!(trap.specific_trap, 42);
        assert_eq!(trap.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2));
        assert_eq!(trap.time_stamp, 100);
    }

    #[test]
    fn test_v2_to_v1_enterprise_specific_nonzero_penultimate() {
        // RFC 3584 Section 3.2: when next-to-last sub-id is non-zero,
        // enterprise is snmpTrapOID with only the last sub-id removed.
        let pdu = Pdu::trap_v2(1, 200, &oid!(1, 3, 6, 1, 4, 1, 9999, 1, 42), vec![]);

        let trap = pdu.to_v1_trap([0, 0, 0, 0]).unwrap();

        assert_eq!(trap.generic_trap, GenericTrap::EnterpriseSpecific);
        assert_eq!(trap.specific_trap, 42);
        // Next-to-last arc is 1 (non-zero), so only last arc stripped
        assert_eq!(trap.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999, 1));
        assert_eq!(trap.time_stamp, 200);
    }

    #[test]
    fn test_v2_to_v1_snmp_traps_arc_out_of_range() {
        // RFC 3584 Section 3.2 rules (1), (3), (4): snmpTraps.x with x=0 or
        // x>6 is not a standard trap, so enterprise = OID minus last arc
        // (next-to-last arc 5 is non-zero), generic = 6, specific = last arc.
        for arc in [0u32, 7, 9] {
            let pdu = Pdu::trap_v2(1, 100, &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, arc), vec![]);

            let trap = pdu.to_v1_trap([0, 0, 0, 0]).unwrap();

            assert_eq!(trap.generic_trap, GenericTrap::EnterpriseSpecific);
            assert_eq!(trap.specific_trap, i32::try_from(arc).unwrap());
            assert_eq!(trap.enterprise, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5));
        }
    }

    #[test]
    fn test_v2_to_v1_extracts_trap_address() {
        use crate::notification::oids;
        use crate::value::Value;
        use crate::varbind::VarBind;

        let pdu = Pdu::trap_v2(
            1,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), // coldStart
            vec![VarBind::new(
                oids::snmp_trap_address(),
                Value::IpAddress([192, 168, 1, 1]),
            )],
        );

        let trap = pdu.to_v1_trap([0, 0, 0, 0]).unwrap();
        assert_eq!(trap.agent_addr, [192, 168, 1, 1]);
        // RFC 3584 Section 3.2 rule (6): only sysUpTime.0 and snmpTrapOID.0
        // are excluded; snmpTrapAddress.0 is retained in the varbinds
        assert_eq!(trap.varbinds.len(), 1);
        assert_eq!(trap.varbinds[0].oid, oids::snmp_trap_address());
    }

    #[test]
    fn test_v2_to_v1_extracts_trap_enterprise() {
        use crate::notification::oids;
        use crate::value::Value;
        use crate::varbind::VarBind;

        let pdu = Pdu::trap_v2(
            1,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), // coldStart
            vec![VarBind::new(
                oids::snmp_trap_enterprise(),
                Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 9999)),
            )],
        );

        let trap = pdu.to_v1_trap([0, 0, 0, 0]).unwrap();
        // Standard trap should use the enterprise from snmpTrapEnterprise.0
        assert_eq!(trap.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999));
        // RFC 3584 Section 3.2 rule (6): only sysUpTime.0 and snmpTrapOID.0
        // are excluded; snmpTrapEnterprise.0 is retained in the varbinds
        assert_eq!(trap.varbinds.len(), 1);
        assert_eq!(trap.varbinds[0].oid, oids::snmp_trap_enterprise());
    }

    #[test]
    fn test_v2_to_v1_counter64_dropped() {
        use crate::value::Value;
        use crate::varbind::VarBind;

        let pdu = Pdu::trap_v2(
            1,
            0,
            &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1),
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                Value::Counter64(12345),
            )],
        );

        // Counter64 in any varbind means the trap cannot be represented in V1
        assert!(pdu.to_v1_trap([0, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_v2_to_v1_too_few_varbinds() {
        let pdu = Pdu::standard(crate::pdu::StandardPduType::TrapV2, 1, 0, 0, vec![]);

        assert!(pdu.to_v1_trap([0, 0, 0, 0]).is_none());
    }

    #[test]
    fn test_v1_v2_roundtrip_enterprise_specific() {
        use crate::value::Value;
        use crate::varbind::VarBind;

        // Enterprise-specific traps preserve enterprise and specific_trap
        // through the OID encoding (enterprise.0.specific_trap), so these
        // fields survive a non-proxy v1->v2->v1 roundtrip. agent_addr is
        // lost (comes from default_addr on the v1 side).
        let original = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999, 1, 2),
            [192, 168, 1, 1],
            GenericTrap::EnterpriseSpecific,
            42,
            12345,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1),
                Value::Integer(1),
            )],
        );

        let v2 = original.to_v2_pdu().unwrap();
        let restored = v2.to_v1_trap([0, 0, 0, 0]).unwrap();

        assert_eq!(restored.enterprise, original.enterprise);
        assert_eq!(restored.generic_trap, original.generic_trap);
        assert_eq!(restored.specific_trap, original.specific_trap);
        assert_eq!(restored.time_stamp, original.time_stamp);
        assert_eq!(restored.varbinds.len(), original.varbinds.len());
        assert_eq!(restored.varbinds[0].oid, original.varbinds[0].oid);
        // agent_addr not preserved without proxy varbinds
        assert_eq!(restored.agent_addr, [0, 0, 0, 0]);
    }

    #[test]
    fn test_v1_v2_roundtrip_standard_trap() {
        // Standard trap roundtrip preserves generic_trap and time_stamp.
        // Without proxy varbinds, enterprise falls back to snmpTraps and
        // agent_addr comes from default_addr.
        let original = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [10, 0, 0, 1],
            GenericTrap::WarmStart,
            0,
            500,
            vec![],
        );

        let v2 = original.to_v2_pdu().unwrap();
        let restored = v2.to_v1_trap([10, 0, 0, 1]).unwrap();

        assert_eq!(restored.generic_trap, GenericTrap::WarmStart);
        assert_eq!(restored.specific_trap, 0);
        assert_eq!(restored.time_stamp, 500);
        assert_eq!(restored.agent_addr, [10, 0, 0, 1]); // from default_addr
        // Enterprise falls back to snmpTraps without snmpTrapEnterprise.0
        assert_eq!(restored.enterprise, oid!(1, 3, 6, 1, 6, 3, 1, 1, 5));
    }

    #[test]
    fn test_v2_to_v1_all_generic_traps() {
        // Verify all 6 standard traps roundtrip correctly
        let traps = [
            (oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), GenericTrap::ColdStart),
            (oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 2), GenericTrap::WarmStart),
            (oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 3), GenericTrap::LinkDown),
            (oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 4), GenericTrap::LinkUp),
            (
                oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 5),
                GenericTrap::AuthenticationFailure,
            ),
            (
                oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 6),
                GenericTrap::EgpNeighborLoss,
            ),
        ];

        for (trap_oid, expected_generic) in traps {
            let pdu = Pdu::trap_v2(1, 100, &trap_oid, vec![]);
            let v1 = pdu.to_v1_trap([0, 0, 0, 0]).unwrap();
            assert_eq!(v1.generic_trap, expected_generic, "Failed for {trap_oid:?}");
            assert_eq!(v1.specific_trap, 0);
        }
    }
}
