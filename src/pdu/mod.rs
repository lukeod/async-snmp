//! SNMP Protocol Data Units (PDUs).
//!
//! PDUs represent the different SNMP operations.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::error::{DecodeErrorKind, Error, ErrorStatus, Result};
use crate::oid::Oid;
use crate::varbind::{VarBind, decode_varbind_list, encode_varbind_list};

/// PDU type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// SNMPv1 trap - unsolicited notification from an agent.
    TrapV1 = 0xA4,
    /// GET-BULK request - efficient bulk retrieval of table data.
    GetBulkRequest = 0xA5,
    /// INFORM request - acknowledged notification.
    InformRequest = 0xA6,
    /// SNMPv2c/v3 trap - unsolicited notification from an agent.
    TrapV2 = 0xA7,
    /// Report - used in SNMPv3 for engine discovery and error reporting.
    Report = 0xA8,
}

impl PduType {
    /// Create from tag byte.
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

/// Generic PDU structure for request/response operations.
#[derive(Debug, Clone)]
pub struct Pdu {
    /// PDU type
    pub pdu_type: PduType,
    /// Request ID for correlating requests and responses
    pub request_id: i32,
    /// Error status (0 for requests, error code for responses)
    pub error_status: i32,
    /// Error index (1-based index of problematic varbind)
    pub error_index: i32,
    /// Variable bindings
    pub varbinds: Vec<VarBind>,
}

impl Pdu {
    /// Create a new GET request PDU.
    pub fn get_request(request_id: i32, oids: &[Oid]) -> Self {
        Self {
            pdu_type: PduType::GetRequest,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: oids.iter().map(|oid| VarBind::null(oid.clone())).collect(),
        }
    }

    /// Create a new GETNEXT request PDU.
    pub fn get_next_request(request_id: i32, oids: &[Oid]) -> Self {
        Self {
            pdu_type: PduType::GetNextRequest,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: oids.iter().map(|oid| VarBind::null(oid.clone())).collect(),
        }
    }

    /// Create a new SET request PDU.
    pub fn set_request(request_id: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            pdu_type: PduType::SetRequest,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds,
        }
    }

    /// Create a GETBULK request PDU.
    ///
    /// Note: For GETBULK, error_status holds non_repeaters and error_index holds max_repetitions.
    pub fn get_bulk(
        request_id: i32,
        non_repeaters: i32,
        max_repetitions: i32,
        varbinds: Vec<VarBind>,
    ) -> Self {
        Self {
            pdu_type: PduType::GetBulkRequest,
            request_id,
            error_status: non_repeaters,
            error_index: max_repetitions,
            varbinds,
        }
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_constructed(self.pdu_type.tag(), |buf| {
            encode_varbind_list(buf, &self.varbinds);
            buf.push_integer(self.error_index);
            buf.push_integer(self.error_status);
            buf.push_integer(self.request_id);
        });
    }

    /// Decode from BER (after tag has been peeked).
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let tag = decoder.read_tag()?;
        let pdu_type = PduType::from_tag(tag)
            .ok_or_else(|| Error::decode(decoder.offset(), DecodeErrorKind::UnknownPduType(tag)))?;

        let len = decoder.read_length()?;
        let mut pdu_decoder = decoder.sub_decoder(len)?;

        let request_id = pdu_decoder.read_integer()?;
        let error_status = pdu_decoder.read_integer()?;
        let error_index = pdu_decoder.read_integer()?;
        let varbinds = decode_varbind_list(&mut pdu_decoder)?;

        // Validate error_index bounds per RFC 3416 Section 3.
        // error_index is 1-based: 0 means no error, 1..=len points to specific varbind.
        // Note: For GETBULK, error_status holds non_repeaters and error_index holds
        // max_repetitions, so these validations don't apply.
        if pdu_type != PduType::GetBulkRequest {
            if error_index < 0 {
                return Err(Error::decode(
                    pdu_decoder.offset(),
                    DecodeErrorKind::NegativeErrorIndex { value: error_index },
                ));
            }
            if error_index > 0 && (error_index as usize) > varbinds.len() {
                return Err(Error::decode(
                    pdu_decoder.offset(),
                    DecodeErrorKind::ErrorIndexOutOfBounds {
                        index: error_index,
                        varbind_count: varbinds.len(),
                    },
                ));
            }
        }

        Ok(Pdu {
            pdu_type,
            request_id,
            error_status,
            error_index,
            varbinds,
        })
    }

    /// Check if this is an error response.
    pub fn is_error(&self) -> bool {
        self.error_status != 0
    }

    /// Get the error status as an enum.
    pub fn error_status_enum(&self) -> ErrorStatus {
        ErrorStatus::from_i32(self.error_status)
    }

    /// Create a Response PDU from this PDU (for Inform handling).
    ///
    /// The response copies the request_id and variable bindings,
    /// sets error_status and error_index to 0, and changes the PDU type to Response.
    pub fn to_response(&self) -> Self {
        Self {
            pdu_type: PduType::Response,
            request_id: self.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: self.varbinds.clone(),
        }
    }

    /// Create a Response PDU with specific error status.
    pub fn to_error_response(&self, error_status: ErrorStatus, error_index: i32) -> Self {
        Self {
            pdu_type: PduType::Response,
            request_id: self.request_id,
            error_status: error_status.as_i32(),
            error_index,
            varbinds: self.varbinds.clone(),
        }
    }

    /// Check if this is a notification PDU (Trap or Inform).
    pub fn is_notification(&self) -> bool {
        matches!(
            self.pdu_type,
            PduType::TrapV1 | PduType::TrapV2 | PduType::InformRequest
        )
    }

    /// Check if this is a confirmed-class PDU (requires response).
    pub fn is_confirmed(&self) -> bool {
        matches!(
            self.pdu_type,
            PduType::GetRequest
                | PduType::GetNextRequest
                | PduType::GetBulkRequest
                | PduType::SetRequest
                | PduType::InformRequest
        )
    }
}

/// SNMPv1 generic trap types (RFC 1157 Section 4.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GenericTrap {
    /// coldStart(0) - agent is reinitializing, config may change
    ColdStart = 0,
    /// warmStart(1) - agent is reinitializing, config unchanged
    WarmStart = 1,
    /// linkDown(2) - communication link failure
    LinkDown = 2,
    /// linkUp(3) - communication link came up
    LinkUp = 3,
    /// authenticationFailure(4) - improperly authenticated message received
    AuthenticationFailure = 4,
    /// egpNeighborLoss(5) - EGP peer marked down
    EgpNeighborLoss = 5,
    /// enterpriseSpecific(6) - vendor-specific trap, see specific_trap field
    EnterpriseSpecific = 6,
}

impl GenericTrap {
    /// Create from integer value.
    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::ColdStart),
            1 => Some(Self::WarmStart),
            2 => Some(Self::LinkDown),
            3 => Some(Self::LinkUp),
            4 => Some(Self::AuthenticationFailure),
            5 => Some(Self::EgpNeighborLoss),
            6 => Some(Self::EnterpriseSpecific),
            _ => None,
        }
    }

    /// Get the integer value.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// SNMPv1 Trap PDU (RFC 1157 Section 4.1.6).
///
/// This PDU type has a completely different structure from other PDUs.
/// It is only used in SNMPv1 and is replaced by SNMPv2-Trap in v2c/v3.
#[derive(Debug, Clone)]
pub struct TrapV1Pdu {
    /// Enterprise OID (sysObjectID of the entity generating the trap)
    pub enterprise: Oid,
    /// Agent address (IP address of the agent generating the trap)
    pub agent_addr: [u8; 4],
    /// Generic trap type
    pub generic_trap: i32,
    /// Specific trap code (meaningful when generic_trap is enterpriseSpecific)
    pub specific_trap: i32,
    /// Time since the network entity was last (re)initialized (in hundredths of seconds)
    pub time_stamp: u32,
    /// Variable bindings containing "interesting" information
    pub varbinds: Vec<VarBind>,
}

impl TrapV1Pdu {
    /// Create a new SNMPv1 Trap PDU.
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
            generic_trap: generic_trap.as_i32(),
            specific_trap,
            time_stamp,
            varbinds,
        }
    }

    /// Get the generic trap type as an enum.
    pub fn generic_trap_enum(&self) -> Option<GenericTrap> {
        GenericTrap::from_i32(self.generic_trap)
    }

    /// Check if this is an enterprise-specific trap.
    pub fn is_enterprise_specific(&self) -> bool {
        self.generic_trap == GenericTrap::EnterpriseSpecific as i32
    }

    /// Convert to SNMPv2 trap OID (RFC 3584 Section 3).
    ///
    /// RFC 3584 defines how to translate SNMPv1 trap information to SNMPv2
    /// snmpTrapOID.0 format:
    ///
    /// - For generic traps 0-5 (coldStart through egpNeighborLoss):
    ///   The trap OID is `snmpTraps.{generic_trap + 1}` (1.3.6.1.6.3.1.1.5.{1-6})
    ///
    /// - For enterprise-specific traps (generic_trap = 6):
    ///   The trap OID is `enterprise.0.specific_trap`
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidTrap`] if:
    /// - `generic_trap < 0` (undefined per RFC 1157)
    /// - `generic_trap == i32::MAX` (would overflow when adding 1)
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
                return Err(crate::Error::InvalidTrap {
                    reason: "specific_trap cannot be negative",
                });
            }
            let mut arcs: Vec<u32> = self.enterprise.arcs().to_vec();
            arcs.push(0);
            arcs.push(self.specific_trap as u32);
            Ok(Oid::new(arcs))
        } else {
            if self.generic_trap < 0 {
                return Err(crate::Error::InvalidTrap {
                    reason: "generic_trap cannot be negative",
                });
            }
            if self.generic_trap == i32::MAX {
                return Err(crate::Error::InvalidTrap {
                    reason: "generic_trap overflow",
                });
            }
            let trap_num = self.generic_trap + 1;
            Ok(crate::oid!(1, 3, 6, 1, 6, 3, 1, 1, 5).child(trap_num as u32))
        }
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_constructed(tag::pdu::TRAP_V1, |buf| {
            encode_varbind_list(buf, &self.varbinds);
            buf.push_unsigned32(tag::application::TIMETICKS, self.time_stamp);
            buf.push_integer(self.specific_trap);
            buf.push_integer(self.generic_trap);
            // NetworkAddress is APPLICATION 0 IMPLICIT IpAddress
            // IpAddress is APPLICATION 0 IMPLICIT OCTET STRING (SIZE (4))
            buf.push_bytes(&self.agent_addr);
            buf.push_length(4);
            buf.push_tag(tag::application::IP_ADDRESS);
            buf.push_oid(&self.enterprise);
        });
    }

    /// Decode from BER (after tag has been peeked).
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut pdu = decoder.read_constructed(tag::pdu::TRAP_V1)?;

        // enterprise OBJECT IDENTIFIER
        let enterprise = pdu.read_oid()?;

        // agent-addr NetworkAddress (IpAddress)
        let agent_tag = pdu.read_tag()?;
        if agent_tag != tag::application::IP_ADDRESS {
            return Err(Error::decode(
                pdu.offset(),
                DecodeErrorKind::UnexpectedTag {
                    expected: 0x40,
                    actual: agent_tag,
                },
            ));
        }
        let agent_len = pdu.read_length()?;
        if agent_len != 4 {
            return Err(Error::decode(
                pdu.offset(),
                DecodeErrorKind::InvalidIpAddressLength { length: agent_len },
            ));
        }
        let agent_bytes = pdu.read_bytes(4)?;
        let agent_addr = [
            agent_bytes[0],
            agent_bytes[1],
            agent_bytes[2],
            agent_bytes[3],
        ];

        // generic-trap INTEGER
        let generic_trap = pdu.read_integer()?;

        // specific-trap INTEGER
        let specific_trap = pdu.read_integer()?;

        // time-stamp TimeTicks
        let ts_tag = pdu.read_tag()?;
        if ts_tag != tag::application::TIMETICKS {
            return Err(Error::decode(
                pdu.offset(),
                DecodeErrorKind::UnexpectedTag {
                    expected: 0x43,
                    actual: ts_tag,
                },
            ));
        }
        let ts_len = pdu.read_length()?;
        let time_stamp = pdu.read_unsigned32_value(ts_len)?;

        // variable-bindings
        let varbinds = decode_varbind_list(&mut pdu)?;

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

/// GETBULK request PDU.
#[derive(Debug, Clone)]
pub struct GetBulkPdu {
    /// Request ID
    pub request_id: i32,
    /// Number of non-repeating OIDs
    pub non_repeaters: i32,
    /// Maximum repetitions for repeating OIDs
    pub max_repetitions: i32,
    /// Variable bindings
    pub varbinds: Vec<VarBind>,
}

impl GetBulkPdu {
    /// Create a new GETBULK request.
    pub fn new(request_id: i32, non_repeaters: i32, max_repetitions: i32, oids: &[Oid]) -> Self {
        Self {
            request_id,
            non_repeaters,
            max_repetitions,
            varbinds: oids.iter().map(|oid| VarBind::null(oid.clone())).collect(),
        }
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_constructed(tag::pdu::GET_BULK_REQUEST, |buf| {
            encode_varbind_list(buf, &self.varbinds);
            buf.push_integer(self.max_repetitions);
            buf.push_integer(self.non_repeaters);
            buf.push_integer(self.request_id);
        });
    }

    /// Decode from BER.
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut pdu = decoder.read_constructed(tag::pdu::GET_BULK_REQUEST)?;

        let request_id = pdu.read_integer()?;
        let non_repeaters = pdu.read_integer()?;
        let max_repetitions = pdu.read_integer()?;
        let varbinds = decode_varbind_list(&mut pdu)?;

        // Validate non_repeaters and max_repetitions per RFC 3416 Section 4.2.3.
        if non_repeaters < 0 {
            return Err(Error::decode(
                pdu.offset(),
                DecodeErrorKind::NegativeNonRepeaters {
                    value: non_repeaters,
                },
            ));
        }
        if max_repetitions < 0 {
            return Err(Error::decode(
                pdu.offset(),
                DecodeErrorKind::NegativeMaxRepetitions {
                    value: max_repetitions,
                },
            ));
        }

        Ok(GetBulkPdu {
            request_id,
            non_repeaters,
            max_repetitions,
            varbinds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    /// Test helper for encoding PDUs with arbitrary field values.
    ///
    /// Unlike `Pdu`, this allows encoding invalid values (negative error_index,
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
                encode_varbind_list(buf, &self.varbinds);
                buf.push_integer(self.error_index);
                buf.push_integer(self.error_status);
                buf.push_integer(self.request_id);
            });
            buf.finish()
        }
    }

    /// Test helper for encoding GETBULK PDUs with arbitrary field values.
    struct RawGetBulkPdu {
        request_id: i32,
        non_repeaters: i32,
        max_repetitions: i32,
        varbinds: Vec<VarBind>,
    }

    impl RawGetBulkPdu {
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
                encode_varbind_list(buf, &self.varbinds);
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
        pdu.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.pdu_type, PduType::GetRequest);
        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.varbinds.len(), 1);
    }

    #[test]
    fn test_getbulk_roundtrip() {
        let pdu = GetBulkPdu::new(12345, 0, 10, &[oid!(1, 3, 6, 1, 2, 1, 1)]);

        let mut buf = EncodeBuf::new();
        pdu.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = GetBulkPdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.request_id, 12345);
        assert_eq!(decoded.non_repeaters, 0);
        assert_eq!(decoded.max_repetitions, 10);
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
            12345678, // time stamp
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1),
                Value::Integer(1),
            )],
        );

        let mut buf = EncodeBuf::new();
        trap.encode(&mut buf);
        let bytes = buf.finish();

        let mut decoder = Decoder::new(bytes);
        let decoded = TrapV1Pdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999));
        assert_eq!(decoded.agent_addr, [192, 168, 1, 1]);
        assert_eq!(decoded.generic_trap, GenericTrap::LinkDown as i32);
        assert_eq!(decoded.specific_trap, 0);
        assert_eq!(decoded.time_stamp, 12345678);
        assert_eq!(decoded.varbinds.len(), 1);
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
        assert_eq!(
            trap.generic_trap_enum(),
            Some(GenericTrap::EnterpriseSpecific)
        );

        let mut buf = EncodeBuf::new();
        trap.encode(&mut buf);
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
                "Failed for {:?}",
                generic_trap
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

        let inform = Pdu {
            pdu_type: PduType::InformRequest,
            request_id: 99999,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345)),
                VarBind::new(
                    oid!(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0),
                    Value::ObjectIdentifier(oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1)),
                ),
            ],
        };

        let response = inform.to_response();

        assert_eq!(response.pdu_type, PduType::Response);
        assert_eq!(response.request_id, 99999);
        assert_eq!(response.error_status, 0);
        assert_eq!(response.error_index, 0);
        assert_eq!(response.varbinds.len(), 2);
    }

    #[test]
    fn test_pdu_is_confirmed() {
        let get = Pdu::get_request(1, &[oid!(1, 3, 6, 1)]);
        assert!(get.is_confirmed());

        let inform = Pdu {
            pdu_type: PduType::InformRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
        };
        assert!(inform.is_confirmed());

        let trap = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
        };
        assert!(!trap.is_confirmed());
        assert!(trap.is_notification());
    }

    #[test]
    fn test_decode_rejects_negative_error_index() {
        // Response PDU with negative error_index (-1)
        let raw = RawPdu::response(1, 0, -1, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);

        assert!(result.is_err(), "should reject negative error_index");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Decode {
                    kind: crate::error::DecodeErrorKind::NegativeErrorIndex { value: -1 },
                    ..
                }
            ),
            "expected NegativeErrorIndex, got {:?}",
            err
        );
    }

    #[test]
    fn test_decode_rejects_error_index_beyond_varbinds() {
        // Response PDU with error_index=5 but only 1 varbind
        let raw = RawPdu::response(1, 5, 5, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);

        assert!(result.is_err(), "should reject error_index beyond varbinds");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Decode {
                    kind: crate::error::DecodeErrorKind::ErrorIndexOutOfBounds {
                        index: 5,
                        varbind_count: 1
                    },
                    ..
                }
            ),
            "expected ErrorIndexOutOfBounds, got {:?}",
            err
        );
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
    fn test_decode_rejects_negative_non_repeaters() {
        let raw = RawGetBulkPdu::new(1, -1, 10, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = GetBulkPdu::decode(&mut decoder);

        assert!(result.is_err(), "should reject negative non_repeaters");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Decode {
                    kind: crate::error::DecodeErrorKind::NegativeNonRepeaters { value: -1 },
                    ..
                }
            ),
            "expected NegativeNonRepeaters, got {:?}",
            err
        );
    }

    #[test]
    fn test_decode_rejects_negative_max_repetitions() {
        let raw = RawGetBulkPdu::new(1, 0, -5, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = GetBulkPdu::decode(&mut decoder);

        assert!(result.is_err(), "should reject negative max_repetitions");
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::Error::Decode {
                    kind: crate::error::DecodeErrorKind::NegativeMaxRepetitions { value: -5 },
                    ..
                }
            ),
            "expected NegativeMaxRepetitions, got {:?}",
            err
        );
    }

    #[test]
    fn test_decode_accepts_valid_getbulk_params() {
        let raw = RawGetBulkPdu::new(1, 0, 10, vec![VarBind::null(oid!(1, 3, 6, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = GetBulkPdu::decode(&mut decoder);
        assert!(result.is_ok(), "valid GETBULK params should be accepted");

        let pdu = result.unwrap();
        assert_eq!(pdu.non_repeaters, 0);
        assert_eq!(pdu.max_repetitions, 10);
    }

    #[test]
    fn test_pdu_decode_getbulk_with_large_max_repetitions() {
        // GETBULK PDU with max_repetitions (25) > varbinds.len() (1)
        // This is the normal case for GETBULK requests.
        // The generic Pdu::decode must not reject this as an invalid error_index.
        let raw = RawGetBulkPdu::new(12345, 0, 25, vec![VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1))]);
        let encoded = raw.encode();

        let mut decoder = Decoder::new(encoded);
        let result = Pdu::decode(&mut decoder);
        assert!(
            result.is_ok(),
            "Pdu::decode should accept GETBULK with max_repetitions > varbinds.len(), got {:?}",
            result.err()
        );

        let pdu = result.unwrap();
        assert_eq!(pdu.pdu_type, PduType::GetBulkRequest);
        assert_eq!(pdu.request_id, 12345);
        // For GETBULK: error_status = non_repeaters, error_index = max_repetitions
        assert_eq!(pdu.error_status, 0);
        assert_eq!(pdu.error_index, 25);
        assert_eq!(pdu.varbinds.len(), 1);
    }
}
