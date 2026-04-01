//! SNMP Protocol Data Units (PDUs).
//!
//! PDUs represent the different SNMP operations.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, ErrorStatus, Result, UNKNOWN_TARGET};
use crate::oid::Oid;
use crate::varbind::{VarBind, decode_varbind_list, encode_varbind_list};

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Create a SNMPv2c/v3 Trap PDU.
    ///
    /// Prepends the mandatory varbind prefix per RFC 3416 Section 4.2.6:
    /// 1. sysUpTime.0 (1.3.6.1.2.1.1.3.0) with TimeTicks value
    /// 2. snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) with the trap OID
    ///
    /// Caller-provided varbinds are appended after the prefix.
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
        Self {
            pdu_type: PduType::TrapV2,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: all_varbinds,
        }
    }

    /// Create an InformRequest PDU.
    ///
    /// Same varbind structure as `trap_v2` (sysUpTime.0 + snmpTrapOID.0 prefix),
    /// but uses InformRequest PDU type which expects a Response from the receiver.
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
        Self {
            pdu_type: PduType::InformRequest,
            request_id,
            error_status: 0,
            error_index: 0,
            varbinds: all_varbinds,
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
        let pdu_type = PduType::from_tag(tag).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::pdu", { offset = decoder.offset(), tag = tag, kind = %DecodeErrorKind::UnknownPduType(tag) }, "decode error");
            Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed()
        })?;

        let len = decoder.read_length()?;
        let mut pdu_decoder = decoder.sub_decoder(len)?;

        let request_id = pdu_decoder.read_integer()?;
        let error_status = pdu_decoder.read_integer()?;
        let error_index = pdu_decoder.read_integer()?;
        let varbinds = decode_varbind_list(&mut pdu_decoder)?;

        // error_index is not validated here. net-snmp performs no bounds checking
        // on this field (validation code in snmp_client.c is wrapped in
        // #ifdef TEMPORARILY_DISABLED). RFC 3416 Section 3 annotates it "sometimes
        // ignored" and places no MUST/SHOULD obligation on receivers. Rejecting
        // out-of-range values would break compatibility with buggy agents that
        // work fine with net-snmp.

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
        self.pdu_type == PduType::Response && self.error_status != 0
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

    /// Convert a v2 notification PDU to a v1 TrapV1Pdu (RFC 3584 Section 3.2).
    ///
    /// Extracts the v1 fields from the standard v2 notification varbind layout:
    /// - sysUpTime.0 (first varbind) -> time_stamp
    /// - snmpTrapOID.0 (second varbind) -> generic_trap, specific_trap, enterprise
    /// - snmpTrapAddress.0 varbind (if present) -> agent_addr
    /// - snmpTrapEnterprise.0 varbind (if present) -> enterprise (for standard traps)
    ///
    /// Per RFC 3584 Section 3.2: if any varbind is Counter64, the trap cannot be
    /// represented in v1 and `None` is returned.
    ///
    /// The `default_addr` parameter provides the agent_addr when no
    /// snmpTrapAddress.0 varbind is present (typically the local IP address,
    /// or `[0,0,0,0]` if unknown).
    ///
    /// Returns `None` if:
    /// - The PDU has fewer than 2 varbinds
    /// - The first varbind is not TimeTicks
    /// - The second varbind is not an OID
    /// - Any varbind contains a Counter64 value
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

        let trap_oid = match &self.varbinds[1].value {
            Value::ObjectIdentifier(oid) => oid,
            _ => return None,
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
        {
            // Standard trap: snmpTraps.{generic+1}
            let last_arc = trap_oid.arcs()[trap_oid.len() - 1];
            if last_arc == 0 || last_arc > 6 {
                // Unknown standard trap number, treat as enterprise-specific
                (GenericTrap::EnterpriseSpecific, 0, trap_oid.clone())
            } else {
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
            }
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

        // Collect remaining varbinds, skipping the sysUpTime/snmpTrapOID prefix
        // and the conversion-specific varbinds
        let enterprise_oid = oids::snmp_trap_enterprise();
        let varbinds: Vec<VarBind> = self.varbinds[2..]
            .iter()
            .filter(|vb| vb.oid != trap_address_oid && vb.oid != enterprise_oid)
            .cloned()
            .collect();

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
    /// enterpriseSpecific(6) - vendor-specific trap, see specific_trap field
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

/// SNMPv1 Trap PDU (RFC 1157 Section 4.1.6).
///
/// This PDU type has a completely different structure from other PDUs.
/// It is only used in SNMPv1 and is replaced by SNMPv2-Trap in v2c/v3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrapV1Pdu {
    /// Enterprise OID (sysObjectID of the entity generating the trap)
    pub enterprise: Oid,
    /// Agent address (IP address of the agent generating the trap)
    pub agent_addr: [u8; 4],
    /// Generic trap type
    pub generic_trap: GenericTrap,
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
            generic_trap,
            specific_trap,
            time_stamp,
            varbinds,
        }
    }

    /// Check if this is an enterprise-specific trap.
    pub fn is_enterprise_specific(&self) -> bool {
        self.generic_trap == GenericTrap::EnterpriseSpecific
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
    /// The request_id is set to 0; callers should assign their own.
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

        Ok(Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 0,
            error_status: 0,
            error_index: 0,
            varbinds,
        })
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_constructed(tag::pdu::TRAP_V1, |buf| {
            encode_varbind_list(buf, &self.varbinds);
            buf.push_unsigned32(tag::application::TIMETICKS, self.time_stamp);
            buf.push_integer(self.specific_trap);
            buf.push_integer(self.generic_trap.as_i32());
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
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), expected = 0x40_u8, actual = agent_tag, kind = %DecodeErrorKind::UnexpectedTag {
                    expected: 0x40,
                    actual: agent_tag,
                } }, "decode error");
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }
        let agent_len = pdu.read_length()?;
        if agent_len != 4 {
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), length = agent_len, kind = %DecodeErrorKind::InvalidIpAddressLength { length: agent_len } }, "decode error");
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }
        let agent_bytes = pdu.read_bytes(4)?;
        let agent_addr = [
            agent_bytes[0],
            agent_bytes[1],
            agent_bytes[2],
            agent_bytes[3],
        ];

        // generic-trap INTEGER
        let generic_trap = GenericTrap::from_i32(pdu.read_integer()?);

        // specific-trap INTEGER
        let specific_trap = pdu.read_integer()?;

        // time-stamp TimeTicks
        let ts_tag = pdu.read_tag()?;
        if ts_tag != tag::application::TIMETICKS {
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), expected = 0x43_u8, actual = ts_tag, kind = %DecodeErrorKind::UnexpectedTag {
                    expected: 0x43,
                    actual: ts_tag,
                } }, "decode error");
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
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
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), non_repeaters = non_repeaters, kind = %DecodeErrorKind::NegativeNonRepeaters {
                    value: non_repeaters,
                } }, "decode error");
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }
        if max_repetitions < 0 {
            tracing::debug!(target: "async_snmp::pdu", { offset = pdu.offset(), max_repetitions = max_repetitions, kind = %DecodeErrorKind::NegativeMaxRepetitions {
                    value: max_repetitions,
                } }, "decode error");
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
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
        assert_eq!(decoded.generic_trap, GenericTrap::LinkDown);
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
        assert_eq!(trap.generic_trap, GenericTrap::EnterpriseSpecific);

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
        assert_eq!(result.unwrap().error_index, -1);
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
        assert_eq!(result.unwrap().error_index, 5);
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
            matches!(&*err, crate::error::Error::MalformedResponse { .. }),
            "expected MalformedResponse, got {:?}",
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
            matches!(&*err, crate::error::Error::MalformedResponse { .. }),
            "expected MalformedResponse, got {:?}",
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
        );

        assert!(!pdu.is_error());
    }

    #[test]
    fn test_response_with_error_status_is_treated_as_error() {
        let pdu = Pdu {
            pdu_type: PduType::Response,
            request_id: 12345,
            error_status: ErrorStatus::TooBig.as_i32(),
            error_index: 1,
            varbinds: vec![VarBind::null(oid!(1, 3, 6, 1, 2, 1, 1))],
        };

        assert!(pdu.is_error());
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

        assert_eq!(pdu.pdu_type, PduType::TrapV2);
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
        // snmpTrapAddress should be stripped from varbinds
        assert!(trap.varbinds.is_empty());
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
        // snmpTrapEnterprise should be stripped from varbinds
        assert!(trap.varbinds.is_empty());
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
        let pdu = Pdu {
            pdu_type: PduType::TrapV2,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![],
        };

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
            assert_eq!(
                v1.generic_trap, expected_generic,
                "Failed for {:?}",
                trap_oid
            );
            assert_eq!(v1.specific_trap, 0);
        }
    }
}
