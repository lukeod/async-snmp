//! Community-based SNMP message format (v1/v2c).
//!
//! V1 and V2c messages share the same structure:
//! `SEQUENCE { version INTEGER, community OCTET STRING, pdu PDU }`
//!
//! The only difference is the version number (0 for v1, 1 for v2c).
//! `SNMPv1` Trap PDUs (tag 0xA4) have a distinct wire format from standard PDUs
//! and are represented by the `CommunityPdu::TrapV1` variant.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::pdu::{GetBulkPdu, Pdu, PduType, TrapV1Pdu};
use crate::version::Version;
use bytes::Bytes;

/// PDU carried inside a community (v1/v2c) message.
///
/// `SNMPv1` Trap PDUs have a different wire layout from all other PDU types,
/// so they are decoded into a distinct variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunityPdu {
    /// Standard PDU (Get, `GetNext`, Response, Set, `GetBulk`, Inform, `TrapV2`, Report).
    Standard(Pdu),
    /// `SNMPv1` Trap PDU (distinct wire format, only valid in V1 messages).
    TrapV1(TrapV1Pdu),
}

impl CommunityPdu {
    /// Return a reference to the standard PDU, or `None` if this is a `TrapV1`.
    #[must_use]
    pub fn standard(&self) -> Option<&Pdu> {
        match self {
            Self::Standard(p) => Some(p),
            Self::TrapV1(_) => None,
        }
    }

    /// Return a reference to the `TrapV1` PDU, or `None` if this is a standard PDU.
    #[must_use]
    pub fn trap_v1(&self) -> Option<&TrapV1Pdu> {
        match self {
            Self::TrapV1(t) => Some(t),
            Self::Standard(_) => None,
        }
    }

    /// Return the PDU type.
    #[must_use]
    pub fn pdu_type(&self) -> PduType {
        match self {
            Self::Standard(p) => p.pdu_type,
            Self::TrapV1(_) => PduType::TrapV1,
        }
    }

    /// Encode to BER.
    pub(crate) fn encode(&self, buf: &mut EncodeBuf) {
        match self {
            Self::Standard(p) => p.encode(buf),
            Self::TrapV1(t) => t.encode(buf),
        }
    }
}

impl From<Pdu> for CommunityPdu {
    fn from(p: Pdu) -> Self {
        Self::Standard(p)
    }
}

impl From<TrapV1Pdu> for CommunityPdu {
    fn from(t: TrapV1Pdu) -> Self {
        Self::TrapV1(t)
    }
}

/// Check whether a standard PDU type is valid in a community message of the
/// given version.
///
/// SNMPv1 (RFC 1157) defines GetRequest, GetNextRequest, Response, SetRequest,
/// and the v1 Trap. GETBULK, InformRequest, SNMPv2-Trap, and Report are SNMPv2
/// constructs (RFC 3416) and are not valid in an SNMPv1 message. The v1 Trap PDU
/// is handled separately via its distinct wire tag and is never a `Standard` PDU
/// here, so it is not represented in this check.
fn pdu_type_valid_for_version(pdu_type: PduType, version: Version) -> bool {
    match version {
        Version::V1 => matches!(
            pdu_type,
            PduType::GetRequest | PduType::GetNextRequest | PduType::Response | PduType::SetRequest
        ),
        // V2c permits the full SNMPv2 PDU set. TrapV1 is dispatched by tag before
        // reaching this check, so it can never appear as a Standard PDU.
        Version::V2c => pdu_type != PduType::TrapV1,
        // V3 messages are not decoded through this path.
        Version::V3 => false,
    }
}

/// Community-based SNMP message (v1/v2c).
///
/// This unified type handles both `SNMPv1` and `SNMPv2c` messages,
/// which share identical structure but differ in version number.
/// The `pdu` field is a `CommunityPdu` that can hold either a standard
/// PDU or a `TrapV1` PDU.
#[derive(Debug, Clone)]
pub struct CommunityMessage {
    /// SNMP version (V1 or V2c)
    pub version: Version,
    /// Community string for authentication
    pub community: Bytes,
    /// Protocol data unit
    pub pdu: CommunityPdu,
}

impl CommunityMessage {
    /// Create a new community message with a standard PDU.
    ///
    /// # Panics
    /// Panics if version is V3 (use `V3Message` instead).
    pub fn new(version: Version, community: impl Into<Bytes>, pdu: Pdu) -> Self {
        assert!(
            matches!(version, Version::V1 | Version::V2c),
            "CommunityMessage only supports V1/V2c, not {version:?}"
        );
        Self {
            version,
            community: community.into(),
            pdu: CommunityPdu::Standard(pdu),
        }
    }

    /// Create a V2c message (convenience constructor).
    pub fn v2c(community: impl Into<Bytes>, pdu: Pdu) -> Self {
        Self::new(Version::V2c, community, pdu)
    }

    /// Create a V1 message with a standard PDU (convenience constructor).
    pub fn v1(community: impl Into<Bytes>, pdu: Pdu) -> Self {
        Self::new(Version::V1, community, pdu)
    }

    /// Create a V1 message carrying a `TrapV1` PDU.
    pub fn v1_trap(community: impl Into<Bytes>, trap: TrapV1Pdu) -> Self {
        Self {
            version: Version::V1,
            community: community.into(),
            pdu: CommunityPdu::TrapV1(trap),
        }
    }

    /// Encode to BER.
    pub fn encode(&self) -> Bytes {
        let mut buf = EncodeBuf::new();

        buf.push_sequence(|buf| {
            self.pdu.encode(buf);
            buf.push_octet_string(&self.community);
            buf.push_integer(self.version.as_i32());
        });

        buf.finish()
    }

    /// Decode from BER.
    ///
    /// Returns the message with the version parsed from the data.
    pub fn decode(data: Bytes) -> Result<Self> {
        let mut decoder = Decoder::new(data);
        Self::decode_from(&mut decoder)
    }

    /// Decode from an existing decoder (used by Message dispatcher).
    pub(crate) fn decode_from(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;

        let version_num = seq.read_integer()?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(version_num) }, "decode error");
            Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed()
        })?;

        Self::decode_from_sequence(&mut seq, version)
    }

    /// Decode from a sequence decoder where version has already been read.
    pub(crate) fn decode_from_sequence(seq: &mut Decoder, version: Version) -> Result<Self> {
        if version == Version::V3 {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(3) }, "decode error");
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }

        let community = seq.read_octet_string()?;

        // Peek at the PDU tag to dispatch between standard and TrapV1 layouts.
        let pdu_tag = seq.peek_tag().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::TruncatedData }, "truncated community message");
            Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed()
        })?;

        let pdu = if pdu_tag == tag::pdu::TRAP_V1 {
            // The SNMPv1 Trap PDU (tag 0xA4) is only defined for SNMPv1
            // (RFC 1157 Section 4.1.6); SNMPv2c uses the SNMPv2-Trap PDU
            // (tag 0xA7) instead. Reject a v1 Trap carried in a v2c message.
            if version != Version::V1 {
                tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), version = ?version }, "v1 Trap PDU (0xA4) not valid in this version");
                return Err(Error::MalformedResponse {
                    target: UNKNOWN_TARGET,
                }
                .boxed());
            }
            CommunityPdu::TrapV1(TrapV1Pdu::decode(seq)?)
        } else {
            let pdu = Pdu::decode(seq)?;
            // Enforce version<->PDU-type compatibility. GETBULK, InformRequest,
            // and SNMPv2-Trap are SNMPv2 constructs (RFC 3416) and are not valid
            // in an SNMPv1 message (RFC 1157).
            if !pdu_type_valid_for_version(pdu.pdu_type, version) {
                tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), version = ?version, pdu_type = %pdu.pdu_type }, "PDU type not valid for SNMP version");
                return Err(Error::MalformedResponse {
                    target: UNKNOWN_TARGET,
                }
                .boxed());
            }
            CommunityPdu::Standard(pdu)
        };

        Ok(CommunityMessage {
            version,
            community,
            pdu,
        })
    }

    /// Consume and return the standard PDU.
    ///
    /// Returns `None` if the PDU is a `TrapV1`.
    pub fn into_pdu(self) -> Option<Pdu> {
        match self.pdu {
            CommunityPdu::Standard(p) => Some(p),
            CommunityPdu::TrapV1(_) => None,
        }
    }

    /// Consume and return the `CommunityPdu`.
    pub fn into_community_pdu(self) -> CommunityPdu {
        self.pdu
    }

    /// Encode a GETBULK request message (v2c/v3 only).
    ///
    /// GETBULK is not supported in `SNMPv1`.
    pub fn encode_bulk(version: Version, community: impl Into<Bytes>, pdu: &GetBulkPdu) -> Bytes {
        debug_assert!(version != Version::V1, "GETBULK not supported in SNMPv1");

        let community = community.into();
        let mut buf = EncodeBuf::new();

        buf.push_sequence(|buf| {
            pdu.encode(buf);
            buf.push_octet_string(&community);
            buf.push_integer(version.as_i32());
        });

        buf.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;
    use crate::pdu::{GenericTrap, TrapV1Pdu};

    #[test]
    fn test_v1_trap_roundtrip() {
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            vec![],
        );
        let msg = CommunityMessage::v1_trap(b"public".as_slice(), trap);

        let encoded = msg.encode();
        let decoded = CommunityMessage::decode(encoded).unwrap();

        assert_eq!(decoded.version, Version::V1);
        assert_eq!(decoded.community.as_ref(), b"public");
        match decoded.pdu {
            CommunityPdu::TrapV1(ref t) => {
                assert_eq!(t.enterprise, oid!(1, 3, 6, 1, 4, 1, 9999));
                assert_eq!(t.agent_addr, [192, 168, 1, 1]);
                assert_eq!(t.generic_trap, GenericTrap::LinkDown);
                assert_eq!(t.time_stamp, 12345);
            }
            CommunityPdu::Standard(_) => panic!("expected TrapV1 pdu"),
        }
    }

    #[test]
    fn test_v1_roundtrip() {
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let msg = CommunityMessage::v1(b"public".as_slice(), pdu);

        let encoded = msg.encode();
        let decoded = CommunityMessage::decode(encoded).unwrap();

        assert_eq!(decoded.version, Version::V1);
        assert_eq!(decoded.community.as_ref(), b"public");
        assert_eq!(decoded.pdu.standard().unwrap().request_id, 42);
    }

    #[test]
    fn test_v2c_roundtrip() {
        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let msg = CommunityMessage::v2c(b"private".as_slice(), pdu);

        let encoded = msg.encode();
        let decoded = CommunityMessage::decode(encoded).unwrap();

        assert_eq!(decoded.version, Version::V2c);
        assert_eq!(decoded.community.as_ref(), b"private");
        assert_eq!(decoded.pdu.standard().unwrap().request_id, 123);
    }

    #[test]
    fn test_v1_getbulk_rejected() {
        // GETBULK is an SNMPv2 construct (RFC 3416) and must be rejected in an
        // SNMPv1 message even though the encoder will emit it.
        let pdu = Pdu::get_bulk(1, 0, 10, vec![]);
        let msg = CommunityMessage::new(Version::V1, b"public".as_slice(), pdu);
        let encoded = msg.encode();

        let result = CommunityMessage::decode(encoded);
        assert!(
            result.is_err(),
            "v1 GETBULK must be rejected, got {result:?}"
        );
    }

    #[test]
    fn test_v1_inform_rejected() {
        // InformRequest is an SNMPv2 construct and must be rejected in a v1 message.
        let pdu = Pdu::inform_request(1, 0, &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), vec![]);
        let msg = CommunityMessage::new(Version::V1, b"public".as_slice(), pdu);
        let encoded = msg.encode();

        let result = CommunityMessage::decode(encoded);
        assert!(
            result.is_err(),
            "v1 Inform must be rejected, got {result:?}"
        );
    }

    #[test]
    fn test_v1_trapv2_rejected() {
        // SNMPv2-Trap must be rejected in a v1 message.
        let pdu = Pdu::trap_v2(1, 0, &oid!(1, 3, 6, 1, 6, 3, 1, 1, 5, 1), vec![]);
        let msg = CommunityMessage::new(Version::V1, b"public".as_slice(), pdu);
        let encoded = msg.encode();

        let result = CommunityMessage::decode(encoded);
        assert!(
            result.is_err(),
            "v1 SNMPv2-Trap must be rejected, got {result:?}"
        );
    }

    #[test]
    fn test_v2c_trapv1_rejected() {
        // The v1 Trap PDU (tag 0xA4) has a distinct wire layout and is only
        // defined for SNMPv1; a v2c message carrying it must be rejected.
        let trap = TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            vec![],
        );
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            trap.encode(buf);
            buf.push_octet_string(b"public");
            buf.push_integer(Version::V2c.as_i32());
        });
        let encoded = buf.finish();

        let result = CommunityMessage::decode(encoded);
        assert!(
            result.is_err(),
            "v2c v1-Trap (0xA4) must be rejected, got {result:?}"
        );
    }

    #[test]
    fn test_version_preserved() {
        for version in [Version::V1, Version::V2c] {
            let pdu = Pdu::get_request(1, &[oid!(1, 3, 6, 1)]);
            let msg = CommunityMessage::new(version, b"test".as_slice(), pdu);

            let encoded = msg.encode();
            let decoded = CommunityMessage::decode(encoded).unwrap();

            assert_eq!(decoded.version, version);
        }
    }
}
