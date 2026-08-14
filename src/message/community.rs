//! Community-based SNMP message format (v1/v2c).
//!
//! V1 and V2c messages share the same structure:
//! `SEQUENCE { version INTEGER, community OCTET STRING, pdu PDU }`
//!
//! The only difference is the version number (0 for v1, 1 for v2c).
//! `SNMPv1` Trap PDUs (tag 0xA4) have a distinct wire format from standard PDUs
//! and are represented by the `CommunityPdu::TrapV1` variant.

use crate::Community;
use crate::ber::{Decoder, EncodeBuf, tag};
use crate::compatibility::DecodeConfig;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::message::{DecodeOutcome, finalize_envelope};
use crate::pdu::{Pdu, PduType, TrapV1Pdu};
use crate::version::Version;
use bytes::Bytes;
use std::net::SocketAddr;

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
            Self::Standard(p) => p.pdu_type(),
            Self::TrapV1(_) => PduType::TrapV1,
        }
    }

    /// Encode to BER for a community message version.
    pub(crate) fn encode(&self, buf: &mut EncodeBuf, version: Version) -> Result<()> {
        match self {
            Self::Standard(pdu) => pdu.encode_for(buf, version, pdu.outbound_direction()),
            Self::TrapV1(trap) => trap.encode(buf),
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

fn invalid_message(reason: impl Into<Box<str>>) -> Box<Error> {
    Error::InvalidMessage(reason.into()).boxed()
}

fn validate_community_message(version: Version, pdu: &CommunityPdu) -> Result<()> {
    if version == Version::V3 {
        return Err(invalid_message(
            "community messages only support SNMPv1 and SNMPv2c",
        ));
    }

    match pdu {
        CommunityPdu::Standard(pdu) => {
            pdu.validate_outbound(version, pdu.outbound_direction())?;
        }
        CommunityPdu::TrapV1(trap) => {
            if version != Version::V1 {
                return Err(invalid_message("TrapV1 PDU is only valid in SNMPv1"));
            }
            trap.validate_outbound()?;
        }
    }

    Ok(())
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
    version: Version,
    /// Community string for authentication
    community: Community,
    /// Protocol data unit
    pdu: CommunityPdu,
}

impl CommunityMessage {
    /// Create a new community message with a standard PDU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the version cannot carry the PDU
    /// or an SNMPv1 PDU contains a `Counter64` value.
    pub fn new(
        version: Version,
        community: impl Into<Community>,
        pdu: impl Into<Pdu>,
    ) -> Result<Self> {
        let message = Self {
            version,
            community: community.into(),
            pdu: CommunityPdu::Standard(pdu.into()),
        };
        message.validate()?;
        Ok(message)
    }

    /// Create a V2c message (convenience constructor).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the PDU is not valid in SNMPv2c.
    pub fn v2c(community: impl Into<Community>, pdu: impl Into<Pdu>) -> Result<Self> {
        Self::new(Version::V2c, community, pdu)
    }

    /// Create a V1 message with a standard PDU (convenience constructor).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the PDU is not valid in SNMPv1.
    pub fn v1(community: impl Into<Community>, pdu: impl Into<Pdu>) -> Result<Self> {
        Self::new(Version::V1, community, pdu)
    }

    /// Create a V1 message carrying a `TrapV1` PDU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the trap contains `Counter64`.
    pub fn v1_trap(community: impl Into<Community>, trap: impl Into<TrapV1Pdu>) -> Result<Self> {
        let message = Self {
            version: Version::V1,
            community: community.into(),
            pdu: CommunityPdu::TrapV1(trap.into()),
        };
        message.validate()?;
        Ok(message)
    }

    fn validate(&self) -> Result<()> {
        validate_community_message(self.version, &self.pdu)
    }

    /// Return the SNMP version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Return the community string.
    #[must_use]
    pub fn community(&self) -> &Community {
        &self.community
    }

    /// Return the community PDU.
    #[must_use]
    pub fn pdu(&self) -> &CommunityPdu {
        &self.pdu
    }

    /// Consume the message into its version, community string, and PDU.
    #[must_use]
    pub fn into_parts(self) -> (Version, Community, CommunityPdu) {
        (self.version, self.community, self.pdu)
    }

    /// Encode to BER after validating the complete outbound envelope.
    pub fn encode(&self) -> Result<Bytes> {
        self.validate()?;
        let mut buf = EncodeBuf::new();

        buf.push_sequence(|buf| {
            self.pdu.encode(buf, self.version)?;
            buf.push_octet_string(self.community.as_bytes())?;
            buf.push_integer(self.version.as_i32());
            Ok(())
        })?;

        Ok(buf.finish())
    }

    /// Decode a community message and retain every accepted anomaly.
    pub fn decode(data: Bytes, config: DecodeConfig) -> Result<DecodeOutcome<Self>> {
        Self::decode_with_target(data, None, config)
    }

    pub(crate) fn decode_with_target(
        data: Bytes,
        peer: Option<SocketAddr>,
        config: DecodeConfig,
    ) -> Result<DecodeOutcome<Self>> {
        let anomalies = std::cell::RefCell::new(Vec::new());
        let mut decoder = Decoder::with_optional_peer(data, peer)
            .with_decode_config(config)
            .with_anomaly_sink(&anomalies);
        let mut seq = decoder.read_sequence()?;

        let version_num = seq.read_bounded_integer(0, i32::MAX)?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(version_num) }, "decode error");
            seq.malformed(DecodeErrorKind::UnknownVersion(version_num))
        })?;

        let value = Self::decode_from_sequence(&mut seq, version)?;
        finalize_envelope(&seq, &decoder, config)?;
        drop(seq);
        drop(decoder);
        Ok(DecodeOutcome {
            value,
            anomalies: anomalies.into_inner(),
        })
    }

    /// Decode from a sequence decoder where version has already been read.
    pub(crate) fn decode_from_sequence(seq: &mut Decoder, version: Version) -> Result<Self> {
        if version == Version::V3 {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(3) }, "decode error");
            return Err(seq.malformed(DecodeErrorKind::UnknownVersion(3)));
        }

        let community = Community::from(seq.read_octet_string()?);

        // Peek at the PDU tag to dispatch between standard and TrapV1 layouts.
        let pdu_tag = seq.peek_byte().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::TruncatedData }, "truncated community message");
            seq.malformed(DecodeErrorKind::TruncatedData)
        })?;

        let pdu = if pdu_tag == tag::pdu::TRAP_V1 {
            // The SNMPv1 Trap PDU (tag 0xA4) is only defined for SNMPv1
            // (RFC 1157 Section 4.1.6); SNMPv2c uses the SNMPv2-Trap PDU
            // (tag 0xA7) instead. Reject a v1 Trap carried in a v2c message.
            if version != Version::V1 {
                tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), version = ?version }, "v1 Trap PDU (0xA4) not valid in this version");
                return Err(seq.malformed(DecodeErrorKind::UnknownPduType(pdu_tag)));
            }
            CommunityPdu::TrapV1(TrapV1Pdu::decode(seq)?)
        } else {
            let pdu = Pdu::decode(seq)?;
            // Enforce version<->PDU-type compatibility. GETBULK, InformRequest,
            // and SNMPv2-Trap are SNMPv2 constructs (RFC 3416) and are not valid
            // in an SNMPv1 message (RFC 1157).
            if !crate::pdu::pdu_type_valid_for_version(pdu.pdu_type(), version) {
                tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), version = ?version, pdu_type = %pdu.pdu_type() }, "PDU type not valid for SNMP version");
                return Err(seq.malformed(DecodeErrorKind::UnknownPduType(pdu.pdu_type().tag())));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
    use crate::oid;
    use crate::pdu::GenericTrap;
    use crate::value::Value;
    use crate::varbind::VarBind;

    fn standard_pdu(pdu_type: PduType, varbinds: Vec<VarBind>) -> Pdu {
        if pdu_type == PduType::GetBulkRequest {
            Pdu::get_bulk(1, 0, 0, varbinds).unwrap()
        } else {
            Pdu::standard(
                crate::pdu::StandardPduType::try_from(pdu_type).unwrap(),
                1,
                0,
                0,
                varbinds,
            )
        }
    }

    fn trap_v1(varbinds: Vec<VarBind>) -> TrapV1Pdu {
        TrapV1Pdu::new(
            oid!(1, 3, 6, 1, 4, 1, 9999),
            [192, 168, 1, 1],
            GenericTrap::LinkDown,
            0,
            12345,
            varbinds,
        )
    }

    fn raw_standard_message(version: Version, pdu: &Pdu) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            let (pdu_type, first, second) = match pdu.body {
                crate::pdu::PduBody::Standard {
                    pdu_type,
                    error_status,
                    error_index,
                } => (pdu_type.pdu_type(), error_status, error_index),
                crate::pdu::PduBody::GetBulk {
                    non_repeaters,
                    max_repetitions,
                } => (
                    PduType::GetBulkRequest,
                    i32::try_from(non_repeaters).unwrap(),
                    i32::try_from(max_repetitions).unwrap(),
                ),
            };
            buf.push_constructed(pdu_type.tag(), |buf| {
                crate::varbind::encode_varbind_list(buf, &pdu.varbinds)?;
                buf.push_integer(second);
                buf.push_integer(first);
                buf.push_integer(pdu.request_id);
                Ok(())
            })?;
            buf.push_octet_string(b"public")?;
            buf.push_integer(version.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    fn raw_response_message(
        version: Version,
        error_status: i32,
        error_index: i32,
        varbinds: &[VarBind],
    ) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_constructed(tag::pdu::RESPONSE, |buf| {
                crate::varbind::encode_varbind_list(buf, varbinds).unwrap();
                buf.push_integer(error_index);
                buf.push_integer(error_status);
                buf.push_integer(1);
                Ok(())
            })?;
            buf.push_octet_string(b"public")?;
            buf.push_integer(version.as_i32());
            Ok(())
        })
        .unwrap();
        buf.finish()
    }

    fn assert_invalid_message<T: std::fmt::Debug>(result: Result<T>) {
        assert!(matches!(&*result.unwrap_err(), Error::InvalidMessage(_)));
    }

    #[test]
    fn construction_rejects_invalid_oid() {
        let error =
            CommunityMessage::v2c("public", Pdu::get_request(1, &[crate::oid::Oid::empty()]))
                .unwrap_err();
        assert!(matches!(&*error, Error::InvalidOid(_)));
    }

    #[test]
    fn valid_messages_roundtrip() {
        let trap = trap_v1(vec![]);
        let message = CommunityMessage::v1_trap("public", trap).unwrap();
        let decoded = CommunityMessage::decode(message.encode().unwrap(), DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(decoded.version(), Version::V1);
        assert!(decoded.community().matches(b"public"));
        assert_eq!(
            decoded.pdu().trap_v1().unwrap().enterprise,
            oid!(1, 3, 6, 1, 4, 1, 9999)
        );

        for version in [Version::V1, Version::V2c] {
            let message = CommunityMessage::new(
                version,
                "private",
                Pdu::get_request(123, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]),
            )
            .unwrap();
            let decoded =
                CommunityMessage::decode(message.encode().unwrap(), DecodeConfig::default())
                    .unwrap()
                    .value;
            assert_eq!(decoded.version(), version);
            assert!(decoded.community().matches(b"private"));
            assert_eq!(decoded.pdu().standard().unwrap().request_id, 123);
        }
    }

    #[test]
    fn full_envelope_distinguishes_multi_octet_pdu_tag_from_missing_pdu() {
        let mut encoded = raw_standard_message(Version::V2c, &Pdu::get_request(7, &[])).to_vec();
        let pdu_offset = encoded
            .iter()
            .position(|byte| *byte == tag::pdu::GET_REQUEST)
            .unwrap();
        encoded[pdu_offset] = 0xbf;

        let error =
            CommunityMessage::decode(Bytes::from(encoded), DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*error, Error::Decode(error)
            if error.offset == pdu_offset
                && error.kind == DecodeErrorKind::UnsupportedMultiOctetTag { first_octet: 0xbf }));

        let mut missing = EncodeBuf::new();
        missing
            .push_sequence(|buf| {
                buf.push_octet_string(b"public")?;
                buf.push_integer(Version::V2c.as_i32());
                Ok(())
            })
            .unwrap();
        let missing = missing.finish();
        let missing_offset = missing.len();
        let error = CommunityMessage::decode(missing, DecodeConfig::default()).unwrap_err();
        assert!(matches!(&*error, Error::Decode(error)
            if error.offset == missing_offset
                && error.kind == DecodeErrorKind::TruncatedData));
    }

    #[test]
    fn constructors_reject_invalid_version_pdu_pairs() {
        for pdu_type in [
            PduType::GetBulkRequest,
            PduType::InformRequest,
            PduType::TrapV2,
            PduType::Report,
        ] {
            assert_invalid_message(CommunityMessage::v1(
                "public",
                standard_pdu(pdu_type, vec![]),
            ));
        }

        assert_invalid_message(CommunityMessage::v2c(
            "public",
            standard_pdu(PduType::Report, vec![]),
        ));
        assert_invalid_message(CommunityMessage::new(
            Version::V3,
            "public",
            standard_pdu(PduType::GetRequest, vec![]),
        ));
    }

    #[test]
    fn structured_community_envelopes_enforce_version_specific_too_big_shape() {
        let varbinds = vec![VarBind::null(oid!(1, 3, 6, 1))];
        let too_big = Pdu::response(1, crate::ErrorStatus::TooBig.as_i32(), 0, varbinds.clone());

        let v1 = CommunityMessage::v1("public", too_big.clone())
            .expect("SNMPv1 tooBig retains the request variable bindings");
        let v1 = CommunityMessage::decode(v1.encode().unwrap(), DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(v1.pdu().standard().unwrap().varbinds, varbinds);

        assert_invalid_message(CommunityMessage::v2c("public", too_big));
        CommunityMessage::v2c(
            "public",
            Pdu::response(1, crate::ErrorStatus::TooBig.as_i32(), 0, vec![]),
        )
        .unwrap()
        .encode()
        .unwrap();
    }

    #[test]
    fn community_decode_remains_permissive_for_noncanonical_too_big_response() {
        let encoded = raw_response_message(
            Version::V2c,
            crate::ErrorStatus::TooBig.as_i32(),
            0,
            &[VarBind::null(oid!(1, 3, 6, 1))],
        );

        let decoded = CommunityMessage::decode(encoded, DecodeConfig::default())
            .expect("receive path accepts the PDU")
            .value;
        let pdu = decoded.pdu().standard().unwrap();
        assert_eq!(pdu.error_status(), crate::ErrorStatus::TooBig.as_i32());
        assert_eq!(pdu.varbinds.len(), 1);
        assert_invalid_message(decoded.encode());
    }

    #[test]
    fn constructors_reject_counter64_in_every_v1_varbind_container() {
        for pdu_type in [
            PduType::GetRequest,
            PduType::GetNextRequest,
            PduType::Response,
            PduType::SetRequest,
        ] {
            assert_invalid_message(CommunityMessage::v1(
                "public",
                standard_pdu(
                    pdu_type,
                    vec![VarBind::new(oid!(1, 3, 6, 1), Value::Counter64(1))],
                ),
            ));
        }

        assert_invalid_message(CommunityMessage::v1_trap(
            "public",
            trap_v1(vec![VarBind::new(oid!(1, 3, 6, 1), Value::Counter64(1))]),
        ));
    }

    #[test]
    fn encoders_revalidate_internal_state() {
        let mut invalid_messages: Vec<_> = [
            PduType::GetBulkRequest,
            PduType::InformRequest,
            PduType::TrapV2,
            PduType::Report,
        ]
        .into_iter()
        .map(|pdu_type| CommunityMessage {
            version: Version::V1,
            community: Community::from(Bytes::from_static(b"public")),
            pdu: CommunityPdu::Standard(standard_pdu(pdu_type, vec![])),
        })
        .collect();
        invalid_messages.extend(
            [
                PduType::GetRequest,
                PduType::GetNextRequest,
                PduType::Response,
                PduType::SetRequest,
            ]
            .into_iter()
            .map(|pdu_type| CommunityMessage {
                version: Version::V1,
                community: Community::from(Bytes::from_static(b"public")),
                pdu: CommunityPdu::Standard(standard_pdu(
                    pdu_type,
                    vec![VarBind::new(oid!(1, 3, 6, 1), Value::Counter64(1))],
                )),
            }),
        );
        invalid_messages.extend([
            CommunityMessage {
                version: Version::V3,
                community: Community::from(Bytes::from_static(b"public")),
                pdu: CommunityPdu::Standard(standard_pdu(PduType::GetRequest, vec![])),
            },
            CommunityMessage {
                version: Version::V1,
                community: Community::from(Bytes::from_static(b"public")),
                pdu: CommunityPdu::TrapV1(trap_v1(vec![VarBind::new(
                    oid!(1, 3, 6, 1),
                    Value::Counter64(1),
                )])),
            },
        ]);

        for message in invalid_messages {
            assert_invalid_message(message.encode());
        }
    }

    #[test]
    fn get_bulk_uses_ordinary_message_path_and_requires_v2c() {
        let bulk = Pdu::get_bulk(7, 0, 10, vec![]).unwrap();
        assert_invalid_message(CommunityMessage::v1("public", bulk.clone()));
        assert_invalid_message(CommunityMessage::new(Version::V3, "public", bulk.clone()));

        let encoded = CommunityMessage::v2c("public", bulk)
            .unwrap()
            .encode()
            .unwrap();
        let decoded = CommunityMessage::decode(encoded, DecodeConfig::default())
            .unwrap()
            .value;
        assert_eq!(decoded.version(), Version::V2c);
        assert_eq!(
            decoded.pdu().standard().unwrap().pdu_type(),
            PduType::GetBulkRequest
        );
    }

    #[test]
    fn pdu_and_message_envelopes_reject_the_same_malformed_objects_without_mutation() {
        let name = oid!(1, 3, 6, 1);
        let malformed = [
            Pdu {
                request_id: 7,
                body: crate::pdu::PduBody::GetBulk {
                    non_repeaters: crate::pdu::MAX_GET_BULK_VALUE + 1,
                    max_repetitions: 0,
                },
                varbinds: vec![VarBind::null(name.clone())],
            },
            Pdu::standard(
                crate::pdu::StandardPduType::GetRequest,
                7,
                1,
                0,
                vec![VarBind::null(name.clone())],
            ),
            Pdu::response(7, 0, 1, vec![VarBind::null(name.clone())]),
            Pdu::standard(
                crate::pdu::StandardPduType::GetRequest,
                7,
                0,
                0,
                vec![VarBind::new(name.clone(), Value::NoSuchObject)],
            ),
            Pdu::set_request(
                7,
                vec![VarBind::new(
                    name,
                    Value::Unknown {
                        tag: 0x48,
                        data: Bytes::from_static(b"raw"),
                    },
                )],
            ),
        ];

        for pdu in malformed {
            let original = pdu.clone();

            let mut pdu_buf = EncodeBuf::new();
            assert_invalid_message(pdu.encode(&mut pdu_buf));
            assert!(pdu_buf.is_empty());

            assert_invalid_message(CommunityMessage::v2c("public", pdu.clone()));

            let scoped = ScopedPdu::with_empty_context(pdu.clone());
            let mut scoped_buf = EncodeBuf::new();
            assert_invalid_message(scoped.encode(&mut scoped_buf));
            assert!(scoped_buf.is_empty());

            let global = MsgGlobalData::new(
                11,
                crate::MessageSize::new(65_507).unwrap(),
                MsgFlags::new(SecurityLevel::NoAuthNoPriv, false),
            )
            .unwrap();
            let security_params = crate::v3::UsmSecurityParams::discovery().encode().unwrap();
            assert_invalid_message(V3Message::new(global, security_params, scoped));
            assert_eq!(pdu, original);
        }
    }

    #[test]
    fn decoder_rejects_invalid_version_pdu_pairs_from_raw_ber() {
        for pdu_type in [
            PduType::GetBulkRequest,
            PduType::InformRequest,
            PduType::TrapV2,
            PduType::Report,
        ] {
            let encoded = raw_standard_message(Version::V1, &standard_pdu(pdu_type, vec![]));
            assert!(CommunityMessage::decode(encoded, DecodeConfig::default()).is_err());
        }

        let trap = trap_v1(vec![]);
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            trap.encode(buf).unwrap();
            buf.push_octet_string(b"public")?;
            buf.push_integer(Version::V2c.as_i32());
            Ok(())
        })
        .unwrap();
        assert!(CommunityMessage::decode(buf.finish(), DecodeConfig::default()).is_err());
    }
}
