//! Community-based SNMP message format (v1/v2c).
//!
//! V1 and V2c messages share the same structure:
//! `SEQUENCE { version INTEGER, community OCTET STRING, pdu PDU }`
//!
//! The only difference is the version number (0 for v1, 1 for v2c).
//! `SNMPv1` Trap PDUs (tag 0xA4) have a distinct wire format from standard PDUs
//! and are represented by the `CommunityPdu::TrapV1` variant.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::compatibility::CompatibilityPolicy;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result};
use crate::message::{DecodeOutcome, DecodePolicy, finalize_envelope};
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
    community: Bytes,
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
    pub fn new(version: Version, community: impl Into<Bytes>, pdu: Pdu) -> Result<Self> {
        let message = Self {
            version,
            community: community.into(),
            pdu: CommunityPdu::Standard(pdu),
        };
        message.validate()?;
        Ok(message)
    }

    /// Create a V2c message (convenience constructor).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the PDU is not valid in SNMPv2c.
    pub fn v2c(community: impl Into<Bytes>, pdu: Pdu) -> Result<Self> {
        Self::new(Version::V2c, community, pdu)
    }

    /// Create a V1 message with a standard PDU (convenience constructor).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the PDU is not valid in SNMPv1.
    pub fn v1(community: impl Into<Bytes>, pdu: Pdu) -> Result<Self> {
        Self::new(Version::V1, community, pdu)
    }

    /// Create a V1 message carrying a `TrapV1` PDU.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidMessage`] when the trap contains `Counter64`.
    pub fn v1_trap(community: impl Into<Bytes>, trap: TrapV1Pdu) -> Result<Self> {
        let message = Self {
            version: Version::V1,
            community: community.into(),
            pdu: CommunityPdu::TrapV1(trap),
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
    pub fn community(&self) -> &Bytes {
        &self.community
    }

    /// Return the community PDU.
    #[must_use]
    pub fn pdu(&self) -> &CommunityPdu {
        &self.pdu
    }

    /// Consume the message into its version, community string, and PDU.
    #[must_use]
    pub fn into_parts(self) -> (Version, Bytes, CommunityPdu) {
        (self.version, self.community, self.pdu)
    }

    /// Encode to BER after validating the complete outbound envelope.
    pub fn encode(&self) -> Result<Bytes> {
        self.validate()?;
        let mut buf = EncodeBuf::new();

        buf.try_push_sequence(|buf| {
            self.pdu.encode(buf, self.version)?;
            buf.push_octet_string(&self.community);
            buf.push_integer(self.version.as_i32());
            Ok(())
        })?;

        Ok(buf.finish())
    }

    /// Decode using the default compatible top-level policy.
    ///
    /// Suffix acceptance emits the stable `async_snmp::message`
    /// `trailing_bytes` anomaly event. Use [`Self::decode_with_policy`] to
    /// retain the anomaly metadata.
    pub fn decode(data: Bytes) -> Result<Self> {
        Ok(Self::decode_with_policy(data, DecodePolicy::Compatible)?.value)
    }

    /// Decode using an explicit top-level consumption policy.
    pub fn decode_with_policy(data: Bytes, policy: DecodePolicy) -> Result<DecodeOutcome<Self>> {
        Self::decode_with_policies(data, policy, CompatibilityPolicy::default())
    }

    /// Decode using an explicit malformed-input compatibility policy.
    pub fn decode_with_compatibility_policy(
        data: Bytes,
        compatibility: CompatibilityPolicy,
    ) -> Result<Self> {
        Ok(Self::decode_with_policies(data, DecodePolicy::Compatible, compatibility)?.value)
    }

    /// Decode using independent envelope-consumption and malformed-input policies.
    pub fn decode_with_policies(
        data: Bytes,
        policy: DecodePolicy,
        compatibility: CompatibilityPolicy,
    ) -> Result<DecodeOutcome<Self>> {
        Self::decode_with_target_and_policies(
            data,
            crate::error::UNKNOWN_TARGET,
            policy,
            compatibility,
        )
    }

    /// Decode while requiring the input to contain exactly one message TLV.
    pub fn decode_strict(data: Bytes) -> Result<Self> {
        Ok(Self::decode_with_policy(data, DecodePolicy::Strict)?.value)
    }

    pub(crate) fn decode_with_target(data: Bytes, target: SocketAddr) -> Result<Self> {
        Ok(Self::decode_with_target_and_policy(data, target, DecodePolicy::Compatible)?.value)
    }

    fn decode_with_target_and_policy(
        data: Bytes,
        target: SocketAddr,
        policy: DecodePolicy,
    ) -> Result<DecodeOutcome<Self>> {
        Self::decode_with_target_and_policies(data, target, policy, CompatibilityPolicy::default())
    }

    fn decode_with_target_and_policies(
        data: Bytes,
        target: SocketAddr,
        policy: DecodePolicy,
        compatibility: CompatibilityPolicy,
    ) -> Result<DecodeOutcome<Self>> {
        let mut decoder =
            Decoder::with_target(data, target).with_compatibility_policy(compatibility);
        let mut seq = decoder.read_sequence()?;

        let version_num = seq.read_bounded_integer(0, i32::MAX)?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(version_num) }, "decode error");
            seq.malformed()
        })?;

        let value = Self::decode_from_sequence(&mut seq, version)?;
        let anomaly = finalize_envelope(&seq, &decoder, policy)?;
        Ok(DecodeOutcome { value, anomaly })
    }

    /// Decode from a sequence decoder where version has already been read.
    pub(crate) fn decode_from_sequence(seq: &mut Decoder, version: Version) -> Result<Self> {
        if version == Version::V3 {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(3) }, "decode error");
            return Err(seq.malformed());
        }

        let community = seq.read_octet_string()?;

        // Peek at the PDU tag to dispatch between standard and TrapV1 layouts.
        let pdu_tag = seq.peek_tag().ok_or_else(|| {
            tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), kind = %DecodeErrorKind::TruncatedData }, "truncated community message");
            seq.malformed()
        })?;

        let pdu = if pdu_tag == tag::pdu::TRAP_V1 {
            // The SNMPv1 Trap PDU (tag 0xA4) is only defined for SNMPv1
            // (RFC 1157 Section 4.1.6); SNMPv2c uses the SNMPv2-Trap PDU
            // (tag 0xA7) instead. Reject a v1 Trap carried in a v2c message.
            if version != Version::V1 {
                tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), version = ?version }, "v1 Trap PDU (0xA4) not valid in this version");
                return Err(seq.malformed());
            }
            CommunityPdu::TrapV1(TrapV1Pdu::decode(seq)?)
        } else {
            let pdu = Pdu::decode(seq)?;
            // Enforce version<->PDU-type compatibility. GETBULK, InformRequest,
            // and SNMPv2-Trap are SNMPv2 constructs (RFC 3416) and are not valid
            // in an SNMPv1 message (RFC 1157).
            if !crate::pdu::pdu_type_valid_for_version(pdu.pdu_type(), version) {
                tracing::debug!(target: "async_snmp::ber", { offset = seq.offset(), version = ?version, pdu_type = %pdu.pdu_type() }, "PDU type not valid for SNMP version");
                return Err(seq.malformed());
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
            Pdu::get_bulk(1, 0, 0, varbinds)
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
        buf.try_push_sequence(|buf| {
            pdu.encode(buf)?;
            buf.push_octet_string(b"public");
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
    fn encode_rejects_invalid_oid() {
        let message =
            CommunityMessage::v2c("public", Pdu::get_request(1, &[crate::oid::Oid::empty()]))
                .unwrap();
        assert!(matches!(
            &*message.encode().unwrap_err(),
            Error::InvalidOid(_)
        ));
    }

    #[test]
    fn valid_messages_roundtrip() {
        let trap = trap_v1(vec![]);
        let message = CommunityMessage::v1_trap("public", trap).unwrap();
        let decoded = CommunityMessage::decode(message.encode().unwrap()).unwrap();
        assert_eq!(decoded.version(), Version::V1);
        assert_eq!(decoded.community().as_ref(), b"public");
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
            let decoded = CommunityMessage::decode(message.encode().unwrap()).unwrap();
            assert_eq!(decoded.version(), version);
            assert_eq!(decoded.community().as_ref(), b"private");
            assert_eq!(decoded.pdu().standard().unwrap().request_id, 123);
        }
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
            community: Bytes::from_static(b"public"),
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
                community: Bytes::from_static(b"public"),
                pdu: CommunityPdu::Standard(standard_pdu(
                    pdu_type,
                    vec![VarBind::new(oid!(1, 3, 6, 1), Value::Counter64(1))],
                )),
            }),
        );
        invalid_messages.extend([
            CommunityMessage {
                version: Version::V3,
                community: Bytes::from_static(b"public"),
                pdu: CommunityPdu::Standard(standard_pdu(PduType::GetRequest, vec![])),
            },
            CommunityMessage {
                version: Version::V1,
                community: Bytes::from_static(b"public"),
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
        let bulk = Pdu::get_bulk(7, 0, 10, vec![]);
        assert_invalid_message(CommunityMessage::v1("public", bulk.clone()));
        assert_invalid_message(CommunityMessage::new(Version::V3, "public", bulk.clone()));

        let encoded = CommunityMessage::v2c("public", bulk)
            .unwrap()
            .encode()
            .unwrap();
        let decoded = CommunityMessage::decode(encoded).unwrap();
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
            Pdu::get_bulk(7, -1, -5, vec![VarBind::null(name.clone())]),
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
            assert_invalid_message(
                V3Message::new(global, security_params, scoped)
                    .unwrap()
                    .encode(),
            );
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
            assert!(CommunityMessage::decode(encoded).is_err());
        }

        let trap = trap_v1(vec![]);
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            trap.encode(buf).unwrap();
            buf.push_octet_string(b"public");
            buf.push_integer(Version::V2c.as_i32());
        });
        assert!(CommunityMessage::decode(buf.finish()).is_err());
    }
}
