//! SNMP message wrappers.
//!
//! Messages encapsulate PDUs with version and authentication information.
//!
//! # Message Types
//!
//! - [`CommunityMessage`] - V1/V2c messages with community string auth
//! - [`V3Message`] - V3 messages with USM security

mod community;
mod v3;

pub use community::{CommunityMessage, CommunityPdu};
pub(crate) use v3::{MpdFailure, classify_mpd_failure};
pub use v3::{
    MsgFlags, MsgGlobalData, RawMsgData, RawV3Message, ScopedPdu, SecurityLevel, V3Message,
    V3MessageData, V3SecurityModel,
};

use crate::ber::Decoder;
use crate::compatibility::CompatibilityPolicy;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::pdu::Pdu;
use crate::version::Version;
use bytes::Bytes;
use std::net::SocketAddr;

/// Policy for bytes following a complete top-level SNMP message TLV.
///
/// Both policies reject unconsumed fields inside the message's declared outer
/// SEQUENCE. [`DecodePolicy::Compatible`] accepts a packet suffix and reports
/// its exact size as a [`DecodeAnomaly`]; [`DecodePolicy::Strict`] rejects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodePolicy {
    /// Preserve interoperability with transports that deliver a valid SNMP TLV
    /// followed by unrelated bytes. This is the default used by `decode` APIs.
    Compatible,
    /// Require the complete input to contain exactly one SNMP message TLV.
    Strict,
}

/// Observable non-canonical input accepted by compatible decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeAnomaly {
    /// Number of bytes following the fully consumed top-level message TLV.
    pub trailing_bytes: usize,
}

/// A decoded value together with compatible-mode anomaly metadata.
#[derive(Debug)]
pub struct DecodeOutcome<T> {
    /// Decoded value.
    pub value: T,
    /// Input anomaly, if compatible decoding accepted a packet suffix.
    pub anomaly: Option<DecodeAnomaly>,
}

pub(crate) fn finalize_envelope(
    sequence: &Decoder,
    root: &Decoder,
    policy: DecodePolicy,
) -> Result<Option<DecodeAnomaly>> {
    if !sequence.is_empty() {
        tracing::debug!(target: "async_snmp::message", { remaining = sequence.remaining() }, "unconsumed field inside SNMP message envelope");
        return Err(sequence.malformed());
    }

    let trailing_bytes = root.remaining();
    if trailing_bytes == 0 {
        return Ok(None);
    }
    if policy == DecodePolicy::Strict {
        tracing::debug!(target: "async_snmp::message", { trailing_bytes }, "bytes follow SNMP message envelope");
        return Err(root.malformed());
    }

    // Stable event and field names let callers observe anomalies even when
    // using the legacy value-only `decode` convenience methods.
    tracing::warn!(target: "async_snmp::message", anomaly = "trailing_bytes", trailing_bytes, peer = %root.target(), "accepted trailing bytes after SNMP message");
    Ok(Some(DecodeAnomaly { trailing_bytes }))
}

/// Decoded SNMP message (any version).
///
/// This enum provides a unified interface for working with SNMP messages
/// regardless of version. Use [`Message::decode`] to parse incoming data.
#[derive(Debug)]
pub enum Message {
    /// `SNMPv1` or `SNMPv2c` message with community string
    Community(CommunityMessage),
    /// `SNMPv3` message with USM security
    V3(V3Message),
}

impl Message {
    /// Get a reference to the PDU.
    ///
    /// Returns `None` for encrypted V3 messages or `SNMPv1` Trap messages.
    pub fn pdu(&self) -> Option<&Pdu> {
        match self {
            Message::Community(m) => m.pdu().standard(),
            Message::V3(m) => m.pdu(),
        }
    }

    /// Consume and return the PDU.
    ///
    /// Returns `None` for encrypted V3 messages or `SNMPv1` Trap messages.
    pub fn into_pdu(self) -> Option<Pdu> {
        match self {
            Message::Community(m) => m.into_pdu(),
            Message::V3(m) => m.into_pdu(),
        }
    }

    /// Get the SNMP version.
    pub fn version(&self) -> Version {
        match self {
            Message::Community(m) => m.version(),
            Message::V3(_) => Version::V3,
        }
    }

    /// Decode using the default compatible top-level policy.
    ///
    /// The complete declared message SEQUENCE is always required. A suffix
    /// after that SEQUENCE is accepted and emits the stable
    /// `async_snmp::message` `trailing_bytes` anomaly event. Use
    /// [`Message::decode_with_policy`] to retain anomaly metadata.
    pub fn decode(data: Bytes) -> Result<Self> {
        Ok(Self::decode_with_policy(data, DecodePolicy::Compatible)?.value)
    }

    /// Decode using an explicit top-level consumption policy.
    pub fn decode_with_policy(data: Bytes, policy: DecodePolicy) -> Result<DecodeOutcome<Self>> {
        Self::decode_with_policies(data, policy, CompatibilityPolicy::default())
    }

    /// Decode using an explicit malformed-input compatibility policy and the
    /// default compatible top-level consumption policy.
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
        let input_len = data.len();
        Self::decode_bounded_with_target_and_compatibility(
            data,
            input_len,
            UNKNOWN_TARGET,
            policy,
            compatibility,
        )
    }

    /// Decode while requiring the input to contain exactly one message TLV.
    pub fn decode_strict(data: Bytes) -> Result<Self> {
        Ok(Self::decode_with_policy(data, DecodePolicy::Strict)?.value)
    }

    pub(crate) fn decode_bounded_with_target(
        data: Bytes,
        maximum: usize,
        target: SocketAddr,
        policy: DecodePolicy,
    ) -> Result<DecodeOutcome<Self>> {
        Self::decode_bounded_with_target_and_compatibility(
            data,
            maximum,
            target,
            policy,
            CompatibilityPolicy::default(),
        )
    }

    fn decode_bounded_with_target_and_compatibility(
        data: Bytes,
        maximum: usize,
        target: SocketAddr,
        policy: DecodePolicy,
        compatibility: CompatibilityPolicy,
    ) -> Result<DecodeOutcome<Self>> {
        if data.len() > maximum {
            tracing::debug!(target: "async_snmp::message", { received_size = data.len(), maximum, peer = %target }, "message exceeds receive limit");
            return Err(Error::MalformedResponse { target }.boxed());
        }
        let mut decoder =
            Decoder::with_target(data, target).with_compatibility_policy(compatibility);
        let mut seq = decoder.read_sequence()?;

        let version_num = seq.read_bounded_integer(0, i32::MAX)?;
        let version = Version::from_i32(version_num).ok_or_else(|| {
            tracing::debug!(target: "async_snmp::message", { offset = seq.offset(), kind = %DecodeErrorKind::UnknownVersion(version_num) }, "decode error");
            seq.malformed()
        })?;

        let value = match version {
            Version::V1 | Version::V2c => {
                Message::Community(CommunityMessage::decode_from_sequence(&mut seq, version)?)
            }
            Version::V3 => Message::V3(V3Message::decode_from_sequence(&mut seq)?),
        };
        let anomaly = finalize_envelope(&seq, &decoder, policy)?;
        Ok(DecodeOutcome { value, anomaly })
    }
}

/// Peek at the version integer of an encoded SNMP message without decoding
/// the rest, for version-based dispatch. `target` is only used as the
/// error's target address.
pub(crate) fn peek_version(data: Bytes, target: std::net::SocketAddr) -> Result<Version> {
    let mut decoder = Decoder::with_target(data, target);
    let mut seq = decoder.read_sequence()?;
    let version_num = seq.read_bounded_integer(0, i32::MAX)?;
    Version::from_i32(version_num).ok_or_else(|| {
        tracing::debug!(target: "async_snmp::message", { source = %target, kind = %DecodeErrorKind::UnknownVersion(version_num) }, "unknown SNMP version");
        Error::MalformedResponse { target }.boxed()
    })
}

// Convenience conversions
impl From<CommunityMessage> for Message {
    fn from(msg: CommunityMessage) -> Self {
        Message::Community(msg)
    }
}

impl From<V3Message> for Message {
    fn from(msg: V3Message) -> Self {
        Message::V3(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_exception_compatibility_policy_reaches_message_values() {
        let encoded = Bytes::from_static(&[
            0x30, 0x20, // message
            0x02, 0x01, 0x01, // v2c
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa2, 0x13, // response PDU
            0x02, 0x01, 0x01, // request-id
            0x02, 0x01, 0x00, // error-status
            0x02, 0x01, 0x00, // error-index
            0x30, 0x08, // varbind list
            0x30, 0x06, 0x06, 0x01, 0x2b, 0x80, 0x01, 0xff,
        ]);
        assert!(Message::decode(encoded.clone()).is_err());

        let compatibility = CompatibilityPolicy {
            malformed_exception_payloads: true,
            ..CompatibilityPolicy::STRICT
        };
        let decoded = Message::decode_with_compatibility_policy(encoded, compatibility).unwrap();
        assert_eq!(
            decoded.pdu().unwrap().varbinds[0].value,
            crate::Value::NoSuchObject
        );
    }

    #[test]
    fn bounded_decode_replaces_the_previous_global_two_mib_ceiling() {
        let message = CommunityMessage::new(
            Version::V2c,
            vec![b'x'; 3 * 1024 * 1024],
            Pdu::get_request(1, &[]),
        )
        .unwrap();
        let encoded = message.encode().unwrap();
        let encoded_len = encoded.len();

        assert!(
            Message::decode_bounded_with_target(
                encoded.clone(),
                encoded_len,
                UNKNOWN_TARGET,
                DecodePolicy::Compatible,
            )
            .is_ok()
        );
        assert!(
            Message::decode_bounded_with_target(
                encoded,
                encoded_len - 1,
                UNKNOWN_TARGET,
                DecodePolicy::Compatible,
            )
            .is_err()
        );
    }

    #[test]
    fn community_decoders_share_envelope_and_root_suffix_policy() {
        let encoded = CommunityMessage::v2c("public", Pdu::get_request(1, &[]))
            .unwrap()
            .encode()
            .unwrap();

        assert_eq!(
            Message::decode_with_policy(encoded.clone(), DecodePolicy::Compatible)
                .unwrap()
                .anomaly,
            None
        );
        assert_eq!(
            CommunityMessage::decode_with_policy(encoded.clone(), DecodePolicy::Strict)
                .unwrap()
                .anomaly,
            None
        );

        let mut suffix = encoded.to_vec();
        suffix.extend_from_slice(&[0x05, 0x00, 0x05, 0x00]);
        let suffix = Bytes::from(suffix);
        assert_eq!(
            Message::decode_with_policy(suffix.clone(), DecodePolicy::Compatible)
                .unwrap()
                .anomaly
                .unwrap()
                .trailing_bytes,
            4
        );
        assert_eq!(
            CommunityMessage::decode_with_policy(suffix.clone(), DecodePolicy::Compatible)
                .unwrap()
                .anomaly
                .unwrap()
                .trailing_bytes,
            4
        );
        assert!(Message::decode_strict(suffix.clone()).is_err());
        assert!(CommunityMessage::decode_strict(suffix).is_err());

        // Move an extra NULL inside the declared outer SEQUENCE. Compatible
        // mode is permissive only after the root TLV, never inside it.
        let mut inner_extra = encoded.to_vec();
        assert!(inner_extra[1] < 0x80, "fixture uses short-form length");
        inner_extra[1] += 2;
        inner_extra.extend_from_slice(&[0x05, 0x00]);
        let inner_extra = Bytes::from(inner_extra);
        assert!(Message::decode(inner_extra.clone()).is_err());
        assert!(CommunityMessage::decode(inner_extra).is_err());
    }

    #[test]
    fn peer_target_survives_nested_pdu_decoder_errors() {
        let mut encoded = CommunityMessage::v2c("public", Pdu::get_request(1, &[]))
            .unwrap()
            .encode()
            .unwrap()
            .to_vec();
        let pdu_start = encoded
            .iter()
            .position(|byte| *byte == crate::ber::tag::pdu::GET_REQUEST)
            .unwrap();
        assert!(encoded[1] < 0x80 && encoded[pdu_start + 1] < 0x80);
        let pdu_end = pdu_start + 2 + usize::from(encoded[pdu_start + 1]);
        encoded[1] += 2;
        encoded[pdu_start + 1] += 2;
        encoded.splice(pdu_end..pdu_end, [0x05, 0x00]);

        assert_peer_target(encoded);
    }

    #[test]
    fn peer_target_survives_nested_varbind_and_value_errors() {
        let encoded = CommunityMessage::v2c(
            "public",
            Pdu::get_request(1, &[crate::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]),
        )
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
        let oid_tlv = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
        let oid_start = encoded
            .windows(oid_tlv.len())
            .position(|window| window == oid_tlv)
            .unwrap();
        let varbind_start = oid_start - 2;
        let varbind_list_start = varbind_start - 2;
        let pdu_start = encoded
            .iter()
            .position(|byte| *byte == crate::ber::tag::pdu::GET_REQUEST)
            .unwrap();
        let null_start = oid_start + oid_tlv.len();
        assert_eq!(&encoded[null_start..null_start + 2], &[0x05, 0x00]);
        for length_offset in [1, pdu_start + 1, varbind_list_start + 1, varbind_start + 1] {
            assert!(
                encoded[length_offset] < 0x80,
                "fixture uses short-form lengths"
            );
        }

        let mut extra_varbind_field = encoded.clone();
        let varbind_end = varbind_start + 2 + usize::from(extra_varbind_field[varbind_start + 1]);
        for length_offset in [1, pdu_start + 1, varbind_list_start + 1, varbind_start + 1] {
            extra_varbind_field[length_offset] += 2;
        }
        extra_varbind_field.splice(varbind_end..varbind_end, [0x05, 0x00]);
        assert_peer_target(extra_varbind_field);

        let mut malformed_oid = encoded.clone();
        malformed_oid[oid_start + oid_tlv.len() - 1] = 0x80;
        assert_peer_target(malformed_oid);

        let mut constructed_octet_string = encoded;
        constructed_octet_string[null_start] = crate::ber::tag::universal::OCTET_STRING_CONSTRUCTED;
        assert_peer_target(constructed_octet_string);
    }

    fn assert_peer_target(encoded: Vec<u8>) {
        let peer: SocketAddr = "192.0.2.44:161".parse().unwrap();
        let len = encoded.len();
        let error = Message::decode_bounded_with_target(
            Bytes::from(encoded),
            len,
            peer,
            DecodePolicy::Compatible,
        )
        .unwrap_err();
        assert!(matches!(&*error, Error::MalformedResponse { target } if *target == peer));
    }
}
