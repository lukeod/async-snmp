//! Community-based SNMP message format (v1/v2c).
//!
//! V1 and V2c messages share the same structure:
//! `SEQUENCE { version INTEGER, community OCTET STRING, pdu PDU }`
//!
//! The only difference is the version number (0 for v1, 1 for v2c).

use crate::ber::{Decoder, EncodeBuf};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::pdu::{GetBulkPdu, Pdu};
use crate::version::Version;
use bytes::Bytes;

/// Community-based SNMP message (v1/v2c).
///
/// This unified type handles both SNMPv1 and SNMPv2c messages,
/// which share identical structure but differ in version number.
#[derive(Debug, Clone)]
pub struct CommunityMessage {
    /// SNMP version (V1 or V2c)
    pub version: Version,
    /// Community string for authentication
    pub community: Bytes,
    /// Protocol data unit
    pub pdu: Pdu,
}

impl CommunityMessage {
    /// Create a new community message.
    ///
    /// # Panics
    /// Panics if version is V3 (use V3Message instead).
    pub fn new(version: Version, community: impl Into<Bytes>, pdu: Pdu) -> Self {
        assert!(
            matches!(version, Version::V1 | Version::V2c),
            "CommunityMessage only supports V1/V2c, not {:?}",
            version
        );
        Self {
            version,
            community: community.into(),
            pdu,
        }
    }

    /// Create a V2c message (convenience constructor).
    pub fn v2c(community: impl Into<Bytes>, pdu: Pdu) -> Self {
        Self::new(Version::V2c, community, pdu)
    }

    /// Create a V1 message (convenience constructor).
    pub fn v1(community: impl Into<Bytes>, pdu: Pdu) -> Self {
        Self::new(Version::V1, community, pdu)
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
            tracing::debug!(
                target: "async_snmp::ber",
                offset = seq.offset(),
                kind = %DecodeErrorKind::UnknownVersion(version_num),
                "decode error"
            );
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
            tracing::debug!(
                target: "async_snmp::ber",
                offset = seq.offset(),
                kind = %DecodeErrorKind::UnknownVersion(3),
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }

        let community = seq.read_octet_string()?;
        let pdu = Pdu::decode(seq)?;

        Ok(CommunityMessage {
            version,
            community,
            pdu,
        })
    }

    /// Consume and return the PDU.
    pub fn into_pdu(self) -> Pdu {
        self.pdu
    }

    /// Encode a GETBULK request message (v2c/v3 only).
    ///
    /// GETBULK is not supported in SNMPv1.
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

    #[test]
    fn test_v1_roundtrip() {
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let msg = CommunityMessage::v1(b"public".as_slice(), pdu);

        let encoded = msg.encode();
        let decoded = CommunityMessage::decode(encoded).unwrap();

        assert_eq!(decoded.version, Version::V1);
        assert_eq!(decoded.community.as_ref(), b"public");
        assert_eq!(decoded.pdu.request_id, 42);
    }

    #[test]
    fn test_v2c_roundtrip() {
        let pdu = Pdu::get_request(123, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let msg = CommunityMessage::v2c(b"private".as_slice(), pdu);

        let encoded = msg.encode();
        let decoded = CommunityMessage::decode(encoded).unwrap();

        assert_eq!(decoded.version, Version::V2c);
        assert_eq!(decoded.community.as_ref(), b"private");
        assert_eq!(decoded.pdu.request_id, 123);
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
