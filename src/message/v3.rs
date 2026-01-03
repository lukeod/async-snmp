//! SNMPv3 message format (RFC 3412).
//!
//! V3 messages have a more complex structure than v1/v2c:
//! ```text
//! SEQUENCE {
//!     INTEGER version (3)
//!     SEQUENCE msgGlobalData {
//!         INTEGER msgID
//!         INTEGER msgMaxSize
//!         OCTET STRING msgFlags (1 byte)
//!         INTEGER msgSecurityModel
//!     }
//!     OCTET STRING msgSecurityParameters (opaque, USM-encoded)
//!     msgData (ScopedPDU or encrypted OCTET STRING)
//! }
//! ```
//!
//! The msgData field is either:
//! - A plaintext ScopedPDU (SEQUENCE) for noAuthNoPriv/authNoPriv
//! - An encrypted OCTET STRING for authPriv (decrypts to ScopedPDU)

use bytes::Bytes;

use crate::ber::{Decoder, EncodeBuf};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::pdu::Pdu;

/// SNMPv3 security model identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SecurityModel {
    /// User-based Security Model (RFC 3414)
    Usm = 3,
}

impl SecurityModel {
    /// Create from raw value.
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            3 => Some(Self::Usm),
            _ => None,
        }
    }

    /// Get the raw value.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// SNMPv3 security level.
///
/// The variants are ordered from least secure to most secure,
/// supporting VACM-style level comparisons (e.g., `actual >= required`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// No authentication, no privacy
    NoAuthNoPriv,
    /// Authentication only
    AuthNoPriv,
    /// Authentication and privacy (encryption)
    AuthPriv,
}

impl SecurityLevel {
    /// Decode from msgFlags byte.
    pub fn from_flags(flags: u8) -> Option<Self> {
        let auth = flags & 0x01 != 0;
        let priv_ = flags & 0x02 != 0;

        match (auth, priv_) {
            (false, false) => Some(Self::NoAuthNoPriv),
            (true, false) => Some(Self::AuthNoPriv),
            (true, true) => Some(Self::AuthPriv),
            (false, true) => None, // Invalid: priv without auth
        }
    }

    /// Encode to msgFlags byte (without reportable flag).
    pub fn to_flags(self) -> u8 {
        match self {
            Self::NoAuthNoPriv => 0x00,
            Self::AuthNoPriv => 0x01,
            Self::AuthPriv => 0x03,
        }
    }

    /// Check if authentication is required.
    pub fn requires_auth(self) -> bool {
        matches!(self, Self::AuthNoPriv | Self::AuthPriv)
    }

    /// Check if privacy (encryption) is required.
    pub fn requires_priv(self) -> bool {
        matches!(self, Self::AuthPriv)
    }
}

/// Message flags (RFC 3412 Section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsgFlags {
    /// Security level
    pub security_level: SecurityLevel,
    /// Whether a report PDU may be sent on error
    pub reportable: bool,
}

impl MsgFlags {
    /// Create new message flags.
    pub fn new(security_level: SecurityLevel, reportable: bool) -> Self {
        Self {
            security_level,
            reportable,
        }
    }

    /// Decode from byte.
    pub fn from_byte(byte: u8) -> Result<Self> {
        let security_level = SecurityLevel::from_flags(byte).ok_or_else(|| {
            tracing::debug!(
                target: "async_snmp::v3",
                byte,
                kind = %DecodeErrorKind::InvalidMsgFlags,
                "decode error"
            );
            Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed()
        })?;
        let reportable = byte & 0x04 != 0;
        Ok(Self {
            security_level,
            reportable,
        })
    }

    /// Encode to byte.
    pub fn to_byte(self) -> u8 {
        let mut flags = self.security_level.to_flags();
        if self.reportable {
            flags |= 0x04;
        }
        flags
    }
}

/// Message global data header (msgGlobalData).
#[derive(Debug, Clone)]
pub struct MsgGlobalData {
    /// Message identifier for request/response correlation
    pub msg_id: i32,
    /// Maximum message size the sender can accept
    pub msg_max_size: i32,
    /// Message flags (security level + reportable)
    pub msg_flags: MsgFlags,
    /// Security model (always USM=3 for our implementation)
    pub msg_security_model: SecurityModel,
}

impl MsgGlobalData {
    /// Create new global data.
    pub fn new(msg_id: i32, msg_max_size: i32, msg_flags: MsgFlags) -> Self {
        Self {
            msg_id,
            msg_max_size,
            msg_flags,
            msg_security_model: SecurityModel::Usm,
        }
    }

    /// Encode to buffer.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_sequence(|buf| {
            buf.push_integer(self.msg_security_model.as_i32());
            // msgFlags is a 1-byte OCTET STRING
            buf.push_octet_string(&[self.msg_flags.to_byte()]);
            buf.push_integer(self.msg_max_size);
            buf.push_integer(self.msg_id);
        });
    }

    /// Decode from decoder.
    ///
    /// Validates that:
    /// - `msgID` is in range 0..2147483647 (RFC 3412 HeaderData)
    /// - `msgMaxSize` is in range 484..2147483647 (RFC 3412 HeaderData)
    /// - `msgSecurityModel` is a known value (currently only USM=3)
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        const MSG_MAX_SIZE_MINIMUM: i32 = 484;

        let mut seq = decoder.read_sequence()?;

        let msg_id = seq.read_integer()?;
        let msg_max_size = seq.read_integer()?;

        // RFC 3412 HeaderData: msgID INTEGER (0..2147483647)
        if msg_id < 0 {
            tracing::debug!(
                target: "async_snmp::v3",
                offset = seq.offset(),
                value = msg_id,
                kind = %DecodeErrorKind::InvalidMsgId { value: msg_id },
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }

        // RFC 3412 HeaderData: msgMaxSize INTEGER (484..2147483647)
        // Negative values indicate the sender encoded a value > 2^31-1
        if msg_max_size < 0 {
            tracing::debug!(
                target: "async_snmp::v3",
                offset = seq.offset(),
                value = msg_max_size,
                kind = %DecodeErrorKind::MsgMaxSizeTooLarge { value: msg_max_size },
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }

        if msg_max_size < MSG_MAX_SIZE_MINIMUM {
            tracing::debug!(
                target: "async_snmp::v3",
                offset = seq.offset(),
                value = msg_max_size,
                minimum = MSG_MAX_SIZE_MINIMUM,
                kind = %DecodeErrorKind::MsgMaxSizeTooSmall { value: msg_max_size, minimum: MSG_MAX_SIZE_MINIMUM },
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }

        let flags_bytes = seq.read_octet_string()?;
        if flags_bytes.len() != 1 {
            tracing::debug!(
                target: "async_snmp::v3",
                offset = seq.offset(),
                expected = 1,
                actual = flags_bytes.len(),
                "invalid msgFlags length"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }
        let msg_flags = MsgFlags::from_byte(flags_bytes[0])?;

        let msg_security_model_raw = seq.read_integer()?;
        // Reject unknown security models per RFC 3412 Section 7.2
        let msg_security_model =
            SecurityModel::from_i32(msg_security_model_raw).ok_or_else(|| {
                tracing::debug!(
                    target: "async_snmp::v3",
                    offset = seq.offset(),
                    model = msg_security_model_raw,
                    kind = %DecodeErrorKind::UnknownSecurityModel(msg_security_model_raw),
                    "decode error"
                );
                Error::MalformedResponse {
                    target: UNKNOWN_TARGET,
                }
                .boxed()
            })?;

        Ok(Self {
            msg_id,
            msg_max_size,
            msg_flags,
            msg_security_model,
        })
    }
}

/// Scoped PDU (contextEngineID + contextName + PDU).
#[derive(Debug, Clone)]
pub struct ScopedPdu {
    /// Context engine ID (typically same as authoritative engine ID)
    pub context_engine_id: Bytes,
    /// Context name (typically empty string)
    pub context_name: Bytes,
    /// The actual PDU
    pub pdu: Pdu,
}

impl ScopedPdu {
    /// Create a new scoped PDU.
    pub fn new(
        context_engine_id: impl Into<Bytes>,
        context_name: impl Into<Bytes>,
        pdu: Pdu,
    ) -> Self {
        Self {
            context_engine_id: context_engine_id.into(),
            context_name: context_name.into(),
            pdu,
        }
    }

    /// Create with empty context (most common case).
    pub fn with_empty_context(pdu: Pdu) -> Self {
        Self {
            context_engine_id: Bytes::new(),
            context_name: Bytes::new(),
            pdu,
        }
    }

    /// Encode to buffer.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        buf.push_sequence(|buf| {
            self.pdu.encode(buf);
            buf.push_octet_string(&self.context_name);
            buf.push_octet_string(&self.context_engine_id);
        });
    }

    /// Encode to bytes.
    pub fn encode_to_bytes(&self) -> Bytes {
        let mut buf = EncodeBuf::new();
        self.encode(&mut buf);
        buf.finish()
    }

    /// Decode from decoder.
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;

        let context_engine_id = seq.read_octet_string()?;
        let context_name = seq.read_octet_string()?;
        let pdu = Pdu::decode(&mut seq)?;

        Ok(Self {
            context_engine_id,
            context_name,
            pdu,
        })
    }
}

/// SNMPv3 message.
#[derive(Debug, Clone)]
pub struct V3Message {
    /// Global data (header)
    pub global_data: MsgGlobalData,
    /// Security parameters (opaque, USM-encoded)
    pub security_params: Bytes,
    /// Message data - either plaintext ScopedPdu or encrypted bytes
    pub data: V3MessageData,
}

/// Message data payload.
#[derive(Debug, Clone)]
pub enum V3MessageData {
    /// Plaintext scoped PDU (noAuthNoPriv or authNoPriv)
    Plaintext(ScopedPdu),
    /// Encrypted scoped PDU (authPriv) - raw ciphertext
    Encrypted(Bytes),
}

impl V3Message {
    /// Create a new V3 message with plaintext data.
    pub fn new(global_data: MsgGlobalData, security_params: Bytes, scoped_pdu: ScopedPdu) -> Self {
        Self {
            global_data,
            security_params,
            data: V3MessageData::Plaintext(scoped_pdu),
        }
    }

    /// Create a new V3 message with encrypted data.
    pub fn new_encrypted(
        global_data: MsgGlobalData,
        security_params: Bytes,
        encrypted: Bytes,
    ) -> Self {
        Self {
            global_data,
            security_params,
            data: V3MessageData::Encrypted(encrypted),
        }
    }

    /// Get the scoped PDU if available (plaintext only).
    pub fn scoped_pdu(&self) -> Option<&ScopedPdu> {
        match &self.data {
            V3MessageData::Plaintext(pdu) => Some(pdu),
            V3MessageData::Encrypted(_) => None,
        }
    }

    /// Consume and return the scoped PDU if available.
    pub fn into_scoped_pdu(self) -> Option<ScopedPdu> {
        match self.data {
            V3MessageData::Plaintext(pdu) => Some(pdu),
            V3MessageData::Encrypted(_) => None,
        }
    }

    /// Get the PDU if available (convenience method).
    pub fn pdu(&self) -> Option<&Pdu> {
        self.scoped_pdu().map(|s| &s.pdu)
    }

    /// Consume and return the PDU.
    pub fn into_pdu(self) -> Option<Pdu> {
        self.into_scoped_pdu().map(|s| s.pdu)
    }

    /// Get the message ID.
    pub fn msg_id(&self) -> i32 {
        self.global_data.msg_id
    }

    /// Get the security level.
    pub fn security_level(&self) -> SecurityLevel {
        self.global_data.msg_flags.security_level
    }

    /// Encode to BER.
    ///
    /// Note: For authenticated messages, the caller must:
    /// 1. Encode with placeholder auth params (12 zero bytes for HMAC-96)
    /// 2. Compute HMAC over the entire encoded message
    /// 3. Replace the placeholder with the actual HMAC
    pub fn encode(&self) -> Bytes {
        let mut buf = EncodeBuf::new();

        buf.push_sequence(|buf| {
            // msgData
            match &self.data {
                V3MessageData::Plaintext(scoped_pdu) => {
                    scoped_pdu.encode(buf);
                }
                V3MessageData::Encrypted(ciphertext) => {
                    buf.push_octet_string(ciphertext);
                }
            }

            // msgSecurityParameters (as OCTET STRING)
            buf.push_octet_string(&self.security_params);

            // msgGlobalData
            self.global_data.encode(buf);

            // version
            buf.push_integer(3);
        });

        buf.finish()
    }

    /// Decode from BER.
    ///
    /// For encrypted messages, returns `V3MessageData::Encrypted` with the raw ciphertext.
    /// The caller must decrypt using USM before accessing the scoped PDU.
    pub fn decode(data: Bytes) -> Result<Self> {
        let mut decoder = Decoder::new(data);
        let mut seq = decoder.read_sequence()?;

        // Version
        let version = seq.read_integer()?;
        if version != 3 {
            tracing::debug!(
                target: "async_snmp::v3",
                offset = seq.offset(),
                version,
                kind = %DecodeErrorKind::UnknownVersion(version),
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }

        Self::decode_from_sequence(&mut seq)
    }

    /// Decode from a sequence decoder where version has already been read.
    pub(crate) fn decode_from_sequence(seq: &mut Decoder) -> Result<Self> {
        // msgGlobalData
        let global_data = MsgGlobalData::decode(seq)?;

        // msgSecurityParameters (OCTET STRING containing USM params)
        let security_params = seq.read_octet_string()?;

        // msgData - either plaintext SEQUENCE or encrypted OCTET STRING
        let data = if global_data.msg_flags.security_level.requires_priv() {
            // Encrypted: expect OCTET STRING
            let encrypted = seq.read_octet_string()?;
            V3MessageData::Encrypted(encrypted)
        } else {
            // Plaintext: expect SEQUENCE (ScopedPDU)
            let scoped_pdu = ScopedPdu::decode(seq)?;
            V3MessageData::Plaintext(scoped_pdu)
        };

        Ok(Self {
            global_data,
            security_params,
            data,
        })
    }

    /// Create a discovery request message.
    ///
    /// This is sent to discover the engine ID and time of a remote SNMP engine.
    /// Uses empty security parameters and no authentication.
    pub fn discovery_request(msg_id: i32) -> Self {
        let global_data = MsgGlobalData::new(
            msg_id,
            65507, // max UDP size
            MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
        );

        // Empty USM security parameters for discovery
        let security_params = crate::v3::UsmSecurityParams::empty().encode();

        // Empty scoped PDU with Report request
        let pdu = Pdu::get_request(0, &[]);
        let scoped_pdu = ScopedPdu::with_empty_context(pdu);

        Self::new(global_data, security_params, scoped_pdu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    #[test]
    fn test_security_level_flags() {
        assert_eq!(SecurityLevel::NoAuthNoPriv.to_flags(), 0x00);
        assert_eq!(SecurityLevel::AuthNoPriv.to_flags(), 0x01);
        assert_eq!(SecurityLevel::AuthPriv.to_flags(), 0x03);

        assert_eq!(
            SecurityLevel::from_flags(0x00),
            Some(SecurityLevel::NoAuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_flags(0x01),
            Some(SecurityLevel::AuthNoPriv)
        );
        assert_eq!(
            SecurityLevel::from_flags(0x03),
            Some(SecurityLevel::AuthPriv)
        );
        assert_eq!(SecurityLevel::from_flags(0x02), None); // Invalid
    }

    #[test]
    fn test_msg_flags_roundtrip() {
        let flags = MsgFlags::new(SecurityLevel::AuthPriv, true);
        let byte = flags.to_byte();
        assert_eq!(byte, 0x07); // auth=1, priv=1, reportable=1

        let decoded = MsgFlags::from_byte(byte).unwrap();
        assert_eq!(decoded.security_level, SecurityLevel::AuthPriv);
        assert!(decoded.reportable);
    }

    #[test]
    fn test_msg_global_data_roundtrip() {
        let global =
            MsgGlobalData::new(12345, 1472, MsgFlags::new(SecurityLevel::AuthNoPriv, true));

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_id, 12345);
        assert_eq!(decoded.msg_max_size, 1472);
        assert_eq!(decoded.msg_flags.security_level, SecurityLevel::AuthNoPriv);
        assert!(decoded.msg_flags.reportable);
        assert_eq!(decoded.msg_security_model, SecurityModel::Usm);
    }

    #[test]
    fn test_scoped_pdu_roundtrip() {
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::new(b"engine".as_slice(), b"ctx".as_slice(), pdu);

        let mut buf = EncodeBuf::new();
        scoped.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = ScopedPdu::decode(&mut decoder).unwrap();

        assert_eq!(decoded.context_engine_id.as_ref(), b"engine");
        assert_eq!(decoded.context_name.as_ref(), b"ctx");
        assert_eq!(decoded.pdu.request_id, 42);
    }

    #[test]
    fn test_v3_message_plaintext_roundtrip() {
        let global =
            MsgGlobalData::new(100, 1472, MsgFlags::new(SecurityLevel::NoAuthNoPriv, true));
        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::with_empty_context(pdu);
        let msg = V3Message::new(global, Bytes::from_static(b"usm-params"), scoped);

        let encoded = msg.encode();
        let decoded = V3Message::decode(encoded).unwrap();

        assert_eq!(decoded.global_data.msg_id, 100);
        assert_eq!(decoded.security_level(), SecurityLevel::NoAuthNoPriv);
        assert_eq!(decoded.security_params.as_ref(), b"usm-params");

        let scoped_pdu = decoded.scoped_pdu().unwrap();
        assert_eq!(scoped_pdu.pdu.request_id, 42);
    }

    #[test]
    fn test_v3_message_encrypted_roundtrip() {
        let global = MsgGlobalData::new(200, 1472, MsgFlags::new(SecurityLevel::AuthPriv, false));
        let msg = V3Message::new_encrypted(
            global,
            Bytes::from_static(b"usm-params"),
            Bytes::from_static(b"encrypted-data"),
        );

        let encoded = msg.encode();
        let decoded = V3Message::decode(encoded).unwrap();

        assert_eq!(decoded.global_data.msg_id, 200);
        assert_eq!(decoded.security_level(), SecurityLevel::AuthPriv);

        match &decoded.data {
            V3MessageData::Encrypted(data) => {
                assert_eq!(data.as_ref(), b"encrypted-data");
            }
            V3MessageData::Plaintext(_) => panic!("expected encrypted data"),
        }
    }

    #[test]
    fn test_msg_global_data_rejects_msg_max_size_below_minimum() {
        // Encode with invalid msgMaxSize (below 484)
        let global = MsgGlobalData {
            msg_id: 100,
            msg_max_size: 400, // Below RFC 3412 minimum of 484
            msg_flags: MsgFlags::new(SecurityLevel::NoAuthNoPriv, true),
            msg_security_model: SecurityModel::Usm,
        };

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_msg_global_data_accepts_msg_max_size_at_minimum() {
        // 484 is exactly the RFC 3412 minimum
        let global = MsgGlobalData::new(100, 484, MsgFlags::new(SecurityLevel::NoAuthNoPriv, true));

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_max_size, 484);
    }

    #[test]
    fn test_msg_global_data_rejects_unknown_security_model() {
        // Manually build encoded data with unknown security model
        // SEQUENCE { msg_id, msg_max_size, msgFlags, msgSecurityModel=99 }
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(99); // unknown security model
            buf.push_octet_string(&[0x04]); // reportable, noAuthNoPriv
            buf.push_integer(1472); // msg_max_size
            buf.push_integer(100); // msg_id
        });
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_msg_global_data_accepts_usm_security_model() {
        // USM (3) should be accepted
        let global =
            MsgGlobalData::new(100, 1472, MsgFlags::new(SecurityLevel::NoAuthNoPriv, true));

        let mut buf = EncodeBuf::new();
        global.encode(&mut buf);
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_security_model, SecurityModel::Usm);
    }

    // RFC 3412 bounds tests for msgID and msgMaxSize
    //
    // RFC 3412 HeaderData definition specifies:
    //   msgID INTEGER (0..2147483647)
    //   msgMaxSize INTEGER (484..2147483647)
    //
    // Values outside these ranges should be rejected.

    #[test]
    fn test_msg_global_data_rejects_negative_msg_id() {
        // RFC 3412: msgID must be in range [0..2147483647]
        // Negative values should be rejected
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM security model
            buf.push_octet_string(&[0x04]); // reportable, noAuthNoPriv
            buf.push_integer(1472); // valid msg_max_size
            buf.push_integer(-1); // negative msg_id
        });
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_msg_global_data_rejects_negative_msg_max_size() {
        // RFC 3412: msgMaxSize must be in range [484..2147483647]
        // Negative values (from signed integer interpretation) should be rejected
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM security model
            buf.push_octet_string(&[0x04]); // reportable, noAuthNoPriv
            buf.push_integer(-1); // negative msg_max_size (would be > 2^31-1 unsigned)
            buf.push_integer(100); // valid msg_id
        });
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let result = MsgGlobalData::decode(&mut decoder);

        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_msg_global_data_accepts_msg_id_at_zero() {
        // RFC 3412: msgID 0 is at the lower bound, should be accepted
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM
            buf.push_octet_string(&[0x04]); // reportable, noAuthNoPriv
            buf.push_integer(1472); // valid msg_max_size
            buf.push_integer(0); // msg_id at lower bound
        });
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_id, 0);
    }

    #[test]
    fn test_msg_global_data_accepts_msg_id_at_maximum() {
        // RFC 3412: msgID 2147483647 is at the upper bound, should be accepted
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM
            buf.push_octet_string(&[0x04]); // reportable, noAuthNoPriv
            buf.push_integer(1472); // valid msg_max_size
            buf.push_integer(i32::MAX); // msg_id at upper bound (2147483647)
        });
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_id, i32::MAX);
    }

    #[test]
    fn test_msg_global_data_accepts_msg_max_size_at_maximum() {
        // RFC 3412: msgMaxSize 2147483647 is at the upper bound, should be accepted
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_integer(3); // USM
            buf.push_octet_string(&[0x04]); // reportable, noAuthNoPriv
            buf.push_integer(i32::MAX); // msg_max_size at upper bound (2147483647)
            buf.push_integer(100); // valid msg_id
        });
        let encoded = buf.finish();

        let mut decoder = Decoder::new(encoded);
        let decoded = MsgGlobalData::decode(&mut decoder).unwrap();

        assert_eq!(decoded.msg_max_size, i32::MAX);
    }
}
