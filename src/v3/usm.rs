//! User-based Security Model (USM) parameters (RFC 3414).
//!
//! USM security parameters are encoded as an OCTET STRING containing
//! a BER-encoded SEQUENCE:
//!
//! ```text
//! UsmSecurityParameters ::= SEQUENCE {
//!     msgAuthoritativeEngineID     OCTET STRING,
//!     msgAuthoritativeEngineBoots  INTEGER (0..2147483647),
//!     msgAuthoritativeEngineTime   INTEGER (0..2147483647),
//!     msgUserName                  OCTET STRING (SIZE(0..32)),
//!     msgAuthenticationParameters  OCTET STRING,
//!     msgPrivacyParameters         OCTET STRING
//! }
//! ```

use bytes::Bytes;
use std::net::SocketAddr;

use crate::ber::{Decoder, EncodeBuf};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::message::SecurityLevel;
use crate::v3::validate_engine_id;

/// Maximum length of `msgUserName`, per RFC 3414 Section 2.4 (SIZE(0..32)).
const MAX_USER_NAME_LEN: usize = 32;

/// USM security parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsmSecurityParams {
    /// Authoritative engine ID
    pub(crate) engine_id: Bytes,
    /// Engine boot count
    pub(crate) engine_boots: u32,
    /// Engine time (seconds since last boot)
    pub(crate) engine_time: u32,
    /// Username
    pub(crate) username: Bytes,
    /// Authentication parameters (HMAC digest, or empty)
    pub(crate) auth_params: Bytes,
    /// Privacy parameters (salt/IV, or empty)
    pub(crate) priv_params: Bytes,
    /// Whether this value was constructed or decoded as explicit discovery parameters.
    discovery: bool,
}

impl UsmSecurityParams {
    /// Create normal (non-discovery) USM security parameters.
    ///
    /// The authoritative engine ID must satisfy RFC 3411's 5..=32-octet
    /// constraints. Authentication and privacy parameters can then be added
    /// with the fallible builder methods.
    pub fn new(
        engine_id: impl Into<Bytes>,
        engine_boots: u32,
        engine_time: u32,
        username: impl Into<Bytes>,
    ) -> Result<Self> {
        let value = Self {
            engine_id: engine_id.into(),
            engine_boots,
            engine_time,
            username: username.into(),
            auth_params: Bytes::new(),
            priv_params: Bytes::new(),
            discovery: false,
        };
        value.validate_common()?;
        Ok(value)
    }

    /// Create the empty USM parameters used only by engine discovery.
    #[must_use]
    pub fn discovery() -> Self {
        Self {
            engine_id: Bytes::new(),
            engine_boots: 0,
            engine_time: 0,
            username: Bytes::new(),
            auth_params: Bytes::new(),
            priv_params: Bytes::new(),
            discovery: true,
        }
    }

    /// Return the authoritative engine ID.
    #[must_use]
    pub fn engine_id(&self) -> &Bytes {
        &self.engine_id
    }

    /// Return the authoritative engine boots value.
    #[must_use]
    pub fn engine_boots(&self) -> u32 {
        self.engine_boots
    }

    /// Return the authoritative engine time.
    #[must_use]
    pub fn engine_time(&self) -> u32 {
        self.engine_time
    }

    /// Return the USM username.
    #[must_use]
    pub fn username(&self) -> &Bytes {
        &self.username
    }

    /// Return the authentication parameters.
    #[must_use]
    pub fn auth_params(&self) -> &Bytes {
        &self.auth_params
    }

    /// Return the privacy parameters.
    #[must_use]
    pub fn priv_params(&self) -> &Bytes {
        &self.priv_params
    }

    /// Set non-empty authentication parameters.
    pub fn with_auth_params(mut self, auth_params: impl Into<Bytes>) -> Result<Self> {
        self.auth_params = auth_params.into();
        if self.auth_params.is_empty() {
            return Err(
                Error::Config("USM authentication parameters must be non-empty".into()).boxed(),
            );
        }
        self.validate_common()?;
        Ok(self)
    }

    /// Set non-empty privacy parameters on authenticated parameters.
    pub fn with_priv_params(mut self, priv_params: impl Into<Bytes>) -> Result<Self> {
        self.priv_params = priv_params.into();
        if self.priv_params.is_empty() {
            return Err(Error::Config("USM privacy parameters must be non-empty".into()).boxed());
        }
        self.validate_common()?;
        Ok(self)
    }

    /// Create non-empty placeholder auth params for HMAC computation.
    pub fn with_auth_placeholder(self, mac_len: usize) -> Result<Self> {
        self.with_auth_params(Bytes::from(vec![0u8; mac_len]))
    }

    fn validate_common(&self) -> Result<()> {
        if self.engine_boots > i32::MAX as u32 || self.engine_time > i32::MAX as u32 {
            return Err(Error::Config("USM engine boots/time exceed i32::MAX".into()).boxed());
        }
        if self.username.len() > MAX_USER_NAME_LEN {
            return Err(Error::Config(
                format!("USM username exceeds {MAX_USER_NAME_LEN} octets").into(),
            )
            .boxed());
        }
        if self.engine_id.is_empty() {
            if !self.discovery
                || self.engine_boots != 0
                || self.engine_time != 0
                || !self.username.is_empty()
                || !self.auth_params.is_empty()
                || !self.priv_params.is_empty()
            {
                return Err(Error::Config(
                    "empty engine ID is reserved for explicit discovery parameters".into(),
                )
                .boxed());
            }
        } else {
            validate_engine_id(&self.engine_id)?;
        }
        self.validate_field_relationships()
    }

    fn validate_field_relationships(&self) -> Result<()> {
        if self.auth_params.is_empty() && !self.priv_params.is_empty() {
            return Err(Error::Config(
                "USM privacy parameters require authentication parameters".into(),
            )
            .boxed());
        }
        Ok(())
    }

    /// Validate the authentication/privacy fields against the message level.
    pub fn validate_for_security_level(&self, level: SecurityLevel) -> Result<()> {
        self.validate_common()?;
        let valid = match level {
            SecurityLevel::NoAuthNoPriv => {
                self.auth_params.is_empty() && self.priv_params.is_empty()
            }
            SecurityLevel::AuthNoPriv => {
                !self.auth_params.is_empty() && self.priv_params.is_empty()
            }
            SecurityLevel::AuthPriv => !self.auth_params.is_empty() && !self.priv_params.is_empty(),
        };
        if !valid {
            return Err(Error::Config(
                "USM authentication/privacy fields contradict the security level".into(),
            )
            .boxed());
        }
        Ok(())
    }

    /// Encode to BER bytes after revalidating all construction invariants.
    pub fn encode(&self) -> Result<Bytes> {
        self.validate_common()?;
        let mut buf = EncodeBuf::new();
        self.encode_to_buf(&mut buf)?;
        Ok(buf.finish())
    }

    /// Encode to an existing buffer after revalidating all invariants.
    pub fn encode_to_buf(&self, buf: &mut EncodeBuf) -> Result<()> {
        self.validate_common()?;
        buf.try_push_sequence(|buf| {
            buf.try_push_octet_string(&self.priv_params)?;
            buf.try_push_octet_string(&self.auth_params)?;
            buf.try_push_octet_string(&self.username)?;
            buf.push_unsigned32(crate::ber::tag::universal::INTEGER, self.engine_time);
            buf.push_unsigned32(crate::ber::tag::universal::INTEGER, self.engine_boots);
            buf.try_push_octet_string(&self.engine_id)?;
            Ok(())
        })
    }

    /// Decode from BER bytes.
    pub fn decode(data: Bytes) -> Result<Self> {
        Self::decode_with_target(data, UNKNOWN_TARGET)
    }

    pub(crate) fn decode_with_target(data: Bytes, target: SocketAddr) -> Result<Self> {
        let mut decoder = Decoder::with_target(data, target);
        let params = Self::decode_from(&mut decoder)?;
        if !decoder.is_empty() {
            return Err(decoder.malformed());
        }
        Ok(params)
    }

    /// Decode from an existing decoder.
    pub fn decode_from(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;

        let engine_id = seq.read_octet_string()?;

        // RFC 3414: msgAuthoritativeEngineBoots INTEGER (0..2147483647)
        let raw_boots = seq.read_bounded_integer(0, i32::MAX)?;
        let engine_boots = raw_boots as u32;

        // RFC 3414: msgAuthoritativeEngineTime INTEGER (0..2147483647)
        let raw_time = seq.read_bounded_integer(0, i32::MAX)?;
        let engine_time = raw_time as u32;

        // RFC 3414: msgUserName OCTET STRING (SIZE(0..32))
        let username = seq.read_octet_string()?;
        if username.len() > MAX_USER_NAME_LEN {
            tracing::debug!(target: "async_snmp::usm", { offset = seq.offset(), length = username.len(), kind = %DecodeErrorKind::InvalidUserNameLength { length: username.len() } }, "decode error");
            return Err(seq.malformed());
        }

        let auth_params = seq.read_octet_string()?;
        let priv_params = seq.read_octet_string()?;
        if !seq.is_empty() {
            return Err(seq.malformed());
        }
        let discovery = engine_id.is_empty();

        Ok(Self {
            engine_id,
            engine_boots,
            engine_time,
            username,
            auth_params,
            priv_params,
            discovery,
        })
    }

    /// Get the position of `auth_params` within the encoded message.
    ///
    /// This is needed for HMAC computation: we need to know where to
    /// replace the placeholder zeros with the actual HMAC.
    ///
    /// The walk runs through the central [`Decoder`], so every length field is
    /// bounded by its enclosing input; any structural mismatch or truncation
    /// yields `None`.
    #[must_use]
    pub fn find_auth_params_offset(encoded_msg: &[u8]) -> Option<(usize, usize)> {
        use crate::ber::tag::universal::{OCTET_STRING, SEQUENCE};

        // Message structure:
        //   SEQUENCE {
        //     INTEGER version
        //     SEQUENCE msgGlobalData { ... }
        //     OCTET STRING msgSecurityParameters {
        //       SEQUENCE {
        //         OCTET STRING engineID
        //         INTEGER boots
        //         INTEGER time
        //         OCTET STRING username
        //         OCTET STRING authParams  <-- we want this
        //         OCTET STRING privParams
        //       }
        //     }
        //     ...
        //   }
        //
        // `expect_tag` consumes tag + length and leaves the cursor at the
        // content, which for the wrapping constructed/octet-string types is the
        // next element to walk. Because no sub-decoder is created, the cursor
        // stays in absolute coordinates over `encoded_msg`.
        let mut dec = Decoder::from_slice(encoded_msg);

        dec.expect_tag(SEQUENCE).ok()?; // outer SEQUENCE
        dec.skip_tlv().ok()?; // version INTEGER
        dec.skip_tlv().ok()?; // msgGlobalData SEQUENCE
        dec.expect_tag(OCTET_STRING).ok()?; // msgSecurityParameters wrapper
        dec.expect_tag(SEQUENCE).ok()?; // USM params SEQUENCE
        dec.skip_tlv().ok()?; // engineID
        dec.skip_tlv().ok()?; // boots
        dec.skip_tlv().ok()?; // time
        dec.skip_tlv().ok()?; // username

        // authParams OCTET STRING: record the content offset, then confirm the
        // claimed extent fits by actually reading it.
        let auth_len = dec.expect_tag(OCTET_STRING).ok()?;
        let auth_start = dec.offset();
        dec.read_bytes(auth_len).ok()?;
        Some((auth_start, auth_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    fn push_integer_content(buf: &mut EncodeBuf, content: &[u8]) {
        buf.push_bytes(content);
        buf.push_length(content.len()).unwrap();
        buf.push_tag(crate::ber::tag::universal::INTEGER);
    }

    fn params_with_integer_contents(engine_boots: &[u8], engine_time: &[u8]) -> Bytes {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            push_integer_content(buf, engine_time);
            push_integer_content(buf, engine_boots);
            buf.push_octet_string(&[]);
        });
        buf.finish()
    }

    #[test]
    fn constructors_enforce_public_usm_invariants_and_encode_rechecks() {
        assert!(UsmSecurityParams::new(Bytes::new(), 0, 0, Bytes::new()).is_err());
        assert!(UsmSecurityParams::new(b"abcd".as_slice(), 0, 0, Bytes::new()).is_err());
        assert!(UsmSecurityParams::new([0_u8; 8].as_slice(), 0, 0, Bytes::new()).is_err());
        assert!(UsmSecurityParams::new([0xff_u8; 8].as_slice(), 0, 0, Bytes::new()).is_err());
        assert!(
            UsmSecurityParams::new(
                b"engine".as_slice(),
                i32::MAX as u32,
                i32::MAX as u32,
                [b'u'; 32].as_slice()
            )
            .is_ok()
        );
        assert!(
            UsmSecurityParams::new(b"engine".as_slice(), i32::MAX as u32 + 1, 0, Bytes::new())
                .is_err()
        );
        assert!(
            UsmSecurityParams::new(b"engine".as_slice(), 0, i32::MAX as u32 + 1, Bytes::new())
                .is_err()
        );
        assert!(UsmSecurityParams::new(b"engine".as_slice(), 0, 0, [b'u'; 33].as_slice()).is_err());

        let mut params = UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new()).unwrap();
        params.engine_time = i32::MAX as u32 + 1;
        assert!(params.encode().is_err());

        let mut non_discovery =
            UsmSecurityParams::new(b"engine".as_slice(), 0, 0, Bytes::new()).unwrap();
        non_discovery.engine_id = Bytes::new();
        assert!(non_discovery.encode().is_err());

        let discovery = UsmSecurityParams::discovery();
        assert!(discovery.encode().is_ok());
        assert!(
            discovery
                .validate_for_security_level(SecurityLevel::NoAuthNoPriv)
                .is_ok()
        );
        assert!(
            UsmSecurityParams::discovery()
                .with_auth_params([0_u8; 12].as_slice())
                .is_err()
        );
        assert!(
            UsmSecurityParams::discovery()
                .with_auth_placeholder(12)
                .is_err()
        );
    }

    #[test]
    fn security_level_rejects_auth_priv_field_contradictions() {
        let base = UsmSecurityParams::new(b"engine".as_slice(), 0, 0, b"user".as_slice()).unwrap();
        assert!(
            base.validate_for_security_level(SecurityLevel::AuthNoPriv)
                .is_err()
        );
        let auth = base.with_auth_params([0_u8; 12].as_slice()).unwrap();
        assert!(
            auth.validate_for_security_level(SecurityLevel::NoAuthNoPriv)
                .is_err()
        );
        assert!(
            auth.validate_for_security_level(SecurityLevel::AuthPriv)
                .is_err()
        );
        assert!(
            UsmSecurityParams::new(b"engine".as_slice(), 0, 0, b"user".as_slice())
                .unwrap()
                .with_priv_params([0_u8; 8].as_slice())
                .is_err()
        );
    }

    #[test]
    fn test_usm_params_empty_roundtrip() {
        let params = UsmSecurityParams::discovery();
        let encoded = params.encode().unwrap();
        let decoded = UsmSecurityParams::decode(encoded).unwrap();

        assert!(decoded.engine_id.is_empty());
        assert_eq!(decoded.engine_boots, 0);
        assert_eq!(decoded.engine_time, 0);
        assert!(decoded.username.is_empty());
        assert!(decoded.auth_params.is_empty());
        assert!(decoded.priv_params.is_empty());
    }

    #[test]
    fn test_usm_params_roundtrip() {
        let params =
            UsmSecurityParams::new(b"engine-id".as_slice(), 1234, 5678, b"admin".as_slice())
                .unwrap()
                .with_auth_params(b"auth123456789012".as_slice())
                .unwrap() // 12 bytes for HMAC-96
                .with_priv_params(b"priv1234".as_slice())
                .unwrap(); // 8 bytes for salt

        let encoded = params.encode().unwrap();
        let decoded = UsmSecurityParams::decode(encoded).unwrap();

        assert_eq!(decoded.engine_id.as_ref(), b"engine-id");
        assert_eq!(decoded.engine_boots, 1234);
        assert_eq!(decoded.engine_time, 5678);
        assert_eq!(decoded.username.as_ref(), b"admin");
        assert_eq!(decoded.auth_params.as_ref(), b"auth123456789012");
        assert_eq!(decoded.priv_params.as_ref(), b"priv1234");
    }

    #[test]
    fn test_usm_params_rejects_extra_fields_and_trailing_data() {
        let encoded = UsmSecurityParams::discovery().encode().unwrap();

        let mut trailing = encoded.to_vec();
        trailing.extend_from_slice(&[0x05, 0x00]);
        assert!(UsmSecurityParams::decode(Bytes::from(trailing)).is_err());

        let mut extra_field = encoded.to_vec();
        assert_eq!(extra_field[0], 0x30);
        assert!(extra_field[1] < 0x80);
        extra_field[1] += 2;
        extra_field.extend_from_slice(&[0x05, 0x00]);
        assert!(UsmSecurityParams::decode(Bytes::from(extra_field)).is_err());
    }

    #[test]
    fn test_usm_params_with_placeholder() {
        let params = UsmSecurityParams::new(b"engine".as_slice(), 100, 200, b"user".as_slice())
            .unwrap()
            .with_auth_placeholder(12)
            .unwrap(); // HMAC-MD5-96 / HMAC-SHA-96

        assert_eq!(params.auth_params.len(), 12);
        assert!(params.auth_params.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_find_auth_params_offset() {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
        use crate::oid;
        use crate::pdu::Pdu;

        // Create a V3 message with auth placeholder
        let global = MsgGlobalData::new(
            12345,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::AuthNoPriv, true),
        )
        .unwrap();

        let usm_params =
            UsmSecurityParams::new(b"engine123".as_slice(), 100, 200, b"testuser".as_slice())
                .unwrap()
                .with_auth_placeholder(12)
                .unwrap();

        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::with_empty_context(pdu);
        let msg = V3Message::new(global, usm_params.encode().unwrap(), scoped).unwrap();

        let encoded = msg.encode().unwrap();

        // Find the auth params offset
        let (offset, len) = UsmSecurityParams::find_auth_params_offset(&encoded).unwrap();
        assert_eq!(len, 12);

        // Verify the bytes at that offset are zeros
        assert!(encoded[offset..offset + len].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_usm_params_rejects_negative_engine_boots() {
        use crate::ber::EncodeBuf;

        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_integer(100);
            buf.push_integer(-1);
            buf.push_octet_string(&[]);
        });
        let encoded = buf.finish();

        let result = UsmSecurityParams::decode(encoded);
        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_usm_params_rejects_negative_engine_time() {
        use crate::ber::EncodeBuf;

        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_integer(-1);
            buf.push_integer(100);
            buf.push_octet_string(&[]);
        });
        let encoded = buf.finish();

        let result = UsmSecurityParams::decode(encoded);
        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_usm_params_accepts_max_values() {
        use crate::ber::EncodeBuf;

        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_integer(i32::MAX);
            buf.push_integer(i32::MAX);
            buf.push_octet_string(&[]);
        });
        let encoded = buf.finish();

        let decoded = UsmSecurityParams::decode(encoded).unwrap();
        assert_eq!(decoded.engine_boots, i32::MAX as u32);
        assert_eq!(decoded.engine_time, i32::MAX as u32);
    }

    #[test]
    fn usm_params_reject_over_width_engine_time_aliases() {
        const ZERO: &[u8] = &[0x00];
        const TWO_TO_32: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x00];

        assert!(UsmSecurityParams::decode(params_with_integer_contents(TWO_TO_32, ZERO)).is_err());
        assert!(UsmSecurityParams::decode(params_with_integer_contents(ZERO, TWO_TO_32)).is_err());
    }

    #[test]
    fn test_usm_params_accepts_zero_values() {
        use crate::ber::EncodeBuf;

        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_integer(0);
            buf.push_integer(0);
            buf.push_octet_string(&[]);
        });
        let encoded = buf.finish();

        let decoded = UsmSecurityParams::decode(encoded).unwrap();
        assert_eq!(decoded.engine_boots, 0);
        assert_eq!(decoded.engine_time, 0);
    }

    // Regression tests for malformed auth-parameter offset parsing
    // Crafted messages with lengths that advance offset past buffer end must
    // return None rather than panicking.

    #[test]
    fn test_find_auth_params_offset_truncated_returns_none() {
        // Completely empty buffer
        assert_eq!(UsmSecurityParams::find_auth_params_offset(&[]), None);

        // Only the outer SEQUENCE tag, no length byte
        assert_eq!(UsmSecurityParams::find_auth_params_offset(&[0x30]), None);

        // Outer SEQUENCE with length claiming 100 bytes, but buffer is tiny
        // offset will advance past buffer when trying to read version INTEGER tag
        let msg: &[u8] = &[
            0x30, 0x64, // SEQUENCE, length=100 (but buffer ends here)
        ];
        assert_eq!(UsmSecurityParams::find_auth_params_offset(msg), None);
    }

    #[test]
    fn test_find_auth_params_offset_inflated_global_len_returns_none() {
        // Build a message where version INTEGER is valid but msgGlobalData
        // length claims far more bytes than exist in the buffer.
        //
        // Layout:
        //   30 xx          outer SEQUENCE (length covers rest)
        //   02 01 03       INTEGER version=3
        //   30 7f ...      SEQUENCE global with length=127 (but no real content)
        let msg: &[u8] = &[
            0x30, 0x06, // outer SEQUENCE, length=6
            0x02, 0x01, 0x03, // INTEGER version=3
            0x30, 0x7f, // SEQUENCE global, length=127 - advances past buffer end
        ];
        assert_eq!(UsmSecurityParams::find_auth_params_offset(msg), None);
    }

    #[test]
    fn test_find_auth_params_offset_auth_len_overflow_returns_none() {
        // Build a structurally plausible but minimal message where the auth
        // params OCTET STRING tag is present but the encoded length claims
        // more bytes than remain in the buffer.  The function must return
        // None, not panic when the caller later slices with auth_start+auth_len.
        //
        // We need to craft enough structure so the parser gets past:
        //   outer SEQUENCE -> version INTEGER -> global SEQUENCE ->
        //   msgSecurityParameters OCTET STRING -> USM SEQUENCE ->
        //   engineID, boots, time, username (all skipped) ->
        //   authParams tag + inflated length
        //
        // Use a real V3 message encoding as a base, then corrupt the auth
        // params length field to claim 255 bytes.
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
        use crate::oid;
        use crate::pdu::Pdu;

        let global = MsgGlobalData::new(
            1,
            crate::MessageSize::new(1472).unwrap(),
            MsgFlags::new(SecurityLevel::AuthNoPriv, true),
        )
        .unwrap();
        let usm_params = UsmSecurityParams::new(b"engine".as_slice(), 1, 1, b"u".as_slice())
            .unwrap()
            .with_auth_placeholder(12)
            .unwrap();
        let pdu = Pdu::get_request(1, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::with_empty_context(pdu);
        let msg = V3Message::new(global, usm_params.encode().unwrap(), scoped).unwrap();
        let encoded_bytes = msg.encode().unwrap();
        let mut encoded: Vec<u8> = encoded_bytes.to_vec();

        // Locate the real auth params offset so we can corrupt its length byte
        let (auth_start, auth_len) = UsmSecurityParams::find_auth_params_offset(&encoded).unwrap();
        assert_eq!(auth_len, 12);

        // The BER length byte for the auth params is just before auth_start.
        // Set it to 0x40 (64, short-form) so auth_start + auth_len > buffer.
        encoded[auth_start - 1] = 0x40;

        // Must not panic - must return None because the claimed extent
        // (auth_start + 64) exceeds the buffer length.
        assert_eq!(UsmSecurityParams::find_auth_params_offset(&encoded), None);
    }

    #[test]
    fn test_usm_params_rejects_username_over_32_octets() {
        use crate::ber::EncodeBuf;

        let long_username = vec![b'x'; 33];

        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            buf.push_octet_string(&[]);
            buf.push_octet_string(&[]);
            buf.push_octet_string(&long_username);
            buf.push_integer(0);
            buf.push_integer(0);
            buf.push_octet_string(&[]);
        });
        let encoded = buf.finish();

        let result = UsmSecurityParams::decode(encoded);
        assert!(result.is_err());
        assert!(matches!(
            *result.unwrap_err(),
            Error::MalformedResponse { .. }
        ));
    }

    #[test]
    fn test_usm_params_accepts_username_exactly_32_octets() {
        let username = vec![b'u'; 32];
        let params = UsmSecurityParams::new(b"engine".as_slice(), 0, 0, username.clone()).unwrap();

        let encoded = params.encode().unwrap();
        let decoded = UsmSecurityParams::decode(encoded).unwrap();
        assert_eq!(decoded.username.as_ref(), username.as_slice());
    }

    #[test]
    fn test_usm_params_accepts_short_username() {
        let params =
            UsmSecurityParams::new(b"engine".as_slice(), 0, 0, b"admin".as_slice()).unwrap();

        let encoded = params.encode().unwrap();
        let decoded = UsmSecurityParams::decode(encoded).unwrap();
        assert_eq!(decoded.username.as_ref(), b"admin");
    }

    #[test]
    fn usm_security_params_equality() {
        let a = UsmSecurityParams::new(
            Bytes::from_static(b"engine"),
            1,
            100,
            Bytes::from_static(b"user"),
        )
        .unwrap();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
