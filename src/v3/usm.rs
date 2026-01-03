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

use crate::ber::{Decoder, EncodeBuf};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};

/// USM security parameters.
#[derive(Debug, Clone)]
pub struct UsmSecurityParams {
    /// Authoritative engine ID
    pub engine_id: Bytes,
    /// Engine boot count
    pub engine_boots: u32,
    /// Engine time (seconds since last boot)
    pub engine_time: u32,
    /// Username
    pub username: Bytes,
    /// Authentication parameters (HMAC digest, or empty)
    pub auth_params: Bytes,
    /// Privacy parameters (salt/IV, or empty)
    pub priv_params: Bytes,
}

impl UsmSecurityParams {
    /// Create new USM security parameters.
    pub fn new(
        engine_id: impl Into<Bytes>,
        engine_boots: u32,
        engine_time: u32,
        username: impl Into<Bytes>,
    ) -> Self {
        Self {
            engine_id: engine_id.into(),
            engine_boots,
            engine_time,
            username: username.into(),
            auth_params: Bytes::new(),
            priv_params: Bytes::new(),
        }
    }

    /// Create empty security parameters for discovery.
    pub fn empty() -> Self {
        Self {
            engine_id: Bytes::new(),
            engine_boots: 0,
            engine_time: 0,
            username: Bytes::new(),
            auth_params: Bytes::new(),
            priv_params: Bytes::new(),
        }
    }

    /// Set authentication parameters.
    pub fn with_auth_params(mut self, auth_params: impl Into<Bytes>) -> Self {
        self.auth_params = auth_params.into();
        self
    }

    /// Set privacy parameters.
    pub fn with_priv_params(mut self, priv_params: impl Into<Bytes>) -> Self {
        self.priv_params = priv_params.into();
        self
    }

    /// Create placeholder auth params for HMAC computation.
    ///
    /// For authenticated messages, the auth params field is filled with zeros
    /// during encoding, then the HMAC is computed over the entire message,
    /// and finally the zeros are replaced with the actual HMAC.
    pub fn with_auth_placeholder(mut self, mac_len: usize) -> Self {
        self.auth_params = Bytes::from(vec![0u8; mac_len]);
        self
    }

    /// Encode to BER bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = EncodeBuf::new();
        self.encode_to_buf(&mut buf);
        buf.finish()
    }

    /// Encode to an existing buffer.
    pub fn encode_to_buf(&self, buf: &mut EncodeBuf) {
        buf.push_sequence(|buf| {
            buf.push_octet_string(&self.priv_params);
            buf.push_octet_string(&self.auth_params);
            buf.push_octet_string(&self.username);
            buf.push_unsigned32(crate::ber::tag::universal::INTEGER, self.engine_time);
            buf.push_unsigned32(crate::ber::tag::universal::INTEGER, self.engine_boots);
            buf.push_octet_string(&self.engine_id);
        });
    }

    /// Decode from BER bytes.
    pub fn decode(data: Bytes) -> Result<Self> {
        let mut decoder = Decoder::new(data);
        Self::decode_from(&mut decoder)
    }

    /// Decode from an existing decoder.
    pub fn decode_from(decoder: &mut Decoder) -> Result<Self> {
        let mut seq = decoder.read_sequence()?;

        let engine_id = seq.read_octet_string()?;

        // RFC 3414: msgAuthoritativeEngineBoots INTEGER (0..2147483647)
        let raw_boots = seq.read_integer()?;
        if raw_boots < 0 {
            tracing::debug!(
                target: "async_snmp::usm",
                offset = seq.offset(),
                value = raw_boots,
                kind = %DecodeErrorKind::InvalidEngineBoots { value: raw_boots },
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }
        let engine_boots = raw_boots as u32;

        // RFC 3414: msgAuthoritativeEngineTime INTEGER (0..2147483647)
        let raw_time = seq.read_integer()?;
        if raw_time < 0 {
            tracing::debug!(
                target: "async_snmp::usm",
                offset = seq.offset(),
                value = raw_time,
                kind = %DecodeErrorKind::InvalidEngineTime { value: raw_time },
                "decode error"
            );
            return Err(Error::MalformedResponse {
                target: UNKNOWN_TARGET,
            }
            .boxed());
        }
        let engine_time = raw_time as u32;

        let username = seq.read_octet_string()?;
        let auth_params = seq.read_octet_string()?;
        let priv_params = seq.read_octet_string()?;

        Ok(Self {
            engine_id,
            engine_boots,
            engine_time,
            username,
            auth_params,
            priv_params,
        })
    }

    /// Get the position of auth_params within the encoded message.
    ///
    /// This is needed for HMAC computation: we need to know where to
    /// replace the placeholder zeros with the actual HMAC.
    pub fn find_auth_params_offset(encoded_msg: &[u8]) -> Option<(usize, usize)> {
        // Navigate the BER structure to find auth_params location
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

        let mut offset = 0;

        // Outer SEQUENCE
        if offset >= encoded_msg.len() {
            return None;
        }
        if encoded_msg[offset] != 0x30 {
            return None;
        }
        offset += 1;
        let (_, len_size) = parse_length(&encoded_msg[offset..])?;
        offset += len_size;

        // Version INTEGER
        if encoded_msg[offset] != 0x02 {
            return None;
        }
        offset += 1;
        let (ver_len, len_size) = parse_length(&encoded_msg[offset..])?;
        offset += len_size + ver_len;

        // msgGlobalData SEQUENCE
        if encoded_msg[offset] != 0x30 {
            return None;
        }
        offset += 1;
        let (global_len, len_size) = parse_length(&encoded_msg[offset..])?;
        offset += len_size + global_len;

        // msgSecurityParameters OCTET STRING
        if encoded_msg[offset] != 0x04 {
            return None;
        }
        offset += 1;
        let (_, len_size) = parse_length(&encoded_msg[offset..])?;
        offset += len_size;

        // Now we're inside the USM params SEQUENCE

        // USM SEQUENCE tag
        if encoded_msg[offset] != 0x30 {
            return None;
        }
        offset += 1;
        let (_, len_size) = parse_length(&encoded_msg[offset..])?;
        offset += len_size;

        // engineID OCTET STRING
        offset = skip_tlv(encoded_msg, offset)?;

        // boots INTEGER
        offset = skip_tlv(encoded_msg, offset)?;

        // time INTEGER
        offset = skip_tlv(encoded_msg, offset)?;

        // username OCTET STRING
        offset = skip_tlv(encoded_msg, offset)?;

        // authParams OCTET STRING - this is what we're looking for
        if encoded_msg[offset] != 0x04 {
            return None;
        }
        offset += 1;
        let (auth_len, len_size) = parse_length(&encoded_msg[offset..])?;
        let auth_start = offset + len_size;

        Some((auth_start, auth_len))
    }
}

/// Parse a BER length, returning (length, bytes_consumed).
fn parse_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first < 0x80 {
        // Short form
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite form - not supported
        None
    } else {
        // Long form
        let count = (first & 0x7F) as usize;
        if count > 4 || count == 0 || data.len() < 1 + count {
            return None;
        }

        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Some((len, 1 + count))
    }
}

/// Skip a TLV, returning the new offset.
fn skip_tlv(data: &[u8], offset: usize) -> Option<usize> {
    if offset >= data.len() {
        return None;
    }

    // Skip tag
    let mut pos = offset + 1;
    if pos >= data.len() {
        return None;
    }

    // Parse length
    let (len, len_size) = parse_length(&data[pos..])?;
    pos += len_size + len;

    if pos > data.len() {
        return None;
    }

    Some(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usm_params_empty_roundtrip() {
        let params = UsmSecurityParams::empty();
        let encoded = params.encode();
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
                .with_auth_params(b"auth123456789012".as_slice()) // 12 bytes for HMAC-96
                .with_priv_params(b"priv1234".as_slice()); // 8 bytes for salt

        let encoded = params.encode();
        let decoded = UsmSecurityParams::decode(encoded).unwrap();

        assert_eq!(decoded.engine_id.as_ref(), b"engine-id");
        assert_eq!(decoded.engine_boots, 1234);
        assert_eq!(decoded.engine_time, 5678);
        assert_eq!(decoded.username.as_ref(), b"admin");
        assert_eq!(decoded.auth_params.as_ref(), b"auth123456789012");
        assert_eq!(decoded.priv_params.as_ref(), b"priv1234");
    }

    #[test]
    fn test_usm_params_with_placeholder() {
        let params = UsmSecurityParams::new(b"engine".as_slice(), 100, 200, b"user".as_slice())
            .with_auth_placeholder(12); // HMAC-MD5-96 / HMAC-SHA-96

        assert_eq!(params.auth_params.len(), 12);
        assert!(params.auth_params.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_find_auth_params_offset() {
        use crate::message::{MsgFlags, MsgGlobalData, ScopedPdu, SecurityLevel, V3Message};
        use crate::oid;
        use crate::pdu::Pdu;

        // Create a V3 message with auth placeholder
        let global =
            MsgGlobalData::new(12345, 1472, MsgFlags::new(SecurityLevel::AuthNoPriv, true));

        let usm_params =
            UsmSecurityParams::new(b"engine123".as_slice(), 100, 200, b"testuser".as_slice())
                .with_auth_placeholder(12);

        let pdu = Pdu::get_request(42, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
        let scoped = ScopedPdu::with_empty_context(pdu);
        let msg = V3Message::new(global, usm_params.encode(), scoped);

        let encoded = msg.encode();

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
}
