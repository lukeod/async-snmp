//! BER decoding.
//!
//! Zero-copy decoding using `Bytes` to avoid allocations.

use std::net::SocketAddr;

use super::length::decode_length;
use super::tag;
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::oid::Oid;
use bytes::Bytes;

/// BER decoder that reads from a byte buffer.
pub struct Decoder {
    data: Bytes,
    offset: usize,
    target: Option<SocketAddr>,
}

impl Decoder {
    /// Create a new decoder from bytes.
    pub fn new(data: Bytes) -> Self {
        Self {
            data,
            offset: 0,
            target: None,
        }
    }

    /// Create a decoder from bytes with a target address for error context.
    pub fn with_target(data: Bytes, target: SocketAddr) -> Self {
        Self {
            data,
            offset: 0,
            target: Some(target),
        }
    }

    /// Create a decoder from a byte slice (copies the data).
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(data))
    }

    /// Get the target address for error context.
    fn target(&self) -> SocketAddr {
        self.target.unwrap_or(UNKNOWN_TARGET)
    }

    /// Return a boxed MalformedResponse error for the current target.
    fn malformed(&self) -> Box<crate::error::Error> {
        Error::MalformedResponse {
            target: self.target(),
        }
        .boxed()
    }

    /// Get the current offset.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Get remaining bytes.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    /// Check if we've reached the end.
    pub fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Peek at the next byte without consuming it.
    pub fn peek_byte(&self) -> Option<u8> {
        if self.offset < self.data.len() {
            Some(self.data[self.offset])
        } else {
            None
        }
    }

    /// Peek at the next tag without consuming it.
    ///
    /// Returns `None` if the buffer is empty or if the next byte signals a
    /// multi-byte tag (low five bits all set, i.e. `byte & 0x1F == 0x1F`).
    /// Valid SNMP uses only single-byte tags (all defined tags are below 31).
    pub fn peek_tag(&self) -> Option<u8> {
        let byte = self.peek_byte()?;
        if byte & 0x1F == 0x1F {
            return None;
        }
        Some(byte)
    }

    /// Read a single byte.
    pub fn read_byte(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::TruncatedData }, "truncated data: unexpected end of input");
            return Err(self.malformed());
        }
        let byte = self.data[self.offset];
        self.offset += 1;
        Ok(byte)
    }

    /// Read a tag byte.
    ///
    /// Returns an error if the tag byte signals a multi-byte tag
    /// (low five bits all set, i.e. `byte & 0x1F == 0x1F`).
    /// Valid SNMP uses only single-byte tags (all defined tags are below 31).
    pub fn read_tag(&mut self) -> Result<u8> {
        let tag = self.read_byte()?;
        if tag & 0x1F == 0x1F {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset - 1, kind = %DecodeErrorKind::UnexpectedTag { expected: 0, actual: tag } }, "multi-byte tag not supported");
            return Err(self.malformed());
        }
        Ok(tag)
    }

    /// Read a length and return (length, bytes consumed).
    pub fn read_length(&mut self) -> Result<usize> {
        let (len, consumed) = decode_length(&self.data[self.offset..], self.offset, self.target)?;
        self.offset += consumed;
        Ok(len)
    }

    /// Read raw bytes without copying.
    pub fn read_bytes(&mut self, len: usize) -> Result<Bytes> {
        // Use saturating_add to prevent overflow from bypassing bounds check
        if self.offset.saturating_add(len) > self.data.len() {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::InsufficientData { needed: len, available: self.remaining() } }, "insufficient data");
            return Err(self.malformed());
        }
        let bytes = self.data.slice(self.offset..self.offset + len);
        self.offset += len;
        Ok(bytes)
    }

    /// Read and expect a specific tag, returning the content length.
    pub fn expect_tag(&mut self, expected: u8) -> Result<usize> {
        let tag = self.read_tag()?;
        if tag != expected {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset - 1, kind = %DecodeErrorKind::UnexpectedTag { expected, actual: tag } }, "unexpected tag");
            return Err(self.malformed());
        }
        self.read_length()
    }

    /// Read a BER integer (signed).
    pub fn read_integer(&mut self) -> Result<i32> {
        let len = self.expect_tag(tag::universal::INTEGER)?;
        self.read_integer_value(len)
    }

    /// Read integer value given the length.
    pub fn read_integer_value(&mut self, len: usize) -> Result<i32> {
        if len == 0 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::ZeroLengthInteger }, "zero-length integer");
            return Err(self.malformed());
        }
        if len > 4 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::IntegerTooLong { length: len } }, "integer encoding too long");
            return Err(self.malformed());
        }

        let bytes = self.read_bytes(len)?;

        // Sign extend
        let is_negative = bytes[0] & 0x80 != 0;
        let mut value: i32 = if is_negative { -1 } else { 0 };

        for &byte in bytes.iter() {
            value = (value << 8) | (byte as i32);
        }

        Ok(value)
    }

    /// Read a 64-bit unsigned integer (Counter64).
    pub fn read_integer64(&mut self, expected_tag: u8) -> Result<u64> {
        let len = self.expect_tag(expected_tag)?;
        self.read_integer64_value(len)
    }

    /// Read 64-bit unsigned integer value given the length.
    pub fn read_integer64_value(&mut self, len: usize) -> Result<u64> {
        if len == 0 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::ZeroLengthInteger }, "zero-length integer");
            return Err(self.malformed());
        }
        if len > 9 {
            // 9 bytes max: 1 leading zero + 8 bytes for u64
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Integer64TooLong { length: len } }, "integer64 too long");
            return Err(self.malformed());
        }

        let bytes = self.read_bytes(len)?;

        if len == 9 && bytes[0] != 0x00 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Integer64MissingLeadingZero }, "9-octet integer64 missing leading zero");
            return Err(self.malformed());
        }

        let mut value: u64 = 0;

        for &byte in bytes.iter() {
            value = (value << 8) | (byte as u64);
        }

        Ok(value)
    }

    /// Read an unsigned 32-bit integer with specific tag.
    pub fn read_unsigned32(&mut self, expected_tag: u8) -> Result<u32> {
        let len = self.expect_tag(expected_tag)?;
        self.read_unsigned32_value(len)
    }

    /// Read unsigned 32-bit integer value given length.
    pub fn read_unsigned32_value(&mut self, len: usize) -> Result<u32> {
        if len == 0 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::ZeroLengthInteger }, "zero-length integer");
            return Err(self.malformed());
        }
        if len > 5 {
            // 5 bytes max: 1 leading zero + 4 bytes for u32
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Unsigned32TooLong { length: len } }, "unsigned32 encoding too long");
            return Err(self.malformed());
        }

        let bytes = self.read_bytes(len)?;
        let mut value: u32 = 0;

        for &byte in bytes.iter() {
            value = (value << 8) | (byte as u32);
        }

        Ok(value)
    }

    /// Read an OCTET STRING.
    pub fn read_octet_string(&mut self) -> Result<Bytes> {
        let len = self.expect_tag(tag::universal::OCTET_STRING)?;
        self.read_bytes(len)
    }

    /// Read a NULL.
    pub fn read_null(&mut self) -> Result<()> {
        let len = self.expect_tag(tag::universal::NULL)?;
        if len != 0 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::InvalidNull }, "NULL with non-zero length");
            return Err(self.malformed());
        }
        Ok(())
    }

    /// Read an OBJECT IDENTIFIER.
    pub fn read_oid(&mut self) -> Result<Oid> {
        let len = self.expect_tag(tag::universal::OBJECT_IDENTIFIER)?;
        let bytes = self.read_bytes(len)?;
        Oid::from_ber(&bytes)
    }

    /// Read an OID given a pre-read length.
    pub fn read_oid_value(&mut self, len: usize) -> Result<Oid> {
        let bytes = self.read_bytes(len)?;
        Oid::from_ber(&bytes)
    }

    /// Read a SEQUENCE, returning a decoder for its contents.
    pub fn read_sequence(&mut self) -> Result<Decoder> {
        self.read_constructed(tag::universal::SEQUENCE)
    }

    /// Read a constructed type with a specific tag, returning a decoder for its contents.
    pub fn read_constructed(&mut self, expected_tag: u8) -> Result<Decoder> {
        let len = self.expect_tag(expected_tag)?;
        let content = self.read_bytes(len)?;
        Ok(Decoder {
            data: content,
            offset: 0,
            target: self.target,
        })
    }

    /// Read an IP address.
    pub fn read_ip_address(&mut self) -> Result<[u8; 4]> {
        let len = self.expect_tag(tag::application::IP_ADDRESS)?;
        if len != 4 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::InvalidIpAddressLength { length: len } }, "IP address must be 4 bytes");
            return Err(self.malformed());
        }
        let bytes = self.read_bytes(4)?;
        Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Skip a TLV (tag-length-value) without parsing.
    pub fn skip_tlv(&mut self) -> Result<()> {
        let _tag = self.read_tag()?;
        let len = self.read_length()?;
        // Use saturating_add and check BEFORE modifying offset to prevent overflow
        let new_offset = self.offset.saturating_add(len);
        if new_offset > self.data.len() {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::TlvOverflow }, "TLV extends past end of data");
            return Err(self.malformed());
        }
        self.offset = new_offset;
        Ok(())
    }

    /// Create a sub-decoder for a portion of the remaining data.
    pub fn sub_decoder(&mut self, len: usize) -> Result<Decoder> {
        let content = self.read_bytes(len)?;
        Ok(Decoder {
            data: content,
            offset: 0,
            target: self.target,
        })
    }

    /// Get the underlying bytes for the entire buffer.
    pub fn as_bytes(&self) -> &Bytes {
        &self.data
    }

    /// Get remaining data as a slice.
    pub fn remaining_slice(&self) -> &[u8] {
        &self.data[self.offset..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_integer() {
        let mut dec = Decoder::from_slice(&[0x02, 0x01, 0x00]);
        assert_eq!(dec.read_integer().unwrap(), 0);

        let mut dec = Decoder::from_slice(&[0x02, 0x01, 0x7F]);
        assert_eq!(dec.read_integer().unwrap(), 127);

        let mut dec = Decoder::from_slice(&[0x02, 0x02, 0x00, 0x80]);
        assert_eq!(dec.read_integer().unwrap(), 128);

        let mut dec = Decoder::from_slice(&[0x02, 0x01, 0xFF]);
        assert_eq!(dec.read_integer().unwrap(), -1);

        let mut dec = Decoder::from_slice(&[0x02, 0x01, 0x80]);
        assert_eq!(dec.read_integer().unwrap(), -128);
    }

    #[test]
    fn test_decode_null() {
        let mut dec = Decoder::from_slice(&[0x05, 0x00]);
        dec.read_null().unwrap();
    }

    #[test]
    fn test_decode_octet_string() {
        let mut dec = Decoder::from_slice(&[0x04, 0x05, b'h', b'e', b'l', b'l', b'o']);
        let s = dec.read_octet_string().unwrap();
        assert_eq!(&s[..], b"hello");
    }

    #[test]
    fn test_decode_oid() {
        // 1.3.6.1 = [0x2B, 0x06, 0x01]
        let mut dec = Decoder::from_slice(&[0x06, 0x03, 0x2B, 0x06, 0x01]);
        let oid = dec.read_oid().unwrap();
        assert_eq!(oid.arcs(), &[1, 3, 6, 1]);
    }

    #[test]
    fn test_decode_sequence() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let mut dec = Decoder::from_slice(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        let mut seq = dec.read_sequence().unwrap();
        assert_eq!(seq.read_integer().unwrap(), 1);
        assert_eq!(seq.read_integer().unwrap(), 2);
    }

    #[test]
    fn test_accept_non_minimal_integer() {
        // Non-minimal encodings are accepted per X.690 permissive parsing (matches net-snmp)
        let mut dec = Decoder::from_slice(&[0x02, 0x02, 0x00, 0x01]);
        assert_eq!(dec.read_integer().unwrap(), 1);

        // 02 02 00 7F should decode as 127 (non-minimal: could be 02 01 7F)
        let mut dec = Decoder::from_slice(&[0x02, 0x02, 0x00, 0x7F]);
        assert_eq!(dec.read_integer().unwrap(), 127);

        // 02 03 00 00 80 should decode as 128 (non-minimal: could be 02 02 00 80)
        let mut dec = Decoder::from_slice(&[0x02, 0x03, 0x00, 0x00, 0x80]);
        assert_eq!(dec.read_integer().unwrap(), 128);

        // 02 02 FF FF should decode as -1 (non-minimal: could be 02 01 FF)
        let mut dec = Decoder::from_slice(&[0x02, 0x02, 0xFF, 0xFF]);
        assert_eq!(dec.read_integer().unwrap(), -1);
    }

    #[test]
    fn test_integer_too_long_is_rejected() {
        // 5-byte integer must be rejected (BER: signed i32 max 4 bytes)
        let mut dec = Decoder::from_slice(&[0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let result = dec.read_integer();
        assert!(result.is_err(), "expected error for 5-byte integer");

        // 6-byte integer also rejected
        let mut dec = Decoder::from_slice(&[0x02, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let result = dec.read_integer();
        assert!(result.is_err(), "expected error for 6-byte integer");
    }

    #[test]
    fn test_unsigned32_too_long_is_rejected() {
        // 6-byte unsigned32 must be rejected (max 5: 1 leading zero + 4 value bytes)
        let mut dec = Decoder::from_slice(&[0x42, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let result = dec.read_unsigned32(0x42);
        assert!(result.is_err(), "expected error for 6-byte unsigned32");

        // 7-byte unsigned32 also rejected
        let mut dec = Decoder::from_slice(&[0x42, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let result = dec.read_unsigned32(0x42);
        assert!(result.is_err(), "expected error for 7-byte unsigned32");
    }

    #[test]
    fn test_counter64_nine_bytes_requires_leading_zero() {
        // 9-byte Counter64 with a non-zero first byte must be rejected (BER requires 0x00)
        // Tag 0x46 = Counter64
        let mut dec = Decoder::from_slice(&[
            0x46, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ]);
        let result = dec.read_integer64(0x46);
        assert!(
            result.is_err(),
            "expected error for 9-byte Counter64 without leading zero"
        );

        // 9-byte Counter64 with 0x00 first byte must be accepted
        let mut dec = Decoder::from_slice(&[
            0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        let result = dec.read_integer64(0x46);
        assert!(
            result.is_ok(),
            "expected success for 9-byte Counter64 with leading zero"
        );
        assert_eq!(result.unwrap(), u64::MAX);
    }

    #[test]
    fn test_read_bytes_rejects_oversized_length() {
        // When length exceeds remaining data, should return MalformedResponse error
        let mut dec = Decoder::from_slice(&[0x01, 0x02, 0x03]);
        // Try to read more bytes than available
        let result = dec.read_bytes(100);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(*err, crate::error::Error::MalformedResponse { .. }),
            "expected MalformedResponse error, got {:?}",
            err
        );
    }

    #[test]
    fn test_skip_tlv_rejects_oversized_length() {
        // TLV with length claiming more bytes than available
        // Tag 0x04 (OCTET STRING), Length 0x82 0x01 0x00 (256 bytes), but only 3 content bytes
        let mut dec = Decoder::from_slice(&[0x04, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC]);
        let result = dec.skip_tlv();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(*err, crate::error::Error::MalformedResponse { .. }),
            "expected MalformedResponse error, got {:?}",
            err
        );
    }

    #[test]
    fn test_read_tag_rejects_multi_byte_tag() {
        // A tag byte with all 5 lower bits set (0x1F) signals a multi-byte tag in BER.
        // Valid SNMP uses single-byte tags only, so this must be rejected.
        let mut dec = Decoder::from_slice(&[0x1F, 0x02, 0x00]);
        let result = dec.read_tag();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(*err, crate::error::Error::MalformedResponse { .. }),
            "expected MalformedResponse error for multi-byte tag, got {:?}",
            err
        );

        // 0x3F: constructed form with tag bits all set - also multi-byte
        let mut dec = Decoder::from_slice(&[0x3F, 0x02, 0x00]);
        let result = dec.read_tag();
        assert!(result.is_err());

        // 0x9F: context-specific, primitive, multi-byte
        let mut dec = Decoder::from_slice(&[0x9F, 0x02, 0x00]);
        let result = dec.read_tag();
        assert!(result.is_err());

        // Normal single-byte tags must still be accepted
        let mut dec = Decoder::from_slice(&[0x02, 0x01, 0x00]);
        let result = dec.read_tag();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x02);
    }

    #[test]
    fn test_peek_tag_rejects_multi_byte_tag() {
        // peek_tag must also reject multi-byte tags
        let dec = Decoder::from_slice(&[0x1F, 0x02, 0x00]);
        let result = dec.peek_tag();
        assert!(
            result.is_none(),
            "peek_tag should return None for multi-byte tag"
        );

        // Normal tag should peek as Some
        let dec = Decoder::from_slice(&[0x30, 0x00]);
        let result = dec.peek_tag();
        assert_eq!(result, Some(0x30));
    }
}
