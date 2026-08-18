//! BER decoding.
//!
//! Zero-copy decoding using `Bytes` to avoid allocations.

use std::cell::RefCell;
use std::net::SocketAddr;

use super::length::decode_length_with_origin;
use super::tag;
use crate::compatibility::{DecodeAnomaly, DecodeConfig};
use crate::error::internal::{DecodeErrorKind, DecodeErrorOrigin};
use crate::error::{DecodeError, Error, Result};
use crate::oid::Oid;
use bytes::Bytes;

/// BER decoder that reads from a byte buffer.
pub struct Decoder<'a> {
    data: Bytes,
    offset: usize,
    base_offset: usize,
    origin: DecodeErrorOrigin,
    peer: Option<SocketAddr>,
    config: DecodeConfig,
    anomalies: Option<&'a RefCell<Vec<DecodeAnomaly>>>,
}

impl Decoder<'static> {
    /// Create a decoder from bytes.
    pub fn new(data: Bytes) -> Self {
        Self {
            data,
            offset: 0,
            base_offset: 0,
            origin: DecodeErrorOrigin::Packet,
            peer: None,
            config: DecodeConfig::default(),
            anomalies: None,
        }
    }

    /// Create a decoder from bytes with a target address for error context.
    pub fn with_target(data: Bytes, target: SocketAddr) -> Self {
        Self::with_optional_peer(data, Some(target))
    }

    pub(crate) fn with_optional_peer(data: Bytes, peer: Option<SocketAddr>) -> Self {
        Self::with_context(data, 0, peer)
    }

    pub(crate) fn with_context(data: Bytes, base_offset: usize, peer: Option<SocketAddr>) -> Self {
        Self::with_origin_context(data, base_offset, DecodeErrorOrigin::Packet, peer)
    }

    pub(crate) fn with_origin_context(
        data: Bytes,
        base_offset: usize,
        origin: DecodeErrorOrigin,
        peer: Option<SocketAddr>,
    ) -> Self {
        Self {
            data,
            offset: 0,
            base_offset,
            origin,
            peer,
            config: DecodeConfig::default(),
            anomalies: None,
        }
    }

    /// Create a decoder from a byte slice (copies the data).
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(data))
    }
}

impl<'a> Decoder<'a> {
    pub(crate) fn with_anomaly_sink<'b>(
        self,
        anomalies: &'b RefCell<Vec<DecodeAnomaly>>,
    ) -> Decoder<'b> {
        Decoder {
            data: self.data,
            offset: self.offset,
            base_offset: self.base_offset,
            origin: self.origin,
            peer: self.peer,
            config: self.config,
            anomalies: Some(anomalies),
        }
    }

    pub(crate) fn record_anomaly(&self, anomaly: DecodeAnomaly) {
        if let Some(anomalies) = self.anomalies {
            anomalies.borrow_mut().push(anomaly);
        }
    }

    pub(crate) fn decoder_for(
        &self,
        data: Bytes,
        base_offset: usize,
        origin: DecodeErrorOrigin,
    ) -> Decoder<'a> {
        Decoder {
            data,
            offset: 0,
            base_offset,
            origin,
            peer: self.peer,
            config: self.config,
            anomalies: self.anomalies,
        }
    }

    pub(crate) fn decoder_for_same_origin(&self, data: Bytes, base_offset: usize) -> Decoder<'a> {
        self.decoder_for(data, base_offset, self.origin)
    }

    /// Apply an explicit decode configuration.
    #[must_use]
    pub fn with_decode_config(mut self, config: DecodeConfig) -> Self {
        self.config = config;
        self
    }

    /// Return the decode configuration for this decoder.
    #[must_use]
    pub fn decode_config(&self) -> DecodeConfig {
        self.config
    }

    /// Returns the peer address when decoding at a network boundary.
    #[must_use]
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// Construct a decode error at the current packet-relative offset.
    pub(crate) fn malformed(&self, kind: DecodeErrorKind) -> Box<Error> {
        self.malformed_at(self.offset, kind)
    }

    pub(crate) fn malformed_at(&self, offset: usize, kind: DecodeErrorKind) -> Box<Error> {
        let mut error =
            DecodeError::with_origin(self.origin, self.base_offset.saturating_add(offset), kind);
        error.peer = self.peer;
        Error::Decode(error).boxed()
    }

    /// Returns the current packet-relative offset.
    pub fn offset(&self) -> usize {
        self.base_offset.saturating_add(self.offset)
    }

    pub(crate) fn local_offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of remaining bytes.
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
            return Err(self.malformed(DecodeErrorKind::TruncatedData));
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
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset - 1, kind = %DecodeErrorKind::UnsupportedMultiOctetTag { first_octet: tag } }, "multi-byte tag not supported");
            return Err(self.malformed_at(
                self.offset - 1,
                DecodeErrorKind::UnsupportedMultiOctetTag { first_octet: tag },
            ));
        }
        Ok(tag)
    }

    /// Read a length and return (length, bytes consumed).
    pub fn read_length(&mut self) -> Result<usize> {
        let (len, consumed) = decode_length_with_origin(
            &self.data[self.offset..],
            self.base_offset.saturating_add(self.offset),
            self.origin,
            self.peer,
        )?;
        self.offset += consumed;
        Ok(len)
    }

    /// Read raw bytes without copying.
    pub fn read_bytes(&mut self, len: usize) -> Result<Bytes> {
        // Use saturating_add to prevent overflow from bypassing bounds check
        if self.offset.saturating_add(len) > self.data.len() {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::InsufficientData { needed: len, available: self.remaining() } }, "insufficient data");
            return Err(self.malformed(DecodeErrorKind::InsufficientData {
                needed: len,
                available: self.remaining(),
            }));
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
            return Err(self.malformed_at(
                self.offset - 1,
                DecodeErrorKind::UnexpectedTag {
                    expected,
                    actual: tag,
                },
            ));
        }
        self.read_length()
    }

    /// Read a BER integer (signed).
    pub fn read_integer(&mut self) -> Result<i32> {
        let len = self.expect_tag(tag::universal::INTEGER)?;
        self.read_integer_value(len)
    }

    /// Read a BER integer whose ASN.1 type constrains it to an `i32` range.
    ///
    /// Unlike [`Self::read_integer`], this checks the complete decoded value
    /// before narrowing it. This prevents over-width encodings such as
    /// `2^32` from aliasing an in-range value after truncation.
    pub(crate) fn read_bounded_integer(&mut self, minimum: i32, maximum: i32) -> Result<i32> {
        debug_assert!(minimum <= maximum);

        let len = self.expect_tag(tag::universal::INTEGER)?;
        let value = self.read_signed_integer_value(len)?;
        if value < i64::from(minimum) || value > i64::from(maximum) {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::IntegerOutOfRange { value, minimum, maximum } }, "integer outside constrained range");
            return Err(self.malformed(DecodeErrorKind::IntegerOutOfRange {
                value,
                minimum,
                maximum,
            }));
        }

        Ok(value as i32)
    }

    /// Read integer value given the length.
    pub fn read_integer_value(&mut self, len: usize) -> Result<i32> {
        // ASN.1 protocol fields with narrower ranges must use
        // `read_bounded_integer`, which never consults compatibility policy.
        let value = self.read_signed_integer_value(len)?;
        if value < i64::from(i32::MIN) || value > i64::from(i32::MAX) {
            if !self.config.truncate_numeric_values {
                return Err(self.malformed(DecodeErrorKind::IntegerOutOfRange {
                    value,
                    minimum: i32::MIN,
                    maximum: i32::MAX,
                }));
            }
            tracing::warn!(target: "async_snmp::ber", anomaly = "numeric_truncation", numeric_type = "integer", encoded_length = len, value, normalized = value as i32, "accepted out-of-range generic INTEGER");
            self.record_anomaly(DecodeAnomaly::SignedIntegerTruncation {
                encoded_length: len,
                original: value,
                canonical: value as i32,
            });
        }
        Ok(value as i32)
    }

    /// Read the complete signed value of an INTEGER accepted by the generic
    /// BER parser, without narrowing it to the public `i32` representation.
    fn read_signed_integer_value(&mut self, len: usize) -> Result<i64> {
        if len == 0 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::ZeroLengthInteger }, "zero-length integer");
            return Err(self.malformed(DecodeErrorKind::ZeroLengthInteger));
        }
        if len > 8 {
            // Net-snmp accepts up to sizeof(long)=8 bytes for INTEGER; longer is truly malformed.
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::IntegerTooLong { length: len } }, "integer encoding too long");
            return Err(self.malformed(DecodeErrorKind::IntegerTooLong { length: len }));
        }

        let bytes = self.read_bytes(len)?;

        // Sign-extend into i64. The generic caller truncates this to i32 to
        // match net-snmp's CHECK_OVERFLOW_S compatibility behavior.
        let is_negative = bytes[0] & 0x80 != 0;
        let mut value: i64 = if is_negative { -1 } else { 0 };

        for &byte in &bytes {
            value = (value << 8) | i64::from(byte);
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
            if !self.config.empty_counter64_as_zero {
                return Err(self.malformed(DecodeErrorKind::ZeroLengthInteger));
            }
            tracing::warn!(target: "async_snmp::ber", anomaly = "empty_counter64", snmp.offset = self.offset, normalized = 0_u64, "accepted zero-length Counter64");
            self.record_anomaly(DecodeAnomaly::EmptyCounter64 {
                original_length: 0,
                canonical: 0,
            });
            return Ok(0);
        }
        if len > 9 {
            // 9 bytes max: 1 leading zero + 8 bytes for u64
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Integer64TooLong { length: len } }, "integer64 too long");
            return Err(self.malformed(DecodeErrorKind::Integer64TooLong { length: len }));
        }

        let bytes = self.read_bytes(len)?;

        if len == 9 && bytes[0] != 0x00 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Integer64MissingLeadingZero }, "9-octet integer64 missing leading zero");
            return Err(self.malformed(DecodeErrorKind::Integer64MissingLeadingZero));
        }

        let mut value: u64 = 0;

        for &byte in &bytes {
            value = (value << 8) | u64::from(byte);
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
        let value = self.read_unsigned_integer_value(len)?;
        if value > u64::from(u32::MAX) {
            if !self.config.truncate_numeric_values {
                return Err(self.malformed(DecodeErrorKind::UnsignedIntegerOutOfRange {
                    value,
                    minimum: 0,
                    maximum: u32::MAX,
                }));
            }
            tracing::warn!(target: "async_snmp::ber", anomaly = "numeric_truncation", numeric_type = "unsigned32", encoded_length = len, value, normalized = value as u32, "accepted out-of-range generic Unsigned32");
            self.record_anomaly(DecodeAnomaly::Unsigned32Truncation {
                encoded_length: len,
                original: value,
                canonical: value as u32,
            });
        }

        Ok(value as u32)
    }

    /// Read a protocol Unsigned32 value without applying generic-value
    /// truncation compatibility.
    pub(crate) fn read_bounded_unsigned32_value(&mut self, len: usize) -> Result<u32> {
        let value = self.read_unsigned_integer_value(len)?;
        if value > u64::from(u32::MAX) {
            return Err(self.malformed(DecodeErrorKind::UnsignedIntegerOutOfRange {
                value,
                minimum: 0,
                maximum: u32::MAX,
            }));
        }
        Ok(value as u32)
    }

    fn read_unsigned_integer_value(&mut self, len: usize) -> Result<u64> {
        if len == 0 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::ZeroLengthInteger }, "zero-length integer");
            return Err(self.malformed(DecodeErrorKind::ZeroLengthInteger));
        }
        if len > 9 {
            // Net-snmp accepts up to sizeof(long)+1=9 bytes for unsigned32; longer is truly malformed.
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Unsigned32TooLong { length: len } }, "unsigned32 encoding too long");
            return Err(self.malformed(DecodeErrorKind::Unsigned32TooLong { length: len }));
        }

        let bytes = self.read_bytes(len)?;

        if len == 9 && bytes[0] != 0x00 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::Unsigned32MissingLeadingZero }, "9-octet unsigned32 missing leading zero");
            return Err(self.malformed(DecodeErrorKind::Unsigned32MissingLeadingZero));
        }

        let mut value: u64 = 0;
        for &byte in &bytes {
            value = (value << 8) | u64::from(byte);
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
            return Err(self.malformed(DecodeErrorKind::InvalidNull));
        }
        Ok(())
    }

    /// Read an OBJECT IDENTIFIER.
    pub fn read_oid(&mut self) -> Result<Oid> {
        let len = self.expect_tag(tag::universal::OBJECT_IDENTIFIER)?;
        self.read_oid_value(len)
    }

    /// Read an OID given a pre-read length.
    pub fn read_oid_value(&mut self, len: usize) -> Result<Oid> {
        if len == 0 {
            if !self.config.empty_object_identifier {
                return Err(self.malformed(DecodeErrorKind::InvalidOid));
            }
            tracing::warn!(target: "async_snmp::ber", anomaly = "empty_object_identifier", snmp.offset = self.offset, encoded_length = 0, "accepted zero-length OBJECT IDENTIFIER");
            self.record_anomaly(DecodeAnomaly::EmptyObjectIdentifier {
                original_length: 0,
                canonical_arc_count: 0,
            });
        }
        let bytes = self.read_bytes(len)?;
        Oid::from_ber(&bytes).map_err(|error| match *error {
            Error::Decode(mut error) => {
                error.offset = self
                    .base_offset
                    .saturating_add(self.offset.saturating_sub(len))
                    .saturating_add(error.offset);
                error.origin = self.origin;
                error.peer = self.peer;
                Error::Decode(error).boxed()
            }
            other => Box::new(other),
        })
    }

    /// Read a SEQUENCE, returning a decoder for its contents.
    pub fn read_sequence(&mut self) -> Result<Decoder<'a>> {
        self.read_constructed(tag::universal::SEQUENCE)
    }

    /// Read a constructed type with a specific tag, returning a decoder for its contents.
    pub fn read_constructed(&mut self, expected_tag: u8) -> Result<Decoder<'a>> {
        let len = self.expect_tag(expected_tag)?;
        let content_offset = self.base_offset.saturating_add(self.offset);
        let content = self.read_bytes(len)?;
        Ok(Decoder {
            data: content,
            offset: 0,
            base_offset: content_offset,
            origin: self.origin,
            peer: self.peer,
            config: self.config,
            anomalies: self.anomalies,
        })
    }

    /// Read an IP address.
    pub fn read_ip_address(&mut self) -> Result<[u8; 4]> {
        let len = self.expect_tag(tag::application::IP_ADDRESS)?;
        if len != 4 {
            tracing::debug!(target: "async_snmp::ber", { snmp.offset = %self.offset, kind = %DecodeErrorKind::InvalidIpAddressLength { length: len } }, "IP address must be 4 bytes");
            return Err(self.malformed(DecodeErrorKind::InvalidIpAddressLength { length: len }));
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
            return Err(self.malformed(DecodeErrorKind::TlvOverflow));
        }
        self.offset = new_offset;
        Ok(())
    }

    /// Create a sub-decoder for a portion of the remaining data.
    pub fn sub_decoder(&mut self, len: usize) -> Result<Decoder<'a>> {
        let content_offset = self.base_offset.saturating_add(self.offset);
        let content = self.read_bytes(len)?;
        Ok(Decoder {
            data: content,
            offset: 0,
            base_offset: content_offset,
            origin: self.origin,
            peer: self.peer,
            config: self.config,
            anomalies: self.anomalies,
        })
    }

    /// Returns the underlying bytes for the entire buffer.
    pub fn as_bytes(&self) -> &Bytes {
        &self.data
    }

    /// Returns the remaining data as a slice.
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
    fn malformed_oid_errors_retain_decoder_target() {
        let peer = "192.0.2.44:161".parse().unwrap();

        let mut tagged = Decoder::with_target(Bytes::from_static(&[0x06, 0x01, 0x80]), peer);
        let error = tagged.read_oid().unwrap_err();
        assert!(matches!(&*error, Error::Decode(error) if error.peer == Some(peer)));

        let mut value = Decoder::with_target(Bytes::from_static(&[0x80]), peer);
        let error = value.read_oid_value(1).unwrap_err();
        assert!(matches!(&*error, Error::Decode(error) if error.peer == Some(peer)));
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
    fn test_integer_too_long_truncates() {
        // 5-8 byte integers are accepted and truncated to i32, matching net-snmp CHECK_OVERFLOW_S.
        // 5 bytes: 0x0102030405 -> truncated to 0x02030405
        let mut dec = Decoder::from_slice(&[0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(dec.read_integer().unwrap(), 0x02_03_04_05_i32);

        // 8 bytes: last 4 bytes kept
        let mut dec =
            Decoder::from_slice(&[0x02, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(dec.read_integer().unwrap(), 0x05_06_07_08_i32);

        // 9 bytes is rejected (exceeds net-snmp's sizeof(long)=8 limit)
        let mut dec = Decoder::from_slice(&[
            0x02, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ]);
        assert!(
            dec.read_integer().is_err(),
            "9-byte integer must be rejected"
        );
    }

    #[test]
    fn bounded_integer_rejects_values_that_generic_decode_truncates() {
        const TWO_TO_32: &[u8] = &[0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
        const NEGATIVE_TWO_TO_32: &[u8] = &[0x02, 0x05, 0xFF, 0x00, 0x00, 0x00, 0x00];

        let mut generic = Decoder::from_slice(TWO_TO_32);
        assert_eq!(generic.read_integer().unwrap(), 0);
        let mut bounded = Decoder::from_slice(TWO_TO_32);
        assert!(bounded.read_bounded_integer(0, i32::MAX).is_err());

        let mut generic = Decoder::from_slice(NEGATIVE_TWO_TO_32);
        assert_eq!(generic.read_integer().unwrap(), 0);
        let mut bounded = Decoder::from_slice(NEGATIVE_TWO_TO_32);
        assert!(bounded.read_bounded_integer(0, i32::MAX).is_err());

        let mut lower_bound = Decoder::from_slice(&[0x02, 0x01, 0x00]);
        assert_eq!(lower_bound.read_bounded_integer(0, i32::MAX).unwrap(), 0);
        let mut upper_bound = Decoder::from_slice(&[0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF]);
        assert_eq!(
            upper_bound.read_bounded_integer(0, i32::MAX).unwrap(),
            i32::MAX
        );

        let mut generic_unsigned = Decoder::from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(generic_unsigned.read_unsigned32_value(5).unwrap(), 0);
        let mut bounded_unsigned = Decoder::from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00]);
        assert!(bounded_unsigned.read_bounded_unsigned32_value(5).is_err());
    }

    #[test]
    fn test_unsigned32_too_long_truncates() {
        // 6-9 byte unsigned32 values are accepted and truncated to u32, matching net-snmp CHECK_OVERFLOW_U.
        // 6 bytes: 0x010203040506 -> truncated to 0x03040506
        let mut dec = Decoder::from_slice(&[0x42, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(dec.read_unsigned32(0x42).unwrap(), 0x03_04_05_06_u32);

        // 9 bytes with leading zero: accepted, value fits in u32
        let mut dec = Decoder::from_slice(&[
            0x42, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        assert_eq!(dec.read_unsigned32(0x42).unwrap(), u32::MAX);

        // 10 bytes is rejected (exceeds net-snmp's sizeof(long)+1=9 limit)
        let mut dec = Decoder::from_slice(&[
            0x42, 0x0A, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ]);
        assert!(
            dec.read_unsigned32(0x42).is_err(),
            "10-byte unsigned32 must be rejected"
        );
    }

    #[test]
    fn compatibility_policy_controls_zero_length_counter64() {
        let mut compatible = Decoder::from_slice(&[0x46, 0x00]);
        assert_eq!(compatible.read_integer64(0x46).unwrap(), 0);

        let config = DecodeConfig {
            empty_counter64_as_zero: false,
            ..DecodeConfig::DEFAULT
        };
        let mut strict = Decoder::from_slice(&[0x46, 0x00]).with_decode_config(config);
        assert!(strict.read_integer64(0x46).is_err());
    }

    #[test]
    fn compatibility_policy_controls_numeric_truncation() {
        let signed = [0x02, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
        let unsigned = [0x42, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00];

        let mut compatible_signed = Decoder::from_slice(&signed);
        assert_eq!(compatible_signed.read_integer().unwrap(), 0);
        let config = DecodeConfig {
            truncate_numeric_values: false,
            ..DecodeConfig::DEFAULT
        };
        let mut strict_signed = Decoder::from_slice(&signed).with_decode_config(config);
        assert!(strict_signed.read_integer().is_err());

        let mut compatible_unsigned = Decoder::from_slice(&unsigned);
        assert_eq!(compatible_unsigned.read_unsigned32(0x42).unwrap(), 0);
        let mut strict_unsigned = Decoder::from_slice(&unsigned).with_decode_config(config);
        assert!(strict_unsigned.read_unsigned32(0x42).is_err());
    }

    #[test]
    fn unsigned32_range_error_preserves_u64_max_and_u32_bounds() {
        let encoded = [0x42, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let config = DecodeConfig {
            truncate_numeric_values: false,
            ..DecodeConfig::DEFAULT
        };
        let mut decoder = Decoder::from_slice(&encoded).with_decode_config(config);
        let error = decoder.read_unsigned32(0x42).unwrap_err();
        assert!(matches!(
            error.as_ref(),
            Error::Decode(DecodeError {
                kind: DecodeErrorKind::UnsignedIntegerOutOfRange {
                    value: u64::MAX,
                    minimum: 0,
                    maximum: u32::MAX,
                },
                ..
            })
        ));

        let mut bounded = Decoder::from_slice(&encoded[2..]);
        let error = bounded.read_bounded_unsigned32_value(8).unwrap_err();
        assert!(matches!(
            error.as_ref(),
            Error::Decode(DecodeError {
                kind: DecodeErrorKind::UnsignedIntegerOutOfRange {
                    value: u64::MAX,
                    minimum: 0,
                    maximum: u32::MAX,
                },
                ..
            })
        ));
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
    fn test_unsigned32_nine_bytes_requires_leading_zero() {
        // 9-byte unsigned32 without a leading zero is rejected (matches net-snmp).
        let mut dec = Decoder::from_slice(&[
            0x42, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        ]);
        assert!(
            dec.read_unsigned32(0x42).is_err(),
            "9-byte unsigned32 without leading zero must be rejected"
        );

        // 9-byte unsigned32 with 0x00 first byte is accepted and truncated to u32.
        let mut dec = Decoder::from_slice(&[
            0x42, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        assert_eq!(dec.read_unsigned32(0x42).unwrap(), u32::MAX);

        // 5-byte unsigned32 with a non-zero first byte is accepted and truncated (matches net-snmp).
        let mut dec = Decoder::from_slice(&[0x42, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(dec.read_unsigned32(0x42).unwrap(), 0u32);
    }

    #[test]
    fn test_read_bytes_rejects_oversized_length() {
        // When length exceeds remaining data, return a structured decode error.
        let mut dec = Decoder::from_slice(&[0x01, 0x02, 0x03]);
        // Try to read more bytes than available
        let result = dec.read_bytes(100);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(*err, crate::error::Error::Decode(_)),
            "expected Decode error, got {err:?}"
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
            matches!(*err, crate::error::Error::Decode(_)),
            "expected Decode error, got {err:?}"
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
        assert!(matches!(
            err.as_ref(),
            Error::Decode(DecodeError {
                offset: 0,
                kind: DecodeErrorKind::UnsupportedMultiOctetTag { first_octet: 0x1f },
                ..
            })
        ));

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
