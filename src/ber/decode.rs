//! BER decoding.
//!
//! Zero-copy decoding using `Bytes` to avoid allocations.

use super::length::decode_length;
use super::tag;
use crate::error::{DecodeErrorKind, Error, Result};
use crate::oid::Oid;
use bytes::Bytes;

/// BER decoder that reads from a byte buffer.
pub struct Decoder {
    data: Bytes,
    offset: usize,
}

impl Decoder {
    /// Create a new decoder from bytes.
    pub fn new(data: Bytes) -> Self {
        Self { data, offset: 0 }
    }

    /// Create a decoder from a byte slice (copies the data).
    pub fn from_slice(data: &[u8]) -> Self {
        Self::new(Bytes::copy_from_slice(data))
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
    pub fn peek_tag(&self) -> Option<u8> {
        self.peek_byte()
    }

    /// Read a single byte.
    pub fn read_byte(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            return Err(Error::decode(self.offset, DecodeErrorKind::TruncatedData));
        }
        let byte = self.data[self.offset];
        self.offset += 1;
        Ok(byte)
    }

    /// Read a tag byte.
    pub fn read_tag(&mut self) -> Result<u8> {
        self.read_byte()
    }

    /// Read a length and return (length, bytes consumed).
    pub fn read_length(&mut self) -> Result<usize> {
        let (len, consumed) = decode_length(&self.data[self.offset..], self.offset)?;
        self.offset += consumed;
        Ok(len)
    }

    /// Read raw bytes without copying.
    pub fn read_bytes(&mut self, len: usize) -> Result<Bytes> {
        if self.offset + len > self.data.len() {
            return Err(Error::decode(
                self.offset,
                DecodeErrorKind::InsufficientData {
                    needed: len,
                    available: self.remaining(),
                },
            ));
        }
        let bytes = self.data.slice(self.offset..self.offset + len);
        self.offset += len;
        Ok(bytes)
    }

    /// Read and expect a specific tag, returning the content length.
    pub fn expect_tag(&mut self, expected: u8) -> Result<usize> {
        let tag = self.read_tag()?;
        if tag != expected {
            return Err(Error::decode(
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

    /// Read integer value given the length.
    pub fn read_integer_value(&mut self, len: usize) -> Result<i32> {
        if len == 0 {
            return Err(Error::decode(
                self.offset,
                DecodeErrorKind::ZeroLengthInteger,
            ));
        }
        if len > 4 {
            // Permissive: truncate with warning (matches net-snmp)
            tracing::warn!(
                ber.offset = self.offset,
                ber.length = len,
                "integer too long, truncating to 4 bytes"
            );
        }

        let bytes = self.read_bytes(len)?;

        // Sign extend
        let is_negative = bytes[0] & 0x80 != 0;
        let mut value: i32 = if is_negative { -1 } else { 0 };

        for &byte in bytes.iter().take(4) {
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
            return Err(Error::decode(
                self.offset,
                DecodeErrorKind::ZeroLengthInteger,
            ));
        }
        if len > 9 {
            // 9 bytes max: 1 leading zero + 8 bytes for u64
            return Err(Error::decode(
                self.offset,
                DecodeErrorKind::Integer64TooLong { length: len },
            ));
        }

        let bytes = self.read_bytes(len)?;
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
            return Err(Error::decode(
                self.offset,
                DecodeErrorKind::ZeroLengthInteger,
            ));
        }
        if len > 5 {
            // 5 bytes max: 1 leading zero + 4 bytes for u32
            tracing::warn!(
                ber.offset = self.offset,
                ber.length = len,
                "unsigned integer too long, truncating to 4 bytes"
            );
        }

        let bytes = self.read_bytes(len)?;
        let mut value: u32 = 0;

        for &byte in bytes.iter().take(5) {
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
            return Err(Error::decode(self.offset, DecodeErrorKind::InvalidNull));
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
        let len = self.expect_tag(tag::universal::SEQUENCE)?;
        let content = self.read_bytes(len)?;
        Ok(Decoder::new(content))
    }

    /// Read a constructed type with a specific tag, returning a decoder for its contents.
    pub fn read_constructed(&mut self, expected_tag: u8) -> Result<Decoder> {
        let len = self.expect_tag(expected_tag)?;
        let content = self.read_bytes(len)?;
        Ok(Decoder::new(content))
    }

    /// Read an IP address.
    pub fn read_ip_address(&mut self) -> Result<[u8; 4]> {
        let len = self.expect_tag(tag::application::IP_ADDRESS)?;
        if len != 4 {
            return Err(Error::decode(
                self.offset,
                DecodeErrorKind::InvalidIpAddressLength { length: len },
            ));
        }
        let bytes = self.read_bytes(4)?;
        Ok([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// Skip a TLV (tag-length-value) without parsing.
    pub fn skip_tlv(&mut self) -> Result<()> {
        let _tag = self.read_tag()?;
        let len = self.read_length()?;
        self.offset += len;
        if self.offset > self.data.len() {
            return Err(Error::decode(self.offset, DecodeErrorKind::TlvOverflow));
        }
        Ok(())
    }

    /// Create a sub-decoder for a portion of the remaining data.
    pub fn sub_decoder(&mut self, len: usize) -> Result<Decoder> {
        let content = self.read_bytes(len)?;
        Ok(Decoder::new(content))
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
    fn test_integer_overflow_truncation() {
        // 5-byte integer should truncate to 4 bytes (matches net-snmp CHECK_OVERFLOW)
        // 02 05 01 02 03 04 05 = value that exceeds i32
        let mut dec = Decoder::from_slice(&[0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        let result = dec.read_integer();
        // Should succeed with truncated value, not error
        assert!(result.is_ok());
        // The value is truncated to first 4 bytes: 0x01020304
        assert_eq!(result.unwrap(), 0x01020304);

        // 6-byte integer also truncates
        let mut dec = Decoder::from_slice(&[0x02, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let result = dec.read_integer();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x01020304);
    }
}
