//! BER encoding.
//!
//! Uses a reverse buffer approach: writes from end backwards to avoid
//! needing to pre-calculate lengths.

use super::length::encode_length;
use super::tag;
use bytes::Bytes;

/// Buffer for BER encoding that writes backwards.
///
/// This approach avoids needing to pre-calculate content lengths:
/// we write the content first, then prepend the length and tag.
pub struct EncodeBuf {
    buf: Vec<u8>,
}

impl EncodeBuf {
    /// Create a new encode buffer with default capacity.
    pub fn new() -> Self {
        Self::with_capacity(512)
    }

    /// Create a new encode buffer with specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Push a single byte (prepends to front).
    pub fn push_byte(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    /// Push multiple bytes (prepends to front, reversed).
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().rev());
    }

    /// Push bytes without reversing (for content that's already in correct order).
    pub fn push_bytes_raw(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().rev());
    }

    /// Push a BER length encoding.
    pub fn push_length(&mut self, len: usize) {
        let (bytes, count) = encode_length(len);
        // The encode_length returns bytes in reverse order for prepending
        for byte in bytes.iter().take(count) {
            self.buf.push(*byte);
        }
    }

    /// Push a BER tag.
    pub fn push_tag(&mut self, tag: u8) {
        self.buf.push(tag);
    }

    /// Get the current length of encoded data.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Encode a constructed type (SEQUENCE, PDU, etc).
    ///
    /// Calls the closure to encode contents, then wraps with length and tag.
    pub fn push_constructed<F>(&mut self, tag: u8, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let start_len = self.len();
        f(self);
        let content_len = self.len() - start_len;
        self.push_length(content_len);
        self.push_tag(tag);
    }

    /// Encode a SEQUENCE.
    pub fn push_sequence<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        self.push_constructed(tag::universal::SEQUENCE, f);
    }

    /// Encode an INTEGER.
    pub fn push_integer(&mut self, value: i32) {
        let (arr, len) = encode_integer_stack(value);
        // Valid bytes are at the end of the array
        self.push_bytes(&arr[4 - len..]);
        self.push_length(len);
        self.push_tag(tag::universal::INTEGER);
    }

    /// Encode a 64-bit integer (for Counter64).
    pub fn push_integer64(&mut self, value: u64) {
        let (arr, len) = encode_integer64_stack(value);
        // Valid bytes are at the end of the array
        self.push_bytes(&arr[9 - len..]);
        self.push_length(len);
        self.push_tag(tag::application::COUNTER64);
    }

    /// Encode an unsigned 32-bit integer with a specific tag.
    pub fn push_unsigned32(&mut self, tag: u8, value: u32) {
        let (arr, len) = encode_unsigned32_stack(value);
        // Valid bytes are at the end of the array
        self.push_bytes(&arr[5 - len..]);
        self.push_length(len);
        self.push_tag(tag);
    }

    /// Encode an OCTET STRING.
    pub fn push_octet_string(&mut self, data: &[u8]) {
        self.push_bytes(data);
        self.push_length(data.len());
        self.push_tag(tag::universal::OCTET_STRING);
    }

    /// Encode a NULL.
    pub fn push_null(&mut self) {
        self.push_length(0);
        self.push_tag(tag::universal::NULL);
    }

    /// Encode an OBJECT IDENTIFIER.
    pub fn push_oid(&mut self, oid: &crate::oid::Oid) {
        let ber = oid.to_ber_smallvec();
        self.push_bytes(&ber);
        self.push_length(ber.len());
        self.push_tag(tag::universal::OBJECT_IDENTIFIER);
    }

    /// Encode an IP address.
    pub fn push_ip_address(&mut self, addr: [u8; 4]) {
        self.push_bytes(&addr);
        self.push_length(4);
        self.push_tag(tag::application::IP_ADDRESS);
    }

    /// Finalize and return the encoded bytes.
    ///
    /// The buffer is reversed to produce the correct order.
    pub fn finish(mut self) -> Bytes {
        self.buf.reverse();
        Bytes::from(self.buf)
    }

    /// Finalize and return as `Vec<u8>`.
    pub fn finish_vec(mut self) -> Vec<u8> {
        self.buf.reverse();
        self.buf
    }
}

impl Default for EncodeBuf {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a signed 32-bit integer in minimal BER form.
///
/// Returns a stack-allocated array and the number of valid bytes.
/// The valid bytes are at the END of the array (for reverse-buffer compatibility).
#[inline]
fn encode_integer_stack(value: i32) -> ([u8; 4], usize) {
    let bytes = value.to_be_bytes();

    // Find first significant byte
    let mut start = 0;
    if value >= 0 {
        // For positive/zero, skip leading 0x00 bytes (but keep one if needed for sign)
        while start < 3 && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
            start += 1;
        }
    } else {
        // For negative, skip leading 0xFF bytes (but keep one if needed for sign)
        while start < 3 && bytes[start] == 0xFF && bytes[start + 1] & 0x80 != 0 {
            start += 1;
        }
    }

    (bytes, 4 - start)
}

/// Encode an unsigned 32-bit integer.
///
/// Returns a stack-allocated array and the number of valid bytes.
/// The valid bytes are at the END of the array (for reverse-buffer compatibility).
#[inline]
fn encode_unsigned32_stack(value: u32) -> ([u8; 5], usize) {
    if value == 0 {
        return ([0, 0, 0, 0, 0], 1);
    }

    let bytes = value.to_be_bytes();
    let mut start = 0;

    // Skip leading zeros, but add a 0x00 prefix if MSB is set (to avoid sign extension)
    while start < 3 && bytes[start] == 0 {
        start += 1;
    }

    if bytes[start] & 0x80 != 0 {
        // Need to add a leading 0x00 to indicate positive
        let mut result = [0u8; 5];
        result[1..].copy_from_slice(&bytes);
        (result, 5 - start)
    } else {
        let mut result = [0u8; 5];
        result[1..].copy_from_slice(&bytes);
        (result, 4 - start)
    }
}

/// Encode an unsigned 64-bit integer.
///
/// Returns a stack-allocated array and the number of valid bytes.
/// The valid bytes are at the END of the array (for reverse-buffer compatibility).
#[inline]
fn encode_integer64_stack(value: u64) -> ([u8; 9], usize) {
    if value == 0 {
        return ([0; 9], 1);
    }

    let bytes = value.to_be_bytes();
    let mut start = 0;

    // Skip leading zeros, but add a 0x00 prefix if MSB is set
    while start < 7 && bytes[start] == 0 {
        start += 1;
    }

    if bytes[start] & 0x80 != 0 {
        // Need to add a leading 0x00 to indicate positive
        let mut result = [0u8; 9];
        result[1..].copy_from_slice(&bytes);
        (result, 9 - start)
    } else {
        let mut result = [0u8; 9];
        result[1..].copy_from_slice(&bytes);
        (result, 8 - start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to extract the valid bytes from stack-based integer encoding
    fn encode_integer(value: i32) -> Vec<u8> {
        let (arr, len) = encode_integer_stack(value);
        arr[4 - len..].to_vec()
    }

    /// Helper to extract the valid bytes from stack-based unsigned32 encoding
    fn encode_unsigned32(value: u32) -> Vec<u8> {
        let (arr, len) = encode_unsigned32_stack(value);
        arr[5 - len..].to_vec()
    }

    #[test]
    fn test_encode_integer() {
        assert_eq!(encode_integer(0), vec![0]);
        assert_eq!(encode_integer(1), vec![1]);
        assert_eq!(encode_integer(127), vec![127]);
        assert_eq!(encode_integer(128), vec![0, 128]);
        assert_eq!(encode_integer(-1), vec![0xFF]);
        assert_eq!(encode_integer(-128), vec![0x80]);
        assert_eq!(encode_integer(-129), vec![0xFF, 0x7F]);
    }

    #[test]
    fn test_encode_unsigned32() {
        assert_eq!(encode_unsigned32(0), vec![0]);
        assert_eq!(encode_unsigned32(127), vec![127]);
        assert_eq!(encode_unsigned32(128), vec![0, 128]);
        assert_eq!(encode_unsigned32(255), vec![0, 255]);
        assert_eq!(encode_unsigned32(256), vec![1, 0]);
    }

    #[test]
    fn test_encode_null() {
        let mut buf = EncodeBuf::new();
        buf.push_null();
        let bytes = buf.finish();
        assert_eq!(&bytes[..], &[0x05, 0x00]);
    }

    #[test]
    fn test_encode_integer_value() {
        let mut buf = EncodeBuf::new();
        buf.push_integer(42);
        let bytes = buf.finish();
        assert_eq!(&bytes[..], &[0x02, 0x01, 0x2A]);
    }

    #[test]
    fn test_encode_sequence() {
        let mut buf = EncodeBuf::new();
        buf.push_sequence(|buf| {
            // Reverse buffer: push in reverse order for forward output
            buf.push_integer(2);
            buf.push_integer(1);
        });
        let bytes = buf.finish();
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        assert_eq!(
            &bytes[..],
            &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]
        );
    }
}
