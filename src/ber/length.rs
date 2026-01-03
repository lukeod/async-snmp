//! BER length encoding and decoding.
//!
//! Length encoding follows X.690 Section 8.1.3:
//! - Short form: Single byte, bit 8=0, value 0-127
//! - Long form: Initial byte (bit 8=1, bits 7-1=count), followed by length bytes
//! - Indefinite form (0x80): Rejected per net-snmp behavior

use std::net::SocketAddr;

use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};

/// Maximum length we'll accept (to prevent DoS).
///
/// 2MB is far larger than any realistic SNMP message (typical messages are
/// hundreds of bytes to a few KB). This provides a sanity check at the BER
/// decode layer while still being generous enough for any legitimate use case.
pub const MAX_LENGTH: usize = 0x200000; // 2MB

/// Returns the number of bytes needed to encode a length value in BER.
///
/// Uses short form (1 byte) for lengths <= 127, long form otherwise.
#[inline]
pub(crate) const fn length_encoded_len(len: usize) -> usize {
    if len <= 127 {
        1
    } else if len <= 0xFF {
        2
    } else if len <= 0xFFFF {
        3
    } else if len <= 0xFFFFFF {
        4
    } else {
        5
    }
}

/// Returns the number of bytes needed for base-128 variable-length encoding.
///
/// Used for OID subidentifier encoding (X.690 Section 8.19.2).
#[inline]
pub(crate) const fn base128_len(value: u32) -> usize {
    if value == 0 {
        return 1;
    }
    // Count 7-bit groups needed: ceil(log2(value+1) / 7)
    // For u32, this is at most 5 bytes
    if value < 0x80 {
        1
    } else if value < 0x4000 {
        2
    } else if value < 0x200000 {
        3
    } else if value < 0x10000000 {
        4
    } else {
        5
    }
}

/// Returns the number of content bytes needed to encode a signed i32 in BER.
#[inline]
pub(crate) const fn integer_content_len(value: i32) -> usize {
    let bytes = value.to_be_bytes();

    if value >= 0 {
        // For positive/zero, skip leading 0x00 bytes (but keep one if next byte has MSB set)
        if bytes[0] != 0 {
            4
        } else if bytes[1] != 0 || bytes[2] & 0x80 != 0 {
            if bytes[1] & 0x80 != 0 { 4 } else { 3 }
        } else if bytes[2] != 0 || bytes[3] & 0x80 != 0 {
            if bytes[2] & 0x80 != 0 { 3 } else { 2 }
        } else {
            1
        }
    } else {
        // For negative, skip leading 0xFF bytes (but keep one if next byte has MSB clear)
        if bytes[0] != 0xFF {
            4
        } else if bytes[1] != 0xFF || bytes[2] & 0x80 == 0 {
            if bytes[1] & 0x80 == 0 { 4 } else { 3 }
        } else if bytes[2] != 0xFF || bytes[3] & 0x80 == 0 {
            if bytes[2] & 0x80 == 0 { 3 } else { 2 }
        } else {
            1
        }
    }
}

/// Returns the number of content bytes needed to encode an unsigned u32 in BER.
#[inline]
pub(crate) const fn unsigned32_content_len(value: u32) -> usize {
    if value == 0 {
        return 1;
    }

    let bytes = value.to_be_bytes();

    // Skip leading zeros, but add a 0x00 prefix if MSB is set
    if bytes[0] != 0 {
        if bytes[0] & 0x80 != 0 { 5 } else { 4 }
    } else if bytes[1] != 0 {
        if bytes[1] & 0x80 != 0 { 4 } else { 3 }
    } else if bytes[2] != 0 {
        if bytes[2] & 0x80 != 0 { 3 } else { 2 }
    } else if bytes[3] & 0x80 != 0 {
        2
    } else {
        1
    }
}

/// Returns the number of content bytes needed to encode an unsigned u64 in BER.
#[inline]
pub(crate) const fn unsigned64_content_len(value: u64) -> usize {
    if value == 0 {
        return 1;
    }

    let bytes = value.to_be_bytes();

    // Find first non-zero byte and check if padding needed
    if bytes[0] != 0 {
        if bytes[0] & 0x80 != 0 { 9 } else { 8 }
    } else if bytes[1] != 0 {
        if bytes[1] & 0x80 != 0 { 8 } else { 7 }
    } else if bytes[2] != 0 {
        if bytes[2] & 0x80 != 0 { 7 } else { 6 }
    } else if bytes[3] != 0 {
        if bytes[3] & 0x80 != 0 { 6 } else { 5 }
    } else if bytes[4] != 0 {
        if bytes[4] & 0x80 != 0 { 5 } else { 4 }
    } else if bytes[5] != 0 {
        if bytes[5] & 0x80 != 0 { 4 } else { 3 }
    } else if bytes[6] != 0 {
        if bytes[6] & 0x80 != 0 { 3 } else { 2 }
    } else if bytes[7] & 0x80 != 0 {
        2
    } else {
        1
    }
}

/// Encode a length value into the buffer (returns bytes in reverse order for prepending)
///
/// Uses short form for lengths <= 127, long form otherwise.
pub fn encode_length(len: usize) -> ([u8; 5], usize) {
    let mut buf = [0u8; 5];

    if len <= 127 {
        // Short form
        buf[0] = len as u8;
        (buf, 1)
    } else if len <= 0xFF {
        // Long form, 1 byte
        buf[0] = len as u8;
        buf[1] = 0x81;
        (buf, 2)
    } else if len <= 0xFFFF {
        // Long form, 2 bytes
        buf[0] = len as u8;
        buf[1] = (len >> 8) as u8;
        buf[2] = 0x82;
        (buf, 3)
    } else if len <= 0xFFFFFF {
        // Long form, 3 bytes
        buf[0] = len as u8;
        buf[1] = (len >> 8) as u8;
        buf[2] = (len >> 16) as u8;
        buf[3] = 0x83;
        (buf, 4)
    } else {
        // Long form, 4 bytes
        buf[0] = len as u8;
        buf[1] = (len >> 8) as u8;
        buf[2] = (len >> 16) as u8;
        buf[3] = (len >> 24) as u8;
        buf[4] = 0x84;
        (buf, 5)
    }
}

/// Decode a length from bytes, returning (length, bytes_consumed)
///
/// The `base_offset` parameter is used to report error offsets correctly
/// when this is called from within a decoder. The `target` parameter provides
/// the target address for error context.
pub fn decode_length(
    data: &[u8],
    base_offset: usize,
    target: Option<SocketAddr>,
) -> Result<(usize, usize)> {
    let target = target.unwrap_or(UNKNOWN_TARGET);

    if data.is_empty() {
        tracing::debug!(

            snmp.offset = %base_offset,
            kind = %DecodeErrorKind::TruncatedData,
            "truncated data: unexpected end of input in length"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    }

    let first = data[0];

    if first == 0x80 {
        // Indefinite length - rejected per net-snmp behavior
        tracing::debug!(

            snmp.offset = %base_offset,
            kind = %DecodeErrorKind::IndefiniteLength,
            "indefinite length encoding not supported"
        );
        return Err(Error::MalformedResponse { target }.boxed());
    }

    if first & 0x80 == 0 {
        // Short form
        Ok((first as usize, 1))
    } else {
        // Long form
        let num_octets = (first & 0x7F) as usize;

        if num_octets == 0 {
            tracing::debug!(

                snmp.offset = %base_offset,
                kind = %DecodeErrorKind::InvalidLength,
                "invalid length encoding: zero octets in long form"
            );
            return Err(Error::MalformedResponse { target }.boxed());
        }

        if num_octets > 4 {
            tracing::debug!(

                snmp.offset = %base_offset,
                kind = %DecodeErrorKind::LengthTooLong { octets: num_octets },
                "length encoding too long"
            );
            return Err(Error::MalformedResponse { target }.boxed());
        }

        if data.len() < 1 + num_octets {
            tracing::debug!(

                snmp.offset = %base_offset,
                kind = %DecodeErrorKind::InsufficientData { needed: 1 + num_octets, available: data.len() },
                "truncated data in length field"
            );
            return Err(Error::MalformedResponse { target }.boxed());
        }

        let mut len: usize = 0;
        for i in 0..num_octets {
            len = (len << 8) | (data[1 + i] as usize);
        }

        if len > MAX_LENGTH {
            tracing::debug!(

                snmp.offset = %base_offset,
                kind = %DecodeErrorKind::LengthExceedsMax { length: len, max: MAX_LENGTH },
                "length exceeds maximum"
            );
            return Err(Error::MalformedResponse { target }.boxed());
        }

        Ok((len, 1 + num_octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_form() {
        assert_eq!(decode_length(&[0], 0, None).unwrap(), (0, 1));
        assert_eq!(decode_length(&[127], 0, None).unwrap(), (127, 1));
        assert_eq!(decode_length(&[1], 0, None).unwrap(), (1, 1));
    }

    #[test]
    fn test_long_form_1_byte() {
        assert_eq!(decode_length(&[0x81, 128], 0, None).unwrap(), (128, 2));
        assert_eq!(decode_length(&[0x81, 255], 0, None).unwrap(), (255, 2));
    }

    #[test]
    fn test_long_form_2_bytes() {
        assert_eq!(
            decode_length(&[0x82, 0x01, 0x00], 0, None).unwrap(),
            (256, 3)
        );
        assert_eq!(
            decode_length(&[0x82, 0xFF, 0xFF], 0, None).unwrap(),
            (65535, 3)
        );
    }

    #[test]
    fn test_indefinite_rejected() {
        assert!(decode_length(&[0x80], 0, None).is_err());
    }

    #[test]
    fn test_encode_short() {
        let (buf, len) = encode_length(0);
        assert_eq!(&buf[..len], &[0]);

        let (buf, len) = encode_length(127);
        assert_eq!(&buf[..len], &[127]);
    }

    #[test]
    fn test_encode_long() {
        let (buf, len) = encode_length(128);
        assert_eq!(&buf[..len], &[128, 0x81]);

        let (buf, len) = encode_length(256);
        assert_eq!(&buf[..len], &[0, 1, 0x82]);
    }

    #[test]
    fn test_accept_oversized_length_encoding() {
        // Non-minimal length encodings are valid per X.690 Section 8.1.3.5 Note 2
        // 0x82 0x00 0x05 = length 5 using 2 bytes (minimal would be 0x05)
        let result = decode_length(&[0x82, 0x00, 0x05], 0, None);
        assert_eq!(result.unwrap(), (5, 3));

        // 0x81 0x01 = length 1 using long form (non-minimal, minimal would be 0x01)
        let result = decode_length(&[0x81, 0x01], 0, None);
        assert_eq!(result.unwrap(), (1, 2));

        // 0x82 0x00 0x7F = length 127 using 2 bytes (non-minimal, minimal would be 0x7F)
        let result = decode_length(&[0x82, 0x00, 0x7F], 0, None);
        assert_eq!(result.unwrap(), (127, 3));

        // 0x83 0x00 0x00 0x80 = length 128 using 3 bytes (non-minimal, minimal would be 0x81 0x80)
        let result = decode_length(&[0x83, 0x00, 0x00, 0x80], 0, None);
        assert_eq!(result.unwrap(), (128, 4));
    }

    #[test]
    fn test_length_encoded_len() {
        assert_eq!(length_encoded_len(0), 1);
        assert_eq!(length_encoded_len(127), 1);
        assert_eq!(length_encoded_len(128), 2);
        assert_eq!(length_encoded_len(255), 2);
        assert_eq!(length_encoded_len(256), 3);
        assert_eq!(length_encoded_len(65535), 3);
        assert_eq!(length_encoded_len(65536), 4);
    }

    #[test]
    fn test_base128_len() {
        assert_eq!(base128_len(0), 1);
        assert_eq!(base128_len(127), 1);
        assert_eq!(base128_len(128), 2);
        assert_eq!(base128_len(16383), 2);
        assert_eq!(base128_len(16384), 3);
        assert_eq!(base128_len(2097151), 3);
        assert_eq!(base128_len(2097152), 4);
        assert_eq!(base128_len(268435455), 4);
        assert_eq!(base128_len(268435456), 5);
        assert_eq!(base128_len(u32::MAX), 5);
    }

    #[test]
    fn test_integer_content_len() {
        // Zero
        assert_eq!(integer_content_len(0), 1);
        // Small positive
        assert_eq!(integer_content_len(1), 1);
        assert_eq!(integer_content_len(127), 1);
        // Needs padding byte
        assert_eq!(integer_content_len(128), 2);
        assert_eq!(integer_content_len(255), 2);
        // Larger values
        assert_eq!(integer_content_len(256), 2);
        assert_eq!(integer_content_len(32767), 2);
        assert_eq!(integer_content_len(32768), 3);
        // Negative
        assert_eq!(integer_content_len(-1), 1);
        assert_eq!(integer_content_len(-128), 1);
        assert_eq!(integer_content_len(-129), 2);
        // Extremes
        assert_eq!(integer_content_len(i32::MAX), 4);
        assert_eq!(integer_content_len(i32::MIN), 4);
    }

    #[test]
    fn test_unsigned32_content_len() {
        assert_eq!(unsigned32_content_len(0), 1);
        assert_eq!(unsigned32_content_len(127), 1);
        assert_eq!(unsigned32_content_len(128), 2); // needs padding
        assert_eq!(unsigned32_content_len(255), 2); // needs padding
        assert_eq!(unsigned32_content_len(256), 2);
        assert_eq!(unsigned32_content_len(u32::MAX), 5); // needs padding
    }

    #[test]
    fn test_unsigned64_content_len() {
        assert_eq!(unsigned64_content_len(0), 1);
        assert_eq!(unsigned64_content_len(127), 1);
        assert_eq!(unsigned64_content_len(128), 2); // needs padding
        assert_eq!(unsigned64_content_len(u64::MAX), 9); // needs padding
    }

    #[test]
    fn test_max_length_enforced() {
        // Length at exactly MAX_LENGTH should succeed
        let max = MAX_LENGTH;
        let max_bytes = [
            0x83,
            ((max >> 16) & 0xFF) as u8,
            ((max >> 8) & 0xFF) as u8,
            (max & 0xFF) as u8,
        ];
        let result = decode_length(&max_bytes, 0, None);
        assert_eq!(result.unwrap(), (MAX_LENGTH, 4));

        // Length exceeding MAX_LENGTH should fail (use 4-byte encoding)
        let over = MAX_LENGTH + 1;
        let over_bytes = [
            0x84, // 4 length bytes follow
            ((over >> 24) & 0xFF) as u8,
            ((over >> 16) & 0xFF) as u8,
            ((over >> 8) & 0xFF) as u8,
            (over & 0xFF) as u8,
        ];
        let result = decode_length(&over_bytes, 0, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(*err, Error::MalformedResponse { .. }),
            "Expected MalformedResponse error, got {:?}",
            err
        );
    }

    mod proptests {
        use super::*;
        use crate::ber::EncodeBuf;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn integer_content_len_matches_encoder(value: i32) {
                // Encode the integer: tag (1 byte) + length (1 byte for i32) + content
                let mut buf = EncodeBuf::new();
                buf.push_integer(value);
                let encoded_len = buf.len();
                // For i32, content is at most 4 bytes, so length encoding is always 1 byte
                // Total = 1 (tag) + 1 (length) + content_len
                let actual_content_len = encoded_len - 2;
                prop_assert_eq!(
                    integer_content_len(value),
                    actual_content_len,
                    "Mismatch for value {}: computed={}, actual={}",
                    value,
                    integer_content_len(value),
                    actual_content_len
                );
            }

            #[test]
            fn unsigned32_content_len_matches_encoder(value: u32) {
                let mut buf = EncodeBuf::new();
                buf.push_unsigned32(crate::ber::tag::application::COUNTER32, value);
                let encoded_len = buf.len();
                // For u32, content is at most 5 bytes, so length encoding is always 1 byte
                let actual_content_len = encoded_len - 2;
                prop_assert_eq!(
                    unsigned32_content_len(value),
                    actual_content_len,
                    "Mismatch for value {}", value
                );
            }

            #[test]
            fn unsigned64_content_len_matches_encoder(value: u64) {
                let mut buf = EncodeBuf::new();
                buf.push_integer64(value);
                let encoded_len = buf.len();
                // For u64, content is at most 9 bytes, so length encoding is always 1 byte
                let actual_content_len = encoded_len - 2;
                prop_assert_eq!(
                    unsigned64_content_len(value),
                    actual_content_len,
                    "Mismatch for value {}", value
                );
            }
        }
    }
}
