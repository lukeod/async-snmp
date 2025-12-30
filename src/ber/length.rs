//! BER length encoding and decoding.
//!
//! Length encoding follows X.690 Section 8.1.3:
//! - Short form: Single byte, bit 8=0, value 0-127
//! - Long form: Initial byte (bit 8=1, bits 7-1=count), followed by length bytes
//! - Indefinite form (0x80): Rejected per net-snmp behavior

use crate::error::{DecodeErrorKind, Error, Result};

/// Maximum length we'll accept (to prevent DoS)
pub const MAX_LENGTH: usize = 0xFFFFFF; // 16MB

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
/// when this is called from within a decoder.
pub fn decode_length(data: &[u8], base_offset: usize) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(Error::decode(base_offset, DecodeErrorKind::TruncatedData));
    }

    let first = data[0];

    if first == 0x80 {
        // Indefinite length - rejected per net-snmp behavior
        return Err(Error::decode(
            base_offset,
            DecodeErrorKind::IndefiniteLength,
        ));
    }

    if first & 0x80 == 0 {
        // Short form
        Ok((first as usize, 1))
    } else {
        // Long form
        let num_octets = (first & 0x7F) as usize;

        if num_octets == 0 {
            return Err(Error::decode(base_offset, DecodeErrorKind::InvalidLength));
        }

        if num_octets > 4 {
            return Err(Error::decode(
                base_offset,
                DecodeErrorKind::LengthTooLong { octets: num_octets },
            ));
        }

        if data.len() < 1 + num_octets {
            return Err(Error::decode(base_offset, DecodeErrorKind::TruncatedData));
        }

        let mut len: usize = 0;
        for i in 0..num_octets {
            len = (len << 8) | (data[1 + i] as usize);
        }

        if len > MAX_LENGTH {
            return Err(Error::decode(
                base_offset,
                DecodeErrorKind::LengthExceedsMax {
                    length: len,
                    max: MAX_LENGTH,
                },
            ));
        }

        Ok((len, 1 + num_octets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_form() {
        assert_eq!(decode_length(&[0], 0).unwrap(), (0, 1));
        assert_eq!(decode_length(&[127], 0).unwrap(), (127, 1));
        assert_eq!(decode_length(&[1], 0).unwrap(), (1, 1));
    }

    #[test]
    fn test_long_form_1_byte() {
        assert_eq!(decode_length(&[0x81, 128], 0).unwrap(), (128, 2));
        assert_eq!(decode_length(&[0x81, 255], 0).unwrap(), (255, 2));
    }

    #[test]
    fn test_long_form_2_bytes() {
        assert_eq!(decode_length(&[0x82, 0x01, 0x00], 0).unwrap(), (256, 3));
        assert_eq!(decode_length(&[0x82, 0xFF, 0xFF], 0).unwrap(), (65535, 3));
    }

    #[test]
    fn test_indefinite_rejected() {
        assert!(decode_length(&[0x80], 0).is_err());
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
        let result = decode_length(&[0x82, 0x00, 0x05], 0);
        assert_eq!(result.unwrap(), (5, 3));

        // 0x81 0x01 = length 1 using long form (non-minimal, minimal would be 0x01)
        let result = decode_length(&[0x81, 0x01], 0);
        assert_eq!(result.unwrap(), (1, 2));

        // 0x82 0x00 0x7F = length 127 using 2 bytes (non-minimal, minimal would be 0x7F)
        let result = decode_length(&[0x82, 0x00, 0x7F], 0);
        assert_eq!(result.unwrap(), (127, 3));

        // 0x83 0x00 0x00 0x80 = length 128 using 3 bytes (non-minimal, minimal would be 0x81 0x80)
        let result = decode_length(&[0x83, 0x00, 0x00, 0x80], 0);
        assert_eq!(result.unwrap(), (128, 4));
    }
}
