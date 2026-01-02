//! Hexadecimal encoding and decoding utilities.

use std::fmt;

/// Encode bytes as lowercase hex string.
///
/// # Examples
///
/// ```
/// use async_snmp::format::hex::encode;
///
/// assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
/// assert_eq!(encode(&[0x00, 0xff]), "00ff");
/// ```
pub fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decode hex string to bytes.
///
/// Returns an error for invalid hex characters or odd-length strings.
///
/// # Examples
///
/// ```
/// use async_snmp::format::hex::decode;
///
/// assert_eq!(decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(decode("00FF").unwrap(), vec![0x00, 0xff]);
/// assert!(decode("xyz").is_err());
/// assert!(decode("abc").is_err()); // odd length
/// ```
pub fn decode(s: &str) -> Result<Vec<u8>, DecodeError> {
    if !s.len().is_multiple_of(2) {
        return Err(DecodeError::OddLength);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| DecodeError::InvalidChar))
        .collect()
}

/// Error type for hex decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Input has odd length (must be pairs of hex digits)
    OddLength,
    /// Invalid hexadecimal character
    InvalidChar,
}

/// Lazy hex formatter - only formats when actually displayed.
///
/// This avoids allocation when logging at disabled levels.
///
/// # Examples
///
/// ```
/// use async_snmp::format::hex::Bytes;
///
/// let data = [0xde, 0xad, 0xbe, 0xef];
/// let formatted = format!("{}", Bytes(&data));
/// assert_eq!(formatted, "deadbeef");
/// ```
pub struct Bytes<'a>(pub &'a [u8]);

impl fmt::Debug for Bytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for Bytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_display() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let hex = Bytes(&data);
        assert_eq!(format!("{}", hex), "deadbeef");
    }

    #[test]
    fn test_bytes_debug() {
        let data = [0x00, 0xff, 0x42];
        let hex = Bytes(&data);
        assert_eq!(format!("{:?}", hex), "00ff42");
    }

    #[test]
    fn test_bytes_empty() {
        let data: [u8; 0] = [];
        let hex = Bytes(&data);
        assert_eq!(format!("{}", hex), "");
    }

    #[test]
    fn test_encode_basic() {
        assert_eq!(encode(b"Hello world!"), "48656c6c6f20776f726c6421");
        assert_eq!(encode(&[0x01, 0x02, 0x03, 0x0f, 0x10]), "0102030f10");
    }

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn test_encode_all_bytes() {
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0xff]), "ff");
        assert_eq!(encode(&[0x00, 0xff]), "00ff");
    }

    #[test]
    fn test_decode_basic() {
        assert_eq!(decode("48656c6c6f20776f726c6421").unwrap(), b"Hello world!");
        assert_eq!(
            decode("0102030f10").unwrap(),
            vec![0x01, 0x02, 0x03, 0x0f, 0x10]
        );
    }

    #[test]
    fn test_decode_empty() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_decode_mixed_case() {
        assert_eq!(decode("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(decode("DeAdBeEf").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_decode_odd_length_error() {
        assert_eq!(decode("1"), Err(DecodeError::OddLength));
        assert_eq!(decode("123"), Err(DecodeError::OddLength));
        assert_eq!(decode("12345"), Err(DecodeError::OddLength));
    }

    #[test]
    fn test_decode_invalid_char_error() {
        assert_eq!(decode("gg"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("0g"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("g0"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("xx"), Err(DecodeError::InvalidChar));
        assert_eq!(decode("  "), Err(DecodeError::InvalidChar));
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let encoded = encode(&original);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
