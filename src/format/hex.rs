//! Hexadecimal encoding and decoding utilities.

use std::fmt;
use std::fmt::Write;

const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

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
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    write_to(&mut out, bytes);
    out
}

/// Write lowercase hex-encoded bytes into an existing String buffer.
///
/// More efficient than [`encode`] when appending to an existing string.
pub fn write_to(out: &mut String, bytes: &[u8]) {
    for &b in bytes {
        out.push(HEX_TABLE[(b >> 4) as usize] as char);
        out.push(HEX_TABLE[(b & 0x0f) as usize] as char);
    }
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

/// Decode hex string to bytes, stripping spaces, colons, and dashes first.
///
/// Accepts formats like "de:ad:be:ef", "de-ad-be-ef", or "de ad be ef".
///
/// Returns an error if the stripped input has an odd number of hex digits or
/// contains invalid hex characters.
///
/// # Examples
///
/// ```
/// use async_snmp::format::hex::decode_relaxed;
///
/// assert_eq!(decode_relaxed("de:ad:be:ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(decode_relaxed("de ad be ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert_eq!(decode_relaxed("deadbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
/// assert!(decode_relaxed("a").is_err()); // one hex digit is odd-length
/// ```
pub fn decode_relaxed(s: &str) -> Result<Vec<u8>, DecodeError> {
    let clean: String = s.chars().filter(char::is_ascii_hexdigit).collect();
    decode(&clean)
}

/// Check if bytes are printable ASCII or valid UTF-8 with only printable characters.
///
/// Returns `true` for empty slices.
///
/// # Examples
///
/// ```
/// use async_snmp::format::hex::is_printable;
///
/// assert!(is_printable(b"Hello World"));
/// assert!(is_printable(b""));
/// assert!(!is_printable(&[0x00, 0x01]));
/// assert!(!is_printable(&[0x80, 0x81]));
/// ```
#[must_use]
pub fn is_printable(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s
            .chars()
            .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()),
        Err(_) => false,
    }
}

/// Error type for hex decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        for &b in self.0 {
            f.write_char(HEX_TABLE[(b >> 4) as usize] as char)?;
            f.write_char(HEX_TABLE[(b & 0x0f) as usize] as char)?;
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
        assert_eq!(format!("{hex}"), "deadbeef");
    }

    #[test]
    fn test_bytes_debug() {
        let data = [0x00, 0xff, 0x42];
        let hex = Bytes(&data);
        assert_eq!(format!("{hex:?}"), "00ff42");
    }

    #[test]
    fn test_bytes_empty() {
        let data: [u8; 0] = [];
        let hex = Bytes(&data);
        assert_eq!(format!("{hex}"), "");
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

    #[test]
    fn test_decode_relaxed_separators() {
        assert_eq!(
            decode_relaxed("de:ad:be:ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_relaxed("de-ad-be-ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_relaxed("de ad be ef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            decode_relaxed("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn test_decode_relaxed_errors() {
        // One hex digit after stripping non-hex chars
        assert!(decode_relaxed("a").is_err());
        // Three hex digits - odd after stripping
        assert!(decode_relaxed("a:b:c").is_err());
    }

    #[test]
    fn test_is_printable() {
        assert!(is_printable(b"Hello World"));
        assert!(is_printable(b"Line 1\nLine 2"));
        assert!(is_printable(b""));
        assert!(!is_printable(&[0x00, 0x01, 0x02]));
        assert!(!is_printable(&[0x80, 0x81]));
    }

    #[test]
    fn test_write_to() {
        let mut out = String::from("prefix-");
        write_to(&mut out, &[0xde, 0xad]);
        assert_eq!(out, "prefix-dead");
    }
}
