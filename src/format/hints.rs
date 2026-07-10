//! Pre-defined DISPLAY-HINT constants for common SNMP types.
//!
//! These constants can be used with [`Value::format_with_hint()`](crate::Value::format_with_hint)
//! to format values according to their MIB definitions without looking up hints.
//!
//! # Example
//!
//! ```
//! use async_snmp::format::hints;
//! use async_snmp::Value;
//! use bytes::Bytes;
//!
//! let mac = Value::OctetString(Bytes::from_static(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
//! assert_eq!(mac.format_with_hint(hints::MAC_ADDRESS), Some("00:1a:2b:3c:4d:5e".to_string()));
//! ```

/// MAC address: "1x:" - each byte as hex separated by colons.
///
/// Used by `SNMPv2-TC::MacAddress` and many physical address fields.
pub const MAC_ADDRESS: &str = "1x:";

/// Display string (UTF-8): "255a" - up to 255 ASCII/UTF-8 characters.
///
/// Used by `SNMPv2-TC::DisplayString`, `SNMPv2-MIB::sysDescr`, etc.
pub const DISPLAY_STRING: &str = "255a";

/// Date and time: "2d-1d-1d,1d:1d:1d.1d,1a1d:1d".
///
/// Used by `SNMPv2-TC::DateAndTime` (8 or 11 bytes).
/// Format: YYYY-MM-DD,HH:MM:SS.d,+/-HH:MM
pub const DATE_AND_TIME: &str = "2d-1d-1d,1d:1d:1d.1d,1a1d:1d";

/// Hexadecimal string: "1x" - each byte as two hex digits.
///
/// Common format for binary data that should display as hex.
pub const HEX_STRING: &str = "1x";

/// Hexadecimal with spaces: "1x " - each byte as hex separated by spaces.
///
/// Alternative hex format sometimes used for readability.
pub const HEX_STRING_SPACED: &str = "1x ";

/// Dotted decimal: "1d." - each byte as decimal separated by dots.
///
/// Used for IP addresses and similar dotted notations.
pub const DOTTED_DECIMAL: &str = "1d.";

/// UTF-8 string: "255t" - up to 255 UTF-8 encoded characters.
///
/// For explicitly UTF-8 encoded strings.
pub const UTF8_STRING: &str = "255t";

/// Integer as hex: "x" - integer value in lowercase hexadecimal.
pub const INTEGER_HEX: &str = "x";

/// Integer with 1 decimal place: "d-1".
///
/// Common for tenths (e.g., temperatures in 0.1 degree units).
pub const DECIMAL_1: &str = "d-1";

/// Integer with 2 decimal places: "d-2".
///
/// Common for hundredths (e.g., percentages as 0-10000).
pub const DECIMAL_2: &str = "d-2";

/// Integer with 3 decimal places: "d-3".
///
/// Common for thousandths (e.g., voltages in millivolts).
pub const DECIMAL_3: &str = "d-3";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Value;
    use bytes::Bytes;

    #[test]
    fn test_mac_address_hint() {
        let mac = Value::OctetString(Bytes::from_static(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
        assert_eq!(
            mac.format_with_hint(MAC_ADDRESS),
            Some("00:1a:2b:3c:4d:5e".to_string())
        );
    }

    #[test]
    fn test_display_string_hint() {
        let desc = Value::OctetString(Bytes::from_static(b"Hello World"));
        assert_eq!(
            desc.format_with_hint(DISPLAY_STRING),
            Some("Hello World".to_string())
        );
    }

    #[test]
    fn test_hex_string_hint() {
        let data = Value::OctetString(Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(
            data.format_with_hint(HEX_STRING),
            Some("deadbeef".to_string())
        );
    }

    #[test]
    fn test_dotted_decimal_hint() {
        let ip = Value::OctetString(Bytes::from_static(&[192, 168, 1, 1]));
        assert_eq!(
            ip.format_with_hint(DOTTED_DECIMAL),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_integer_decimal_hints() {
        assert_eq!(
            Value::Integer(2350).format_with_hint(DECIMAL_2),
            Some("23.50".to_string())
        );
        assert_eq!(
            Value::Integer(1234).format_with_hint(DECIMAL_1),
            Some("123.4".to_string())
        );
        assert_eq!(
            Value::Integer(12500).format_with_hint(DECIMAL_3),
            Some("12.500".to_string())
        );
    }

    #[test]
    fn test_integer_hex_hint() {
        assert_eq!(
            Value::Integer(255).format_with_hint(INTEGER_HEX),
            Some("ff".to_string())
        );
    }

    #[test]
    fn test_hex_string_hint_displays_as_hex() {
        // HEX_STRING uses "1x" which is valid RFC 2579
        let data = Value::OctetString(Bytes::from_static(&[0x0f, 0xff]));
        assert_eq!(data.format_with_hint(HEX_STRING), Some("0fff".to_string()));
    }

    #[test]
    fn test_utf8_string_multibyte() {
        // UTF8_STRING uses "255t" and must decode multi-byte UTF-8 correctly
        let data = Value::OctetString(Bytes::from("café".as_bytes()));
        assert_eq!(data.format_with_hint(UTF8_STRING), Some("café".to_string()));
    }

    #[test]
    fn test_date_and_time_hint_with_timezone() {
        // RFC 2579 3.1(7) worked example: Tuesday May 26, 1992 at 1:30:15 PM EDT
        // (references/rfc2579.txt:1058) -> "1992-5-26,13:30:15.0,-4:0"
        let dt = Value::OctetString(Bytes::from_static(&[
            0x07, 0xC8, // year 1992
            5,    // month
            26,   // day
            13,   // hour
            30,   // minutes
            15,   // seconds
            0,    // deci-seconds
            b'-', // direction from UTC
            4,    // hours from UTC
            0,    // minutes from UTC
        ]));
        assert_eq!(
            dt.format_with_hint(DATE_AND_TIME),
            Some("1992-5-26,13:30:15.0,-4:0".to_string())
        );
    }

    #[test]
    fn test_date_and_time_hint_without_timezone() {
        // 8-octet form: same date/time, no timezone tail. The trailing
        // ",1a1d:1d" specs receive no data and are not emitted.
        let dt = Value::OctetString(Bytes::from_static(&[
            0x07, 0xC8, // year 1992
            5,    // month
            26,   // day
            13,   // hour
            30,   // minutes
            15,   // seconds
            0,    // deci-seconds
        ]));
        assert_eq!(
            dt.format_with_hint(DATE_AND_TIME),
            Some("1992-5-26,13:30:15.0".to_string())
        );
    }

    #[test]
    fn test_date_and_time_hint_positive_offset() {
        // 11-octet form with a '+' direction (e.g. UTC+10:30), covering the
        // positive-offset branch of the `1a` direction character.
        let dt = Value::OctetString(Bytes::from_static(&[
            0x07, 0xC8, // year 1992
            5,    // month
            26,   // day
            13,   // hour
            30,   // minutes
            15,   // seconds
            0,    // deci-seconds
            b'+', // direction from UTC
            10,   // hours from UTC
            30,   // minutes from UTC
        ]));
        assert_eq!(
            dt.format_with_hint(DATE_AND_TIME),
            Some("1992-5-26,13:30:15.0,+10:30".to_string())
        );
    }
}
