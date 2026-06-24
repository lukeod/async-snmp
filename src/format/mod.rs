//! Formatting utilities for SNMP values.
//!
//! This module provides formatting functions for converting raw SNMP data
//! into human-readable strings.
//!
//! ## Display Hints
//!
//! The [`display_hint`] module implements RFC 2579 DISPLAY-HINT formatting
//! for OCTET STRING values. This is commonly used to format MAC addresses,
//! IP addresses, and other structured binary data.
//!
//! ```
//! use async_snmp::format::display_hint;
//!
//! // Format a MAC address
//! let mac = display_hint::apply("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);
//! assert_eq!(mac, "00:1a:2b:3c:4d:5e");
//!
//! // Format an IPv4 address
//! let ip = display_hint::apply("1d.1d.1d.1d", &[192, 168, 1, 1]);
//! assert_eq!(ip, "192.168.1.1");
//! ```
//!
//! ## Hex Encoding
//!
//! The [`hex`] module provides hexadecimal encoding and decoding utilities.
//!
//! ```
//! use async_snmp::format::hex;
//!
//! // Encode bytes to hex string
//! assert_eq!(hex::encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
//!
//! // Lazy formatting for logging
//! let data = [0x00, 0xff];
//! println!("{}", hex::Bytes(&data)); // prints: 00ff
//! ```

pub mod display_hint;
pub mod hex;
pub mod hints;

/// Format `TimeTicks` (centiseconds) as a human-readable duration string.
///
/// Output format: `Xd HH:MM:SS.CC` (with days) or `HH:MM:SS.CC` (without).
///
/// # Examples
///
/// ```
/// use async_snmp::format::format_timeticks;
///
/// assert_eq!(format_timeticks(12345678), "1d 10:17:36.78");
/// assert_eq!(format_timeticks(360000), "01:00:00.00");
/// assert_eq!(format_timeticks(0), "00:00:00.00");
/// ```
#[must_use]
pub fn format_timeticks(centiseconds: u32) -> String {
    let total_seconds = centiseconds / 100;
    let cs = centiseconds % 100;

    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if days > 0 {
        format!(
            "{days}d {hours:02}:{minutes:02}:{seconds:02}.{cs:02}"
        )
    } else {
        format!("{hours:02}:{minutes:02}:{seconds:02}.{cs:02}")
    }
}

/// Format bytes as space-separated uppercase hex (e.g., "0A 1B 2C").
#[must_use]
pub fn format_hex_display(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timeticks() {
        assert_eq!(format_timeticks(1234_5678), "1d 10:17:36.78");
        assert_eq!(format_timeticks(360_000), "01:00:00.00");
        assert_eq!(format_timeticks(0), "00:00:00.00");
    }

    #[test]
    fn test_format_hex_display() {
        assert_eq!(format_hex_display(&[0x00, 0x1A, 0x2B]), "00 1A 2B");
        assert_eq!(format_hex_display(&[]), "");
    }
}
