//! RFC 2579 DISPLAY-HINT formatting for OCTET STRING values.
//!
//! This module provides parsing and application of DISPLAY-HINT format strings
//! to raw bytes, commonly used to format MAC addresses, IP addresses, and other
//! structured binary data.
//!
//! # Examples
//!
//! ```
//! use async_snmp::format::display_hint;
//!
//! // IPv4 address
//! assert_eq!(display_hint::apply("1d.1d.1d.1d", &[192, 168, 1, 1]), "192.168.1.1");
//!
//! // MAC address (implicit repetition)
//! assert_eq!(display_hint::apply("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]), "00:1a:2b:3c:4d:5e");
//!
//! // DateAndTime
//! assert_eq!(display_hint::apply("2d-1d-1d,1d:1d:1d.1d", &[0x07, 0xE6, 8, 15, 8, 1, 15, 0]), "2022-8-15,8:1:15.0");
//! ```

use std::fmt::Write;

use crate::format::hex;

/// Apply RFC 2579 DISPLAY-HINT formatting to raw bytes.
///
/// Parses the hint string and applies it to the data in a single pass.
/// On any parse error or empty input, falls back to lowercase hex encoding.
///
/// # Format Specification
///
/// Each format specification has the form: `[*]<length><format>[separator][terminator]`
///
/// - `*` (optional): First data byte is repeat count for this spec
/// - `length`: Decimal digits specifying bytes to consume per application
/// - `format`: One of `d` (decimal), `x` (hex), `o` (octal), `a` (ASCII), `t` (UTF-8)
/// - `separator` (optional): Character to emit between formatted segments
/// - `terminator` (optional): Character after repeat group (only with `*`)
///
/// The last format specification repeats until all data is exhausted (implicit
/// repetition rule). Trailing separators are suppressed.
///
/// An octet length of zero is permitted (RFC 2579 3.1(2)): a zero-width spec
/// consumes no data and emits only its literal separator/terminator. A trailing
/// zero-width spec is not implicitly repeated (loop guard).
///
/// # Examples
///
/// ```
/// use async_snmp::format::display_hint;
///
/// // IPv4 address
/// assert_eq!(display_hint::apply("1d.1d.1d.1d", &[192, 168, 1, 1]), "192.168.1.1");
///
/// // MAC address (implicit repetition)
/// assert_eq!(display_hint::apply("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]), "00:1a:2b:3c:4d:5e");
///
/// // Star prefix with terminator
/// assert_eq!(display_hint::apply("*1d./1d", &[3, 10, 20, 30, 40]), "10.20.30/40");
///
/// // Empty hint returns hex
/// assert_eq!(display_hint::apply("", &[1, 2, 3]), "010203");
///
/// // Empty data returns empty string
/// assert_eq!(display_hint::apply("1d", &[]), "");
/// ```
#[must_use]
pub fn apply(hint: &str, data: &[u8]) -> String {
    if hint.is_empty() || data.is_empty() {
        return hex::encode(data);
    }

    let hint = hint.as_bytes();
    let mut result = String::with_capacity(data.len() * 4);
    let mut hint_pos = 0;
    let mut data_pos = 0;
    let mut last_spec_start = 0;

    while data_pos < data.len() {
        // If we've exhausted the hint, restart from the last spec (implicit repetition)
        if hint_pos >= hint.len() {
            hint_pos = last_spec_start;
        }

        let spec_start = hint_pos;

        // (1) Optional '*' repeat indicator
        let star_prefix = if hint_pos < hint.len() && hint[hint_pos] == b'*' {
            hint_pos += 1;
            true
        } else {
            false
        };

        // (2) Octet length - one or more decimal digits (required)
        if hint_pos >= hint.len() || !is_digit(hint[hint_pos]) {
            return hex::encode(data);
        }

        let mut take = 0usize;
        while hint_pos < hint.len() && is_digit(hint[hint_pos]) {
            take = take * 10 + (hint[hint_pos] - b'0') as usize;
            hint_pos += 1;
        }

        // (3) Format character (required)
        if hint_pos >= hint.len() {
            return hex::encode(data);
        }

        let fmt_char = hint[hint_pos];
        if !matches!(fmt_char, b'd' | b'x' | b'o' | b'a' | b't') {
            return hex::encode(data);
        }
        hint_pos += 1;

        // (4) Optional separator
        let (sep, has_sep) =
            if hint_pos < hint.len() && !is_digit(hint[hint_pos]) && hint[hint_pos] != b'*' {
                let s = hint[hint_pos];
                hint_pos += 1;
                (s, true)
            } else {
                (0, false)
            };

        // (5) Optional terminator (only valid with star_prefix)
        let (term, has_term) = if star_prefix
            && hint_pos < hint.len()
            && !is_digit(hint[hint_pos])
            && hint[hint_pos] != b'*'
        {
            let t = hint[hint_pos];
            hint_pos += 1;
            (t, true)
        } else {
            (0, false)
        };

        // Remember this spec for implicit repetition
        last_spec_start = spec_start;

        // Apply the spec to data
        let repeat_count = if star_prefix && data_pos < data.len() {
            let count = data[data_pos] as usize;
            data_pos += 1;
            count
        } else {
            1
        };

        // Zero-width spec: RFC 2579 3.1(2) permits an octet length of zero. Such
        // a spec consumes no data bytes (a leading `*` still consumed one byte
        // above as the repeat count) and emits only its literal separator (once
        // per repeat) and terminator, mirroring net-snmp snmplib/mib.c:517-545.
        if take == 0 {
            let is_last_spec = hint_pos >= hint.len();
            if has_sep {
                for r in 0..repeat_count {
                    // Suppress the trailing separator on the last spec
                    // (net-snmp: is_last_spec && repeat == 0).
                    if is_last_spec && r + 1 == repeat_count {
                        break;
                    }
                    result.push(sep as char);
                }
            }
            if has_term && !is_last_spec {
                result.push(term as char);
            }
            if is_last_spec {
                // Loop guard: a trailing zero-width spec never advances the data
                // cursor, so it must not be implicitly repeated (infinite loop).
                break;
            }
            continue;
        }

        for r in 0..repeat_count {
            if data_pos >= data.len() {
                break;
            }

            let end = (data_pos + take).min(data.len());
            let chunk = &data[data_pos..end];

            // Format the chunk
            match fmt_char {
                b'd' => {
                    // Big-endian unsigned integer
                    let val = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                    let _ = write!(result, "{val}");
                }
                b'x' => {
                    // Hex encoding - zero-padded per byte
                    hex::write_to(&mut result, chunk);
                }
                b'o' => {
                    // Big-endian octal
                    let val = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                    let _ = write!(result, "{val:o}");
                }
                b'a' => {
                    // ASCII - write bytes directly (single-byte characters)
                    for &b in chunk {
                        result.push(b as char);
                    }
                }
                b't' => {
                    // UTF-8 text. Per RFC 2579 3.1 (3), trailing octets which do not form a
                    // valid UTF-8 encoded character are discarded. Interior invalid sequences
                    // are unspecified by the RFC; we substitute U+FFFD for those, matching
                    // `from_utf8_lossy` behavior. Trailing handling is per-chunk.
                    let mut last_valid_len = result.len();
                    let mut i = 0;
                    while i < chunk.len() {
                        match std::str::from_utf8(&chunk[i..]) {
                            Ok(valid) => {
                                result.push_str(valid);
                                i = chunk.len();
                                last_valid_len = result.len();
                            }
                            Err(e) => {
                                let vup = e.valid_up_to();
                                if vup > 0 {
                                    // SAFETY: chunk[i..i+vup] is valid UTF-8 by valid_up_to()
                                    result.push_str(
                                        std::str::from_utf8(&chunk[i..i + vup]).unwrap(),
                                    );
                                    i += vup;
                                    last_valid_len = result.len();
                                }
                                match e.error_len() {
                                    None => {
                                        // Incomplete sequence at the end -> trailing, stop.
                                        i = chunk.len();
                                    }
                                    Some(len) => {
                                        // Tentative U+FFFD; trailing ones are trimmed below.
                                        result.push('\u{FFFD}');
                                        i += len;
                                    }
                                }
                            }
                        }
                    }
                    // Discard trailing invalid octets: trim tentative U+FFFDs not followed
                    // by a real character.
                    result.truncate(last_valid_len);
                }
                _ => unreachable!(),
            }
            data_pos = end;

            // Emit separator (suppressed if at end of data)
            let more_data = data_pos < data.len();
            if has_sep && more_data {
                // Suppress separator before terminator
                if has_term && r == repeat_count - 1 {
                    // Don't emit separator, terminator will follow
                } else {
                    result.push(sep as char);
                }
            }
        }

        // Emit terminator after repeat group
        if has_term && data_pos < data.len() {
            result.push(term as char);
        }
    }

    result
}

#[inline]
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Apply RFC 2579 DISPLAY-HINT formatting to an integer value.
///
/// INTEGER hints have the form: `<format>[-<decimal-places>]`
///
/// Format characters:
/// - `d` or `d-N`: Decimal, optionally with N implied decimal places
/// - `x`: Lowercase hexadecimal
/// - `o`: Octal
/// - `b`: Binary
///
/// Returns `None` for invalid or unsupported hint formats.
///
/// # Examples
///
/// ```
/// use async_snmp::format::display_hint;
///
/// // Basic formats
/// assert_eq!(display_hint::apply_integer("d", 1234), Some("1234".to_string()));
/// assert_eq!(display_hint::apply_integer("x", 255), Some("ff".to_string()));
/// assert_eq!(display_hint::apply_integer("o", 8), Some("10".to_string()));
/// assert_eq!(display_hint::apply_integer("b", 5), Some("101".to_string()));
///
/// // Decimal places (DISPLAY-HINT "d-2" means 2 implied decimal places)
/// assert_eq!(display_hint::apply_integer("d-2", 1234), Some("12.34".to_string()));
/// assert_eq!(display_hint::apply_integer("d-2", 5), Some("0.05".to_string()));
/// assert_eq!(display_hint::apply_integer("d-2", -500), Some("-5.00".to_string()));
/// assert_eq!(display_hint::apply_integer("d-1", 255), Some("25.5".to_string()));
/// ```
#[must_use]
pub fn apply_integer(hint: &str, value: i32) -> Option<String> {
    match hint {
        "x" => Some(format!("{value:x}")),
        "o" => Some(format!("{value:o}")),
        "b" => Some(format!("{value:b}")),
        "d" => Some(format!("{value}")),
        hint if hint.starts_with("d-") => {
            let places: usize = hint[2..].parse().ok()?;
            if places == 0 {
                return Some(format!("{value}"));
            }
            Some(format_with_decimal_point(value, places))
        }
        _ => None,
    }
}

/// Format an integer with an implied decimal point.
///
/// Uses pure string manipulation to avoid floating-point rounding issues.
fn format_with_decimal_point(value: i32, places: usize) -> String {
    let is_negative = value < 0;
    let abs_value = value.unsigned_abs();
    let abs_str = abs_value.to_string();

    let result = if abs_str.len() <= places {
        // Need to pad with leading zeros after decimal point
        // e.g., 5 with places=2 -> "0.05"
        let zeros_needed = places - abs_str.len();
        format!("0.{}{}", "0".repeat(zeros_needed), abs_str)
    } else {
        // Insert decimal point
        // e.g., 1234 with places=2 -> "12.34"
        let split_point = abs_str.len() - places;
        let (integer_part, decimal_part) = abs_str.split_at(split_point);
        format!("{integer_part}.{decimal_part}")
    };

    if is_negative {
        format!("-{result}")
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Basic Format Tests
    // ========================================================================

    #[test]
    fn empty_hint_returns_hex() {
        assert_eq!(apply("", &[0x01, 0x02, 0x03]), "010203");
    }

    #[test]
    fn empty_data_returns_empty() {
        assert_eq!(apply("1d", &[]), "");
    }

    #[test]
    fn ipv4_address() {
        assert_eq!(apply("1d.1d.1d.1d", &[192, 168, 1, 1]), "192.168.1.1");
    }

    #[test]
    fn ipv4_with_zone_id() {
        assert_eq!(
            apply("1d.1d.1d.1d%4d", &[192, 168, 1, 1, 0, 0, 0, 3]),
            "192.168.1.1%3"
        );
    }

    #[test]
    fn mac_address() {
        assert_eq!(
            apply("1x:", &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            "00:1a:2b:3c:4d:5e"
        );
    }

    #[test]
    fn ipv6_address() {
        let data = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(
            apply("2x:2x:2x:2x:2x:2x:2x:2x", &data),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn ipv6_with_zone_id() {
        let data = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        ];
        assert_eq!(
            apply("2x:2x:2x:2x:2x:2x:2x:2x%4d", &data),
            "fe80:0000:0000:0000:0000:0000:0000:0001%5"
        );
    }

    #[test]
    fn display_string() {
        assert_eq!(apply("255a", b"Hello, World!"), "Hello, World!");
    }

    #[test]
    fn simple_decimal() {
        assert_eq!(apply("1d", &[42]), "42");
    }

    #[test]
    fn multi_byte_decimal() {
        assert_eq!(apply("4d", &[0x00, 0x01, 0x00, 0x00]), "65536");
    }

    #[test]
    fn octal_format() {
        assert_eq!(apply("1o", &[8]), "10");
    }

    #[test]
    fn hex_with_dash_separator() {
        assert_eq!(apply("1x-", &[0xaa, 0xbb, 0xcc]), "aa-bb-cc");
    }

    #[test]
    fn star_prefix_repeat() {
        assert_eq!(apply("*1x:", &[3, 0xaa, 0xbb, 0xcc]), "aa:bb:cc");
    }

    #[test]
    fn star_prefix_with_terminator() {
        assert_eq!(apply("*1d./1d", &[3, 10, 20, 30, 40]), "10.20.30/40");
    }

    #[test]
    fn star_prefix_zero_repeat_count() {
        // RFC 2579 3.1 (1): the repeat count is read from the data octet; a
        // count of 0 means zero repetitions. The count byte (0x00) is still
        // consumed, but no formatted output is produced.
        assert_eq!(apply("*1x", &[0x00]), "");
    }

    #[test]
    fn star_prefix_nonzero_repeat_count_control() {
        // Control for `star_prefix_zero_repeat_count`: confirms the star path
        // still formats normally when the repeat count is non-zero.
        assert_eq!(apply("*1x", &[0x02, 0xaa, 0xbb]), "aabb");
    }

    #[test]
    fn star_prefix_zero_repeat_count_non_hex_format() {
        // Same zero-count behavior with a `d` format char, showing it is
        // independent of the format character.
        assert_eq!(apply("*1d", &[0x00]), "");
    }

    #[test]
    fn trailing_separator_suppressed() {
        assert_eq!(apply("1d.", &[1, 2, 3]), "1.2.3");
    }

    #[test]
    fn date_and_time() {
        assert_eq!(
            apply("2d-1d-1d,1d:1d:1d.1d", &[0x07, 0xE6, 8, 15, 8, 1, 15, 0]),
            "2022-8-15,8:1:15.0"
        );
    }

    #[test]
    fn data_shorter_than_spec() {
        assert_eq!(apply("1d.1d.1d.1d", &[10, 20]), "10.20");
    }

    #[test]
    fn utf8_format() {
        assert_eq!(apply("10t", b"hello"), "hello");
    }

    #[test]
    fn utf8_multibyte_sequences() {
        // "café" in UTF-8: c, a, f, e-with-acute (0xc3 0xa9)
        let bytes = "café".as_bytes();
        assert_eq!(apply("255t", bytes), "café");
    }

    #[test]
    fn utf8_multibyte_cjk() {
        // U+4E16 (世) = 0xe4 0xb8 0x96
        let bytes = "世界".as_bytes();
        assert_eq!(apply("255t", bytes), "世界");
    }

    #[test]
    fn utf8_trailing_invalid_bytes_discarded() {
        // Trailing invalid octets are discarded per RFC 2579 3.1 (3), not replaced.
        let bytes = &[0xff, 0xfe];
        assert_eq!(apply("2t", bytes), "");
    }

    #[test]
    fn utf8_trailing_truncated_multibyte_discarded() {
        // \xe2\x82 is a cut-off 3-byte euro sign sequence; discarded, no U+FFFD.
        assert_eq!(apply("255t", b"abc\xe2\x82"), "abc");
    }

    #[test]
    fn utf8_trailing_invalid_byte_discarded() {
        assert_eq!(apply("255t", b"abc\xff"), "abc");
    }

    #[test]
    fn utf8_interior_invalid_retained_as_replacement_char() {
        // Interior invalid sequences (followed by valid content) keep U+FFFD.
        assert_eq!(apply("255t", b"a\xffb"), "a\u{fffd}b");
    }

    #[test]
    fn utf8_interior_retained_trailing_discarded() {
        assert_eq!(apply("255t", b"a\xffb\xff"), "a\u{fffd}b");
    }

    #[test]
    fn uuid_format() {
        let data = [
            0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55,
        ];
        assert_eq!(
            apply("4x-2x-2x-1x1x-6x", &data),
            "12345678-abcd-ef01-2345-001122334455"
        );
    }

    #[test]
    fn ipv4_with_prefix() {
        assert_eq!(apply("1d.1d.1d.1d/1d", &[10, 0, 0, 0, 24]), "10.0.0.0/24");
    }

    #[test]
    fn two_digit_take_value() {
        assert_eq!(
            apply("10d", &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "1"
        );
    }

    #[test]
    fn zero_padded_hex_output() {
        assert_eq!(apply("1x", &[0x0f]), "0f");
    }

    #[test]
    fn single_byte_trailing_separator_suppressed() {
        assert_eq!(apply("1d.", &[42]), "42");
    }

    // ========================================================================
    // Error Cases (should return hex fallback)
    // ========================================================================

    #[test]
    fn invalid_format_character() {
        assert_eq!(apply("1z", &[1, 2, 3]), "010203");
    }

    #[test]
    fn missing_format_character() {
        assert_eq!(apply("1", &[1, 2, 3]), "010203");
    }

    #[test]
    fn missing_take_value() {
        assert_eq!(apply("d", &[1, 2, 3]), "010203");
    }

    #[test]
    fn zero_width_trailing_no_abort_no_loop() {
        // RFC 2579 3.1(2): octet length may be zero. A trailing zero-width spec
        // consumes no data and emits no separator/terminator, and must not loop
        // forever (net-snmp snmplib/mib.c:517-545). Remaining data is ignored.
        assert_eq!(apply("0d", &[1, 2, 3]), "");
    }

    #[test]
    fn zero_width_emits_separator_then_real_spec() {
        // Zero-width `0d` is not the last spec, so it emits its `.` separator;
        // `1d` then formats the single byte.
        assert_eq!(apply("0d.1d", &[5]), ".5");
    }

    #[test]
    fn zero_width_star_repeat_suppresses_trailing_separator() {
        // `*` reads repeat=3 from the data byte; the zero-width spec is last, so
        // the 3rd (trailing) separator is suppressed -> two commas.
        assert_eq!(apply("*0d,", &[3]), ",,");
    }

    #[test]
    fn zero_width_control_normal_hint_unchanged() {
        assert_eq!(apply("1d.1d", &[10, 20]), "10.20");
    }

    // ========================================================================
    // Implicit Repetition Tests
    // ========================================================================

    #[test]
    fn single_spec_repeats_for_all_data() {
        assert_eq!(apply("1d.", &[1, 2, 3, 4, 5]), "1.2.3.4.5");
    }

    #[test]
    fn last_spec_repeats_after_fixed_prefix() {
        assert_eq!(apply("1d-1d.", &[1, 2, 3, 4, 5, 6]), "1-2.3.4.5.6");
    }

    #[test]
    fn hex_implicit_repetition() {
        assert_eq!(apply("1x:", &[0xaa, 0xbb, 0xcc, 0xdd]), "aa:bb:cc:dd");
    }

    // ========================================================================
    // INTEGER DISPLAY-HINT Tests
    // ========================================================================

    #[test]
    fn integer_hint_decimal() {
        assert_eq!(apply_integer("d", 1234), Some("1234".to_string()));
        assert_eq!(apply_integer("d", -42), Some("-42".to_string()));
        assert_eq!(apply_integer("d", 0), Some("0".to_string()));
    }

    #[test]
    fn integer_hint_hex() {
        assert_eq!(apply_integer("x", 255), Some("ff".to_string()));
        assert_eq!(apply_integer("x", 0), Some("0".to_string()));
        assert_eq!(apply_integer("x", 16), Some("10".to_string()));
        // Negative values show as two's complement representation
        assert_eq!(apply_integer("x", -1), Some("ffffffff".to_string()));
    }

    #[test]
    fn integer_hint_octal() {
        assert_eq!(apply_integer("o", 8), Some("10".to_string()));
        assert_eq!(apply_integer("o", 64), Some("100".to_string()));
        assert_eq!(apply_integer("o", 0), Some("0".to_string()));
    }

    #[test]
    fn integer_hint_binary() {
        assert_eq!(apply_integer("b", 5), Some("101".to_string()));
        assert_eq!(apply_integer("b", 255), Some("11111111".to_string()));
        assert_eq!(apply_integer("b", 0), Some("0".to_string()));
    }

    #[test]
    fn integer_hint_decimal_places() {
        // Standard cases
        assert_eq!(apply_integer("d-2", 1234), Some("12.34".to_string()));
        assert_eq!(apply_integer("d-1", 255), Some("25.5".to_string()));
        assert_eq!(apply_integer("d-3", 12500), Some("12.500".to_string()));

        // Small values need leading zeros after decimal
        assert_eq!(apply_integer("d-2", 5), Some("0.05".to_string()));
        assert_eq!(apply_integer("d-2", 50), Some("0.50".to_string()));
        assert_eq!(apply_integer("d-3", 5), Some("0.005".to_string()));

        // Zero
        assert_eq!(apply_integer("d-2", 0), Some("0.00".to_string()));

        // Negative values
        assert_eq!(apply_integer("d-2", -500), Some("-5.00".to_string()));
        assert_eq!(apply_integer("d-2", -5), Some("-0.05".to_string()));
        assert_eq!(apply_integer("d-1", -42), Some("-4.2".to_string()));

        // d-0 is just decimal
        assert_eq!(apply_integer("d-0", 1234), Some("1234".to_string()));
    }

    #[test]
    fn integer_hint_invalid() {
        assert_eq!(apply_integer("", 42), None);
        assert_eq!(apply_integer("z", 42), None);
        assert_eq!(apply_integer("d-abc", 42), None);
        assert_eq!(apply_integer("1d", 42), None); // OCTET STRING format, not INTEGER
    }
}
