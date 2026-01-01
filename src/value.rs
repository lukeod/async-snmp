//! SNMP value types.
//!
//! The `Value` enum represents all SNMP data types including exceptions.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::error::{DecodeErrorKind, Error, Result};
use crate::format::hex;
use crate::oid::Oid;
use bytes::Bytes;

/// SNMP value.
///
/// Represents all SNMP data types including SMIv2 types and exception values.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// INTEGER (ASN.1 primitive, signed 32-bit)
    Integer(i32),

    /// OCTET STRING (arbitrary bytes).
    ///
    /// Per RFC 2578 (SMIv2), OCTET STRING values have a maximum size of 65535 octets.
    /// This limit is **not enforced** during decoding to maintain permissive parsing
    /// behavior. Applications that require strict compliance should validate size
    /// after decoding.
    OctetString(Bytes),

    /// NULL
    Null,

    /// OBJECT IDENTIFIER
    ObjectIdentifier(Oid),

    /// IpAddress (4 bytes, big-endian)
    IpAddress([u8; 4]),

    /// Counter32 (unsigned 32-bit, wrapping)
    Counter32(u32),

    /// Gauge32 / Unsigned32 (unsigned 32-bit, non-wrapping)
    Gauge32(u32),

    /// TimeTicks (hundredths of seconds since epoch)
    TimeTicks(u32),

    /// Opaque (legacy, arbitrary bytes)
    Opaque(Bytes),

    /// Counter64 (unsigned 64-bit, wrapping).
    ///
    /// **SNMPv2c/v3 only.** Counter64 was introduced in SNMPv2 (RFC 2578) and is
    /// not supported in SNMPv1. When sending Counter64 values to an SNMPv1 agent,
    /// the value will be silently ignored or cause an error depending on the agent
    /// implementation.
    ///
    /// If your application needs to support SNMPv1, avoid using Counter64 or
    /// fall back to Counter32 (with potential overflow for high-bandwidth counters).
    Counter64(u64),

    /// noSuchObject exception - the requested OID exists in the MIB but has no value.
    ///
    /// This exception indicates that the agent recognizes the OID (it's a valid
    /// MIB object), but there is no instance available. This commonly occurs when
    /// requesting a table column OID without an index.
    ///
    /// # Example
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// let response = Value::NoSuchObject;
    /// assert!(response.is_exception());
    ///
    /// // When handling responses, check for exceptions:
    /// match response {
    ///     Value::NoSuchObject => println!("OID exists but has no value"),
    ///     _ => {}
    /// }
    /// ```
    NoSuchObject,

    /// noSuchInstance exception - the specific instance does not exist.
    ///
    /// This exception indicates that while the MIB object exists, the specific
    /// instance (index) requested does not. This commonly occurs when querying
    /// a table row that doesn't exist.
    ///
    /// # Example
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// let response = Value::NoSuchInstance;
    /// assert!(response.is_exception());
    /// ```
    NoSuchInstance,

    /// endOfMibView exception - end of the MIB has been reached.
    ///
    /// This exception is returned during GETNEXT/GETBULK operations when
    /// there are no more OIDs lexicographically greater than the requested OID.
    /// This is the normal termination condition for SNMP walks.
    ///
    /// # Example
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// let response = Value::EndOfMibView;
    /// assert!(response.is_exception());
    ///
    /// // Commonly used to detect end of walk
    /// if matches!(response, Value::EndOfMibView) {
    ///     println!("Walk complete - reached end of MIB");
    /// }
    /// ```
    EndOfMibView,

    /// Unknown/unrecognized value type (for forward compatibility)
    Unknown { tag: u8, data: Bytes },
}

impl Value {
    /// Try to get as i32.
    ///
    /// Returns `Some(i32)` for [`Value::Integer`], `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// let v = Value::Integer(42);
    /// assert_eq!(v.as_i32(), Some(42));
    ///
    /// let v = Value::Integer(-100);
    /// assert_eq!(v.as_i32(), Some(-100));
    ///
    /// // Counter32 is not an Integer
    /// let v = Value::Counter32(42);
    /// assert_eq!(v.as_i32(), None);
    /// ```
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Value::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Try to get as u32.
    ///
    /// Returns `Some(u32)` for [`Value::Counter32`], [`Value::Gauge32`],
    /// [`Value::TimeTicks`], or non-negative [`Value::Integer`]. Returns `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// // Works for Counter32, Gauge32, TimeTicks
    /// assert_eq!(Value::Counter32(100).as_u32(), Some(100));
    /// assert_eq!(Value::Gauge32(200).as_u32(), Some(200));
    /// assert_eq!(Value::TimeTicks(300).as_u32(), Some(300));
    ///
    /// // Works for non-negative integers
    /// assert_eq!(Value::Integer(50).as_u32(), Some(50));
    ///
    /// // Returns None for negative integers
    /// assert_eq!(Value::Integer(-1).as_u32(), None);
    ///
    /// // Counter64 returns None (use as_u64 instead)
    /// assert_eq!(Value::Counter64(100).as_u32(), None);
    /// ```
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => Some(*v),
            Value::Integer(v) if *v >= 0 => Some(*v as u32),
            _ => None,
        }
    }

    /// Try to get as u64.
    ///
    /// Returns `Some(u64)` for [`Value::Counter64`], or any 32-bit unsigned type
    /// ([`Value::Counter32`], [`Value::Gauge32`], [`Value::TimeTicks`]), or
    /// non-negative [`Value::Integer`]. Returns `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// // Counter64 is the primary use case
    /// assert_eq!(Value::Counter64(10_000_000_000).as_u64(), Some(10_000_000_000));
    ///
    /// // Also works for 32-bit unsigned types
    /// assert_eq!(Value::Counter32(100).as_u64(), Some(100));
    /// assert_eq!(Value::Gauge32(200).as_u64(), Some(200));
    ///
    /// // Non-negative integers work
    /// assert_eq!(Value::Integer(50).as_u64(), Some(50));
    ///
    /// // Negative integers return None
    /// assert_eq!(Value::Integer(-1).as_u64(), None);
    /// ```
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Counter64(v) => Some(*v),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => Some(*v as u64),
            Value::Integer(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    /// Try to get as bytes.
    ///
    /// Returns `Some(&[u8])` for [`Value::OctetString`] or [`Value::Opaque`].
    /// Returns `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// let v = Value::OctetString(Bytes::from_static(b"hello"));
    /// assert_eq!(v.as_bytes(), Some(b"hello".as_slice()));
    ///
    /// // Works for Opaque too
    /// let v = Value::Opaque(Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]));
    /// assert_eq!(v.as_bytes(), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    ///
    /// // Other types return None
    /// assert_eq!(Value::Integer(42).as_bytes(), None);
    /// ```
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::OctetString(v) | Value::Opaque(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as string (UTF-8).
    ///
    /// Returns `Some(&str)` if the value is an [`Value::OctetString`] or [`Value::Opaque`]
    /// containing valid UTF-8. Returns `None` for other types or invalid UTF-8.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// let v = Value::OctetString(Bytes::from_static(b"Linux router1 5.4.0"));
    /// assert_eq!(v.as_str(), Some("Linux router1 5.4.0"));
    ///
    /// // Invalid UTF-8 returns None
    /// let v = Value::OctetString(Bytes::from_static(&[0xFF, 0xFE]));
    /// assert_eq!(v.as_str(), None);
    ///
    /// // Binary data with valid UTF-8 bytes still works, but use as_bytes() for clarity
    /// let binary = Value::OctetString(Bytes::from_static(&[0x80, 0x81, 0x82]));
    /// assert_eq!(binary.as_str(), None); // Invalid UTF-8 sequence
    /// assert!(binary.as_bytes().is_some());
    /// ```
    pub fn as_str(&self) -> Option<&str> {
        self.as_bytes().and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Try to get as OID.
    ///
    /// Returns `Some(&Oid)` for [`Value::ObjectIdentifier`], `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::{Value, oid};
    ///
    /// let v = Value::ObjectIdentifier(oid!(1, 3, 6, 1, 2, 1, 1, 2, 0));
    /// let oid = v.as_oid().unwrap();
    /// assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.2.0");
    ///
    /// // Other types return None
    /// assert_eq!(Value::Integer(42).as_oid(), None);
    /// ```
    pub fn as_oid(&self) -> Option<&Oid> {
        match self {
            Value::ObjectIdentifier(oid) => Some(oid),
            _ => None,
        }
    }

    /// Try to get as IP address.
    ///
    /// Returns `Some(Ipv4Addr)` for [`Value::IpAddress`], `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use std::net::Ipv4Addr;
    ///
    /// let v = Value::IpAddress([192, 168, 1, 1]);
    /// assert_eq!(v.as_ip(), Some(Ipv4Addr::new(192, 168, 1, 1)));
    ///
    /// // Other types return None
    /// assert_eq!(Value::Integer(42).as_ip(), None);
    /// ```
    pub fn as_ip(&self) -> Option<std::net::Ipv4Addr> {
        match self {
            Value::IpAddress(bytes) => Some(std::net::Ipv4Addr::from(*bytes)),
            _ => None,
        }
    }

    /// Check if this is an exception value.
    pub fn is_exception(&self) -> bool {
        matches!(
            self,
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView
        )
    }

    /// Format an OctetString or Opaque value using RFC 2579 DISPLAY-HINT.
    ///
    /// Returns `None` if this is not an OctetString or Opaque value.
    /// On invalid hint syntax, falls back to hex encoding.
    ///
    /// # Example
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// let mac = Value::OctetString(Bytes::from_static(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
    /// assert_eq!(mac.format_with_hint("1x:"), Some("00:1a:2b:3c:4d:5e".into()));
    ///
    /// let integer = Value::Integer(42);
    /// assert_eq!(integer.format_with_hint("1d"), None);
    /// ```
    pub fn format_with_hint(&self, hint: &str) -> Option<String> {
        match self {
            Value::OctetString(bytes) => Some(crate::format::display_hint::apply(hint, bytes)),
            Value::Opaque(bytes) => Some(crate::format::display_hint::apply(hint, bytes)),
            _ => None,
        }
    }

    /// Encode to BER.
    pub fn encode(&self, buf: &mut EncodeBuf) {
        match self {
            Value::Integer(v) => buf.push_integer(*v),
            Value::OctetString(data) => buf.push_octet_string(data),
            Value::Null => buf.push_null(),
            Value::ObjectIdentifier(oid) => buf.push_oid(oid),
            Value::IpAddress(addr) => buf.push_ip_address(*addr),
            Value::Counter32(v) => buf.push_unsigned32(tag::application::COUNTER32, *v),
            Value::Gauge32(v) => buf.push_unsigned32(tag::application::GAUGE32, *v),
            Value::TimeTicks(v) => buf.push_unsigned32(tag::application::TIMETICKS, *v),
            Value::Opaque(data) => {
                buf.push_bytes(data);
                buf.push_length(data.len());
                buf.push_tag(tag::application::OPAQUE);
            }
            Value::Counter64(v) => buf.push_integer64(*v),
            Value::NoSuchObject => {
                buf.push_length(0);
                buf.push_tag(tag::context::NO_SUCH_OBJECT);
            }
            Value::NoSuchInstance => {
                buf.push_length(0);
                buf.push_tag(tag::context::NO_SUCH_INSTANCE);
            }
            Value::EndOfMibView => {
                buf.push_length(0);
                buf.push_tag(tag::context::END_OF_MIB_VIEW);
            }
            Value::Unknown { tag: t, data } => {
                buf.push_bytes(data);
                buf.push_length(data.len());
                buf.push_tag(*t);
            }
        }
    }

    /// Decode from BER.
    pub fn decode(decoder: &mut Decoder) -> Result<Self> {
        let tag = decoder.read_tag()?;
        let len = decoder.read_length()?;

        match tag {
            tag::universal::INTEGER => {
                let value = decoder.read_integer_value(len)?;
                Ok(Value::Integer(value))
            }
            tag::universal::OCTET_STRING => {
                let data = decoder.read_bytes(len)?;
                Ok(Value::OctetString(data))
            }
            tag::universal::NULL => {
                if len != 0 {
                    return Err(Error::decode(
                        decoder.offset(),
                        DecodeErrorKind::InvalidNull,
                    ));
                }
                Ok(Value::Null)
            }
            tag::universal::OBJECT_IDENTIFIER => {
                let oid = decoder.read_oid_value(len)?;
                Ok(Value::ObjectIdentifier(oid))
            }
            tag::application::IP_ADDRESS => {
                if len != 4 {
                    return Err(Error::decode(
                        decoder.offset(),
                        DecodeErrorKind::InvalidIpAddressLength { length: len },
                    ));
                }
                let data = decoder.read_bytes(4)?;
                Ok(Value::IpAddress([data[0], data[1], data[2], data[3]]))
            }
            tag::application::COUNTER32 => {
                let value = decoder.read_unsigned32_value(len)?;
                Ok(Value::Counter32(value))
            }
            tag::application::GAUGE32 => {
                let value = decoder.read_unsigned32_value(len)?;
                Ok(Value::Gauge32(value))
            }
            tag::application::TIMETICKS => {
                let value = decoder.read_unsigned32_value(len)?;
                Ok(Value::TimeTicks(value))
            }
            tag::application::OPAQUE => {
                let data = decoder.read_bytes(len)?;
                Ok(Value::Opaque(data))
            }
            tag::application::COUNTER64 => {
                let value = decoder.read_integer64_value(len)?;
                Ok(Value::Counter64(value))
            }
            tag::context::NO_SUCH_OBJECT => {
                if len != 0 {
                    let _ = decoder.read_bytes(len)?;
                }
                Ok(Value::NoSuchObject)
            }
            tag::context::NO_SUCH_INSTANCE => {
                if len != 0 {
                    let _ = decoder.read_bytes(len)?;
                }
                Ok(Value::NoSuchInstance)
            }
            tag::context::END_OF_MIB_VIEW => {
                if len != 0 {
                    let _ = decoder.read_bytes(len)?;
                }
                Ok(Value::EndOfMibView)
            }
            // Reject constructed OCTET STRING (0x24).
            // Net-snmp documents but does not parse constructed form; we follow suit.
            tag::universal::OCTET_STRING_CONSTRUCTED => Err(Error::decode(
                decoder.offset(),
                DecodeErrorKind::ConstructedOctetString,
            )),
            _ => {
                // Unknown tag - preserve for forward compatibility
                let data = decoder.read_bytes(len)?;
                Ok(Value::Unknown { tag, data })
            }
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Integer(v) => write!(f, "{}", v),
            Value::OctetString(data) => {
                // Try to display as string if it's valid UTF-8
                if let Ok(s) = std::str::from_utf8(data) {
                    write!(f, "{}", s)
                } else {
                    write!(f, "0x{}", hex::encode(data))
                }
            }
            Value::Null => write!(f, "NULL"),
            Value::ObjectIdentifier(oid) => write!(f, "{}", oid),
            Value::IpAddress(addr) => {
                write!(f, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            Value::Counter32(v) => write!(f, "{}", v),
            Value::Gauge32(v) => write!(f, "{}", v),
            Value::TimeTicks(v) => {
                // Display as time
                let secs = v / 100;
                let days = secs / 86400;
                let hours = (secs % 86400) / 3600;
                let mins = (secs % 3600) / 60;
                let s = secs % 60;
                write!(f, "{}d {}h {}m {}s", days, hours, mins, s)
            }
            Value::Opaque(data) => write!(f, "Opaque(0x{})", hex::encode(data)),
            Value::Counter64(v) => write!(f, "{}", v),
            Value::NoSuchObject => write!(f, "noSuchObject"),
            Value::NoSuchInstance => write!(f, "noSuchInstance"),
            Value::EndOfMibView => write!(f, "endOfMibView"),
            Value::Unknown { tag, data } => {
                write!(
                    f,
                    "Unknown(tag=0x{:02X}, data=0x{})",
                    tag,
                    hex::encode(data)
                )
            }
        }
    }
}

/// Convenience conversions for creating [`Value`] from common Rust types.
///
/// # Examples
///
/// ```
/// use async_snmp::Value;
/// use bytes::Bytes;
///
/// // From integers
/// let v: Value = 42i32.into();
/// assert_eq!(v.as_i32(), Some(42));
///
/// // From strings (creates OctetString)
/// let v: Value = "hello".into();
/// assert_eq!(v.as_str(), Some("hello"));
///
/// // From String
/// let v: Value = String::from("world").into();
/// assert_eq!(v.as_str(), Some("world"));
///
/// // From byte slices
/// let v: Value = (&[1u8, 2, 3][..]).into();
/// assert_eq!(v.as_bytes(), Some(&[1, 2, 3][..]));
///
/// // From Bytes
/// let v: Value = Bytes::from_static(b"data").into();
/// assert_eq!(v.as_bytes(), Some(b"data".as_slice()));
///
/// // From u64 (creates Counter64)
/// let v: Value = 10_000_000_000u64.into();
/// assert_eq!(v.as_u64(), Some(10_000_000_000));
///
/// // From Ipv4Addr
/// use std::net::Ipv4Addr;
/// let v: Value = Ipv4Addr::new(10, 0, 0, 1).into();
/// assert_eq!(v.as_ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
///
/// // From [u8; 4] (creates IpAddress)
/// let v: Value = [192u8, 168, 1, 1].into();
/// assert!(matches!(v, Value::IpAddress([192, 168, 1, 1])));
/// ```
impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Integer(v)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::OctetString(Bytes::copy_from_slice(s.as_bytes()))
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::OctetString(Bytes::from(s))
    }
}

impl From<&[u8]> for Value {
    fn from(data: &[u8]) -> Self {
        Value::OctetString(Bytes::copy_from_slice(data))
    }
}

impl From<Oid> for Value {
    fn from(oid: Oid) -> Self {
        Value::ObjectIdentifier(oid)
    }
}

impl From<std::net::Ipv4Addr> for Value {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Value::IpAddress(addr.octets())
    }
}

impl From<Bytes> for Value {
    fn from(data: Bytes) -> Self {
        Value::OctetString(data)
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Counter64(v)
    }
}

impl From<[u8; 4]> for Value {
    fn from(addr: [u8; 4]) -> Self {
        Value::IpAddress(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // AUDIT-003: Test that constructed OCTET STRING (0x24) is explicitly rejected.
    // Net-snmp documents but does not parse constructed form; we reject it.
    #[test]
    fn test_reject_constructed_octet_string() {
        // Constructed OCTET STRING has tag 0x24 (0x04 | 0x20)
        // Create a fake BER-encoded constructed OCTET STRING: 0x24 0x03 0x04 0x01 0x41
        // (constructed OCTET STRING containing primitive OCTET STRING "A")
        let data = bytes::Bytes::from_static(&[0x24, 0x03, 0x04, 0x01, 0x41]);
        let mut decoder = Decoder::new(data);
        let result = Value::decode(&mut decoder);

        assert!(
            result.is_err(),
            "constructed OCTET STRING (0x24) should be rejected"
        );
        let err = result.unwrap_err();
        let err_msg = format!("{}", err);
        assert!(
            err_msg.contains("constructed OCTET STRING"),
            "error message should mention 'constructed OCTET STRING', got: {}",
            err_msg
        );
    }

    #[test]
    fn test_primitive_octet_string_accepted() {
        // Primitive OCTET STRING (0x04) should be accepted
        let data = bytes::Bytes::from_static(&[0x04, 0x03, 0x41, 0x42, 0x43]); // "ABC"
        let mut decoder = Decoder::new(data);
        let result = Value::decode(&mut decoder);

        assert!(result.is_ok(), "primitive OCTET STRING should be accepted");
        let value = result.unwrap();
        assert_eq!(value.as_bytes(), Some(&b"ABC"[..]));
    }

    // ========================================================================
    // Value Type Encoding/Decoding Tests
    // ========================================================================

    fn roundtrip(value: Value) -> Value {
        let mut buf = EncodeBuf::new();
        value.encode(&mut buf);
        let data = buf.finish();
        let mut decoder = Decoder::new(data);
        Value::decode(&mut decoder).unwrap()
    }

    #[test]
    fn test_integer_positive() {
        let value = Value::Integer(42);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_integer_negative() {
        let value = Value::Integer(-42);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_integer_zero() {
        let value = Value::Integer(0);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_integer_min() {
        let value = Value::Integer(i32::MIN);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_integer_max() {
        let value = Value::Integer(i32::MAX);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_octet_string_ascii() {
        let value = Value::OctetString(Bytes::from_static(b"hello world"));
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_octet_string_binary() {
        let value = Value::OctetString(Bytes::from_static(&[0x00, 0xFF, 0x80, 0x7F]));
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_octet_string_empty() {
        let value = Value::OctetString(Bytes::new());
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_null() {
        let value = Value::Null;
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_object_identifier() {
        let value = Value::ObjectIdentifier(crate::oid!(1, 3, 6, 1, 2, 1, 1, 1, 0));
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_ip_address() {
        let value = Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_ip_address_zero() {
        let value = Value::IpAddress([0, 0, 0, 0]);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_ip_address_broadcast() {
        let value = Value::IpAddress([255, 255, 255, 255]);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_counter32() {
        let value = Value::Counter32(999999);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_counter32_zero() {
        let value = Value::Counter32(0);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_counter32_max() {
        let value = Value::Counter32(u32::MAX);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_gauge32() {
        let value = Value::Gauge32(1000000000);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_gauge32_max() {
        let value = Value::Gauge32(u32::MAX);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_timeticks() {
        let value = Value::TimeTicks(123456);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_timeticks_max() {
        let value = Value::TimeTicks(u32::MAX);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_opaque() {
        let value = Value::Opaque(Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_opaque_empty() {
        let value = Value::Opaque(Bytes::new());
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_counter64() {
        let value = Value::Counter64(123456789012345);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_counter64_zero() {
        let value = Value::Counter64(0);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_counter64_max() {
        let value = Value::Counter64(u64::MAX);
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_no_such_object() {
        let value = Value::NoSuchObject;
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_no_such_instance() {
        let value = Value::NoSuchInstance;
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_end_of_mib_view() {
        let value = Value::EndOfMibView;
        assert_eq!(roundtrip(value.clone()), value);
    }

    #[test]
    fn test_unknown_tag_preserved() {
        // Tag 0x45 is application class but not a standard SNMP type
        let data = Bytes::from_static(&[0x45, 0x03, 0x01, 0x02, 0x03]);
        let mut decoder = Decoder::new(data);
        let value = Value::decode(&mut decoder).unwrap();

        match value {
            Value::Unknown { tag, ref data } => {
                assert_eq!(tag, 0x45);
                assert_eq!(data.as_ref(), &[0x01, 0x02, 0x03]);
            }
            _ => panic!("expected Unknown variant"),
        }

        // Roundtrip should preserve
        assert_eq!(roundtrip(value.clone()), value);
    }

    // ========================================================================
    // Accessor Method Tests
    // ========================================================================

    #[test]
    fn test_as_i32() {
        assert_eq!(Value::Integer(42).as_i32(), Some(42));
        assert_eq!(Value::Integer(-42).as_i32(), Some(-42));
        assert_eq!(Value::Counter32(100).as_i32(), None);
        assert_eq!(Value::Null.as_i32(), None);
    }

    #[test]
    fn test_as_u32() {
        assert_eq!(Value::Counter32(100).as_u32(), Some(100));
        assert_eq!(Value::Gauge32(200).as_u32(), Some(200));
        assert_eq!(Value::TimeTicks(300).as_u32(), Some(300));
        assert_eq!(Value::Integer(50).as_u32(), Some(50));
        assert_eq!(Value::Integer(-1).as_u32(), None);
        assert_eq!(Value::Counter64(100).as_u32(), None);
    }

    #[test]
    fn test_as_u64() {
        assert_eq!(Value::Counter64(100).as_u64(), Some(100));
        assert_eq!(Value::Counter32(100).as_u64(), Some(100));
        assert_eq!(Value::Gauge32(200).as_u64(), Some(200));
        assert_eq!(Value::TimeTicks(300).as_u64(), Some(300));
        assert_eq!(Value::Integer(50).as_u64(), Some(50));
        assert_eq!(Value::Integer(-1).as_u64(), None);
    }

    #[test]
    fn test_as_bytes() {
        let s = Value::OctetString(Bytes::from_static(b"test"));
        assert_eq!(s.as_bytes(), Some(b"test".as_slice()));

        let o = Value::Opaque(Bytes::from_static(b"data"));
        assert_eq!(o.as_bytes(), Some(b"data".as_slice()));

        assert_eq!(Value::Integer(1).as_bytes(), None);
    }

    #[test]
    fn test_as_str() {
        let s = Value::OctetString(Bytes::from_static(b"hello"));
        assert_eq!(s.as_str(), Some("hello"));

        // Invalid UTF-8 returns None
        let invalid = Value::OctetString(Bytes::from_static(&[0xFF, 0xFE]));
        assert_eq!(invalid.as_str(), None);

        assert_eq!(Value::Integer(1).as_str(), None);
    }

    #[test]
    fn test_as_oid() {
        let oid = crate::oid!(1, 3, 6, 1);
        let v = Value::ObjectIdentifier(oid.clone());
        assert_eq!(v.as_oid(), Some(&oid));

        assert_eq!(Value::Integer(1).as_oid(), None);
    }

    #[test]
    fn test_as_ip() {
        let v = Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(v.as_ip(), Some(std::net::Ipv4Addr::new(192, 168, 1, 1)));

        assert_eq!(Value::Integer(1).as_ip(), None);
    }

    // ========================================================================
    // is_exception() Tests
    // ========================================================================

    #[test]
    fn test_is_exception() {
        assert!(Value::NoSuchObject.is_exception());
        assert!(Value::NoSuchInstance.is_exception());
        assert!(Value::EndOfMibView.is_exception());

        assert!(!Value::Integer(1).is_exception());
        assert!(!Value::Null.is_exception());
        assert!(!Value::OctetString(Bytes::new()).is_exception());
    }

    // ========================================================================
    // Display Trait Tests
    // ========================================================================

    #[test]
    fn test_display_integer() {
        assert_eq!(format!("{}", Value::Integer(42)), "42");
        assert_eq!(format!("{}", Value::Integer(-42)), "-42");
    }

    #[test]
    fn test_display_octet_string_utf8() {
        let v = Value::OctetString(Bytes::from_static(b"hello"));
        assert_eq!(format!("{}", v), "hello");
    }

    #[test]
    fn test_display_octet_string_binary() {
        // Use bytes that are not valid UTF-8 (0xFF is never valid in UTF-8)
        let v = Value::OctetString(Bytes::from_static(&[0xFF, 0xFE]));
        assert_eq!(format!("{}", v), "0xfffe");
    }

    #[test]
    fn test_display_null() {
        assert_eq!(format!("{}", Value::Null), "NULL");
    }

    #[test]
    fn test_display_ip_address() {
        let v = Value::IpAddress([192, 168, 1, 1]);
        assert_eq!(format!("{}", v), "192.168.1.1");
    }

    #[test]
    fn test_display_counter32() {
        assert_eq!(format!("{}", Value::Counter32(999)), "999");
    }

    #[test]
    fn test_display_gauge32() {
        assert_eq!(format!("{}", Value::Gauge32(1000)), "1000");
    }

    #[test]
    fn test_display_timeticks() {
        // 123456 hundredths = 1234.56 seconds
        // = 0d 0h 20m 34s
        let v = Value::TimeTicks(123456);
        assert_eq!(format!("{}", v), "0d 0h 20m 34s");
    }

    #[test]
    fn test_display_opaque() {
        let v = Value::Opaque(Bytes::from_static(&[0xBE, 0xEF]));
        assert_eq!(format!("{}", v), "Opaque(0xbeef)");
    }

    #[test]
    fn test_display_counter64() {
        assert_eq!(format!("{}", Value::Counter64(12345678)), "12345678");
    }

    #[test]
    fn test_display_exceptions() {
        assert_eq!(format!("{}", Value::NoSuchObject), "noSuchObject");
        assert_eq!(format!("{}", Value::NoSuchInstance), "noSuchInstance");
        assert_eq!(format!("{}", Value::EndOfMibView), "endOfMibView");
    }

    #[test]
    fn test_display_unknown() {
        let v = Value::Unknown {
            tag: 0x99,
            data: Bytes::from_static(&[0x01, 0x02]),
        };
        assert_eq!(format!("{}", v), "Unknown(tag=0x99, data=0x0102)");
    }

    // ========================================================================
    // From Conversion Tests
    // ========================================================================

    #[test]
    fn test_from_i32() {
        let v: Value = 42i32.into();
        assert_eq!(v, Value::Integer(42));
    }

    #[test]
    fn test_from_str() {
        let v: Value = "hello".into();
        assert_eq!(v.as_str(), Some("hello"));
    }

    #[test]
    fn test_from_string() {
        let v: Value = String::from("hello").into();
        assert_eq!(v.as_str(), Some("hello"));
    }

    #[test]
    fn test_from_bytes_slice() {
        let v: Value = (&[1u8, 2, 3][..]).into();
        assert_eq!(v.as_bytes(), Some(&[1u8, 2, 3][..]));
    }

    #[test]
    fn test_from_oid() {
        let oid = crate::oid!(1, 3, 6, 1);
        let v: Value = oid.clone().into();
        assert_eq!(v.as_oid(), Some(&oid));
    }

    #[test]
    fn test_from_ipv4addr() {
        let addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
        let v: Value = addr.into();
        assert_eq!(v, Value::IpAddress([10, 0, 0, 1]));
    }

    #[test]
    fn test_from_bytes() {
        let data = Bytes::from_static(b"hello");
        let v: Value = data.into();
        assert_eq!(v.as_bytes(), Some(b"hello".as_slice()));
    }

    #[test]
    fn test_from_u64() {
        let v: Value = 12345678901234u64.into();
        assert_eq!(v, Value::Counter64(12345678901234));
    }

    #[test]
    fn test_from_ip_array() {
        let v: Value = [192u8, 168, 1, 1].into();
        assert_eq!(v, Value::IpAddress([192, 168, 1, 1]));
    }

    // ========================================================================
    // Decode Error Tests
    // ========================================================================

    #[test]
    fn test_decode_invalid_null_length() {
        // NULL must have length 0
        let data = Bytes::from_static(&[0x05, 0x01, 0x00]); // NULL with length 1
        let mut decoder = Decoder::new(data);
        let result = Value::decode(&mut decoder);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_invalid_ip_address_length() {
        // IpAddress must have length 4
        let data = Bytes::from_static(&[0x40, 0x03, 0x01, 0x02, 0x03]); // Only 3 bytes
        let mut decoder = Decoder::new(data);
        let result = Value::decode(&mut decoder);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_exception_with_content_accepted() {
        // Per implementation, exceptions with non-zero length have content skipped
        let data = Bytes::from_static(&[0x80, 0x01, 0xFF]); // NoSuchObject with 1 byte
        let mut decoder = Decoder::new(data);
        let result = Value::decode(&mut decoder);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::NoSuchObject);
    }
}
