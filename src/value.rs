//! SNMP value types.
//!
//! The `Value` enum represents all SNMP data types including exceptions.

use crate::ber::{Decoder, EncodeBuf, tag};
use crate::error::internal::DecodeErrorKind;
use crate::error::{Error, Result, UNKNOWN_TARGET};
use crate::format::hex;
use crate::oid::Oid;
use bytes::Bytes;

/// RFC 2579 RowStatus textual convention.
///
/// Used by SNMP tables to control row creation, modification, and deletion.
/// The state machine for RowStatus is defined in RFC 2579 Section 7.1.
///
/// # State Transitions
///
/// | Current State | Set to | Result |
/// |--------------|--------|--------|
/// | (none) | createAndGo | row created in `active` state |
/// | (none) | createAndWait | row created in `notInService` or `notReady` |
/// | notInService | active | row becomes operational |
/// | notReady | active | error (row must first be notInService) |
/// | active | notInService | row becomes inactive |
/// | any | destroy | row is deleted |
///
/// # Example
///
/// ```
/// use async_snmp::{Value, RowStatus};
///
/// // Reading a RowStatus column
/// let value = Value::Integer(1);
/// assert_eq!(value.as_row_status(), Some(RowStatus::Active));
///
/// // Creating a value to write
/// let create: Value = RowStatus::CreateAndGo.into();
/// assert_eq!(create, Value::Integer(4));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowStatus {
    /// Row is operational and available for use.
    Active = 1,
    /// Row exists but is not operational (e.g., being modified).
    NotInService = 2,
    /// Row exists but required columns are missing or invalid.
    NotReady = 3,
    /// Request to create a new row that immediately becomes active.
    CreateAndGo = 4,
    /// Request to create a new row that starts in notInService/notReady.
    CreateAndWait = 5,
    /// Request to delete an existing row.
    Destroy = 6,
}

impl RowStatus {
    /// Convert an integer value to RowStatus.
    ///
    /// Returns `None` for values outside the valid range (1-6).
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Active),
            2 => Some(Self::NotInService),
            3 => Some(Self::NotReady),
            4 => Some(Self::CreateAndGo),
            5 => Some(Self::CreateAndWait),
            6 => Some(Self::Destroy),
            _ => None,
        }
    }
}

impl From<RowStatus> for Value {
    fn from(status: RowStatus) -> Self {
        Value::Integer(status as i32)
    }
}

impl std::fmt::Display for RowStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::NotInService => write!(f, "notInService"),
            Self::NotReady => write!(f, "notReady"),
            Self::CreateAndGo => write!(f, "createAndGo"),
            Self::CreateAndWait => write!(f, "createAndWait"),
            Self::Destroy => write!(f, "destroy"),
        }
    }
}

/// RFC 2579 StorageType textual convention.
///
/// Describes how an SNMP row's data is stored and persisted.
///
/// # Persistence Levels
///
/// | Type | Survives Reboot | Writable |
/// |------|-----------------|----------|
/// | other | undefined | varies |
/// | volatile | no | yes |
/// | nonVolatile | yes | yes |
/// | permanent | yes | limited |
/// | readOnly | yes | no |
///
/// # Example
///
/// ```
/// use async_snmp::{Value, StorageType};
///
/// // Reading a StorageType column
/// let value = Value::Integer(3);
/// assert_eq!(value.as_storage_type(), Some(StorageType::NonVolatile));
///
/// // Creating a value to write
/// let storage: Value = StorageType::Volatile.into();
/// assert_eq!(storage, Value::Integer(2));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageType {
    /// Implementation-specific storage.
    Other = 1,
    /// Lost on reboot; can be modified.
    Volatile = 2,
    /// Survives reboot; can be modified.
    NonVolatile = 3,
    /// Survives reboot; limited modifications allowed.
    Permanent = 4,
    /// Survives reboot; cannot be modified.
    ReadOnly = 5,
}

impl StorageType {
    /// Convert an integer value to StorageType.
    ///
    /// Returns `None` for values outside the valid range (1-5).
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            1 => Some(Self::Other),
            2 => Some(Self::Volatile),
            3 => Some(Self::NonVolatile),
            4 => Some(Self::Permanent),
            5 => Some(Self::ReadOnly),
            _ => None,
        }
    }
}

impl From<StorageType> for Value {
    fn from(storage: StorageType) -> Self {
        Value::Integer(storage as i32)
    }
}

impl std::fmt::Display for StorageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other => write!(f, "other"),
            Self::Volatile => write!(f, "volatile"),
            Self::NonVolatile => write!(f, "nonVolatile"),
            Self::Permanent => write!(f, "permanent"),
            Self::ReadOnly => write!(f, "readOnly"),
        }
    }
}

/// SNMP value.
///
/// Represents all SNMP data types including SMIv2 types and exception values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// Extract any numeric value as f64.
    ///
    /// Useful for metrics systems and graphing where all values become f64.
    /// Counter64 values above 2^53 may lose precision.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// assert_eq!(Value::Integer(42).as_f64(), Some(42.0));
    /// assert_eq!(Value::Counter32(1000).as_f64(), Some(1000.0));
    /// assert_eq!(Value::Counter64(10_000_000_000).as_f64(), Some(10_000_000_000.0));
    /// assert_eq!(Value::Null.as_f64(), None);
    /// ```
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Integer(v) => Some(*v as f64),
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => Some(*v as f64),
            Value::Counter64(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Extract Counter64 as f64 with wrapping at 2^53.
    ///
    /// Prevents precision loss for large counters. IEEE 754 double-precision
    /// floats have a 53-bit mantissa, so Counter64 values above 2^53 lose
    /// precision when converted directly. This method wraps at the mantissa
    /// limit, preserving precision for rate calculations.
    ///
    /// Use when computing rates where precision matters more than absolute
    /// magnitude. For Counter32 and other types, behaves identically to `as_f64()`.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// // Small values behave the same as as_f64()
    /// assert_eq!(Value::Counter64(1000).as_f64_wrapped(), Some(1000.0));
    ///
    /// // Large Counter64 wraps at 2^53
    /// let large = 1u64 << 54; // 2^54
    /// let wrapped = Value::Counter64(large).as_f64_wrapped().unwrap();
    /// assert!(wrapped < large as f64); // Wrapped to smaller value
    /// ```
    pub fn as_f64_wrapped(&self) -> Option<f64> {
        const MANTISSA_LIMIT: u64 = 1 << 53;
        match self {
            Value::Counter64(v) => Some((*v % MANTISSA_LIMIT) as f64),
            _ => self.as_f64(),
        }
    }

    /// Extract integer with implied decimal places.
    ///
    /// Many SNMP sensors report fixed-point values as integers with an
    /// implied decimal point. This method applies the scaling directly,
    /// returning a usable f64 value.
    ///
    /// This complements `format_with_hint("d-2")` which returns a String
    /// for display. Use `as_decimal()` when you need the numeric value
    /// for computation or metrics.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// // Temperature 2350 with places=2 → 23.50
    /// assert_eq!(Value::Integer(2350).as_decimal(2), Some(23.50));
    ///
    /// // Percentage 9999 with places=2 → 99.99
    /// assert_eq!(Value::Integer(9999).as_decimal(2), Some(99.99));
    ///
    /// // Voltage 12500 with places=3 → 12.500
    /// assert_eq!(Value::Integer(12500).as_decimal(3), Some(12.5));
    ///
    /// // Non-numeric types return None
    /// assert_eq!(Value::Null.as_decimal(2), None);
    /// ```
    pub fn as_decimal(&self, places: u8) -> Option<f64> {
        let divisor = 10f64.powi(places as i32);
        self.as_f64().map(|v| v / divisor)
    }

    /// TimeTicks as Duration (hundredths of seconds).
    ///
    /// TimeTicks represents time in hundredths of a second. This method
    /// converts to `std::time::Duration` for idiomatic Rust time handling.
    ///
    /// Common use: sysUpTime, interface last-change timestamps.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use std::time::Duration;
    ///
    /// // 360000 ticks = 3600 seconds = 1 hour
    /// let uptime = Value::TimeTicks(360000);
    /// assert_eq!(uptime.as_duration(), Some(Duration::from_secs(3600)));
    ///
    /// // Non-TimeTicks return None
    /// assert_eq!(Value::Integer(100).as_duration(), None);
    /// ```
    pub fn as_duration(&self) -> Option<std::time::Duration> {
        match self {
            Value::TimeTicks(v) => Some(std::time::Duration::from_millis(*v as u64 * 10)),
            _ => None,
        }
    }

    /// Extract IEEE 754 float from Opaque value (net-snmp extension).
    ///
    /// Decodes the two-layer ASN.1 structure used by net-snmp to encode floats
    /// inside Opaque values: extension tag (0x9f) + float type (0x78) + length (4)
    /// + 4 bytes IEEE 754 big-endian float.
    ///
    /// This is a non-standard extension supported by net-snmp for agents that
    /// need to report floating-point values. Standard SNMP uses implied decimal
    /// points via DISPLAY-HINT instead.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// // Opaque-encoded float for pi
    /// let data = Bytes::from_static(&[0x9f, 0x78, 0x04, 0x40, 0x49, 0x0f, 0xdb]);
    /// let value = Value::Opaque(data);
    /// let pi = value.as_opaque_float().unwrap();
    /// assert!((pi - std::f32::consts::PI).abs() < 0.0001);
    ///
    /// // Non-Opaque or wrong format returns None
    /// assert_eq!(Value::Integer(42).as_opaque_float(), None);
    /// ```
    pub fn as_opaque_float(&self) -> Option<f32> {
        match self {
            Value::Opaque(data)
                if data.len() >= 7
                && data[0] == 0x9f       // ASN_OPAQUE_TAG1 (extension)
                && data[1] == 0x78       // ASN_OPAQUE_FLOAT
                && data[2] == 0x04 =>
            {
                // length = 4
                let bytes: [u8; 4] = data[3..7].try_into().ok()?;
                Some(f32::from_be_bytes(bytes))
            }
            _ => None,
        }
    }

    /// Extract IEEE 754 double from Opaque value (net-snmp extension).
    ///
    /// Decodes the two-layer ASN.1 structure used by net-snmp to encode doubles
    /// inside Opaque values: extension tag (0x9f) + double type (0x79) + length (8)
    /// + 8 bytes IEEE 754 big-endian double.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// // Opaque-encoded double for pi ≈ 3.141592653589793
    /// let data = Bytes::from_static(&[
    ///     0x9f, 0x79, 0x08,  // extension tag, double type, length
    ///     0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18  // IEEE 754 double
    /// ]);
    /// let value = Value::Opaque(data);
    /// let pi = value.as_opaque_double().unwrap();
    /// assert!((pi - std::f64::consts::PI).abs() < 1e-10);
    /// ```
    pub fn as_opaque_double(&self) -> Option<f64> {
        match self {
            Value::Opaque(data)
                if data.len() >= 11
                && data[0] == 0x9f       // ASN_OPAQUE_TAG1 (extension)
                && data[1] == 0x79       // ASN_OPAQUE_DOUBLE
                && data[2] == 0x08 =>
            {
                // length = 8
                let bytes: [u8; 8] = data[3..11].try_into().ok()?;
                Some(f64::from_be_bytes(bytes))
            }
            _ => None,
        }
    }

    /// Extract Counter64 from Opaque value (net-snmp extension for SNMPv1).
    ///
    /// SNMPv1 doesn't support Counter64 natively. net-snmp encodes 64-bit
    /// counters inside Opaque for SNMPv1 compatibility using extension tag
    /// (0x9f) + counter64 type (0x76) + length + big-endian bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// // Opaque-encoded Counter64 with value 0x0123456789ABCDEF
    /// let data = Bytes::from_static(&[
    ///     0x9f, 0x76, 0x08,  // extension tag, counter64 type, length
    ///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    /// ]);
    /// let value = Value::Opaque(data);
    /// assert_eq!(value.as_opaque_counter64(), Some(0x0123456789ABCDEF));
    /// ```
    pub fn as_opaque_counter64(&self) -> Option<u64> {
        self.as_opaque_unsigned(0x76)
    }

    /// Extract signed 64-bit integer from Opaque value (net-snmp extension).
    ///
    /// Uses extension tag (0x9f) + i64 type (0x7a) + length + big-endian bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// // Opaque-encoded I64 with value -1 (0xFFFFFFFFFFFFFFFF)
    /// let data = Bytes::from_static(&[
    ///     0x9f, 0x7a, 0x08,
    ///     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    /// ]);
    /// let value = Value::Opaque(data);
    /// assert_eq!(value.as_opaque_i64(), Some(-1i64));
    /// ```
    pub fn as_opaque_i64(&self) -> Option<i64> {
        match self {
            Value::Opaque(data)
                if data.len() >= 4
                && data[0] == 0x9f       // ASN_OPAQUE_TAG1 (extension)
                && data[1] == 0x7a =>
            {
                // ASN_OPAQUE_I64
                let len = data[2] as usize;
                if data.len() < 3 + len || len == 0 || len > 8 {
                    return None;
                }
                let bytes = &data[3..3 + len];
                // Sign-extend from the actual length
                let is_negative = bytes[0] & 0x80 != 0;
                let mut value: i64 = if is_negative { -1 } else { 0 };
                for &byte in bytes {
                    value = (value << 8) | (byte as i64);
                }
                Some(value)
            }
            _ => None,
        }
    }

    /// Extract unsigned 64-bit integer from Opaque value (net-snmp extension).
    ///
    /// Uses extension tag (0x9f) + u64 type (0x7b) + length + big-endian bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// // Opaque-encoded U64 with value 0x0123456789ABCDEF
    /// let data = Bytes::from_static(&[
    ///     0x9f, 0x7b, 0x08,
    ///     0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    /// ]);
    /// let value = Value::Opaque(data);
    /// assert_eq!(value.as_opaque_u64(), Some(0x0123456789ABCDEF));
    /// ```
    pub fn as_opaque_u64(&self) -> Option<u64> {
        self.as_opaque_unsigned(0x7b)
    }

    /// Helper for extracting unsigned 64-bit values from Opaque (Counter64, U64).
    fn as_opaque_unsigned(&self, expected_type: u8) -> Option<u64> {
        match self {
            Value::Opaque(data)
                if data.len() >= 4
                && data[0] == 0x9f           // ASN_OPAQUE_TAG1 (extension)
                && data[1] == expected_type =>
            {
                let len = data[2] as usize;
                if data.len() < 3 + len || len == 0 || len > 8 {
                    return None;
                }
                let bytes = &data[3..3 + len];
                let mut value: u64 = 0;
                for &byte in bytes {
                    value = (value << 8) | (byte as u64);
                }
                Some(value)
            }
            _ => None,
        }
    }

    /// Extract RFC 2579 TruthValue as bool.
    ///
    /// TruthValue is an INTEGER with: true(1), false(2).
    /// Returns `None` for non-Integer values or values outside {1, 2}.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::Value;
    ///
    /// assert_eq!(Value::Integer(1).as_truth_value(), Some(true));
    /// assert_eq!(Value::Integer(2).as_truth_value(), Some(false));
    ///
    /// // Invalid values return None
    /// assert_eq!(Value::Integer(0).as_truth_value(), None);
    /// assert_eq!(Value::Integer(3).as_truth_value(), None);
    /// assert_eq!(Value::Null.as_truth_value(), None);
    /// ```
    pub fn as_truth_value(&self) -> Option<bool> {
        match self {
            Value::Integer(1) => Some(true),
            Value::Integer(2) => Some(false),
            _ => None,
        }
    }

    /// Extract RFC 2579 RowStatus.
    ///
    /// Returns `None` for non-Integer values or values outside {1-6}.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::{Value, RowStatus};
    ///
    /// assert_eq!(Value::Integer(1).as_row_status(), Some(RowStatus::Active));
    /// assert_eq!(Value::Integer(6).as_row_status(), Some(RowStatus::Destroy));
    ///
    /// // Invalid values return None
    /// assert_eq!(Value::Integer(0).as_row_status(), None);
    /// assert_eq!(Value::Integer(7).as_row_status(), None);
    /// assert_eq!(Value::Null.as_row_status(), None);
    /// ```
    pub fn as_row_status(&self) -> Option<RowStatus> {
        match self {
            Value::Integer(v) => RowStatus::from_i32(*v),
            _ => None,
        }
    }

    /// Extract RFC 2579 StorageType.
    ///
    /// Returns `None` for non-Integer values or values outside {1-5}.
    ///
    /// # Examples
    ///
    /// ```
    /// use async_snmp::{Value, StorageType};
    ///
    /// assert_eq!(Value::Integer(2).as_storage_type(), Some(StorageType::Volatile));
    /// assert_eq!(Value::Integer(3).as_storage_type(), Some(StorageType::NonVolatile));
    ///
    /// // Invalid values return None
    /// assert_eq!(Value::Integer(0).as_storage_type(), None);
    /// assert_eq!(Value::Integer(6).as_storage_type(), None);
    /// assert_eq!(Value::Null.as_storage_type(), None);
    /// ```
    pub fn as_storage_type(&self) -> Option<StorageType> {
        match self {
            Value::Integer(v) => StorageType::from_i32(*v),
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

    /// Returns the total BER-encoded length (tag + length + content).
    pub(crate) fn ber_encoded_len(&self) -> usize {
        use crate::ber::{
            integer_content_len, length_encoded_len, unsigned32_content_len, unsigned64_content_len,
        };

        match self {
            Value::Integer(v) => {
                let content_len = integer_content_len(*v);
                1 + length_encoded_len(content_len) + content_len
            }
            Value::OctetString(data) => {
                let content_len = data.len();
                1 + length_encoded_len(content_len) + content_len
            }
            Value::Null => 2, // tag + length(0)
            Value::ObjectIdentifier(oid) => oid.ber_encoded_len(),
            Value::IpAddress(_) => 6, // tag + length(4) + 4 bytes
            Value::Counter32(v) | Value::Gauge32(v) | Value::TimeTicks(v) => {
                let content_len = unsigned32_content_len(*v);
                1 + length_encoded_len(content_len) + content_len
            }
            Value::Opaque(data) => {
                let content_len = data.len();
                1 + length_encoded_len(content_len) + content_len
            }
            Value::Counter64(v) => {
                let content_len = unsigned64_content_len(*v);
                1 + length_encoded_len(content_len) + content_len
            }
            Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView => 2, // tag + length(0)
            Value::Unknown { data, .. } => {
                let content_len = data.len();
                1 + length_encoded_len(content_len) + content_len
            }
        }
    }

    /// Format an OctetString, Opaque, or Integer value using RFC 2579 DISPLAY-HINT.
    ///
    /// For OctetString and Opaque, uses the OCTET STRING hint format (e.g., "1x:").
    /// For Integer, uses the INTEGER hint format (e.g., "d-2" for decimal places).
    ///
    /// Returns `None` for other value types or invalid hint syntax.
    /// On invalid OCTET STRING hint syntax, falls back to hex encoding.
    ///
    /// # Example
    ///
    /// ```
    /// use async_snmp::Value;
    /// use bytes::Bytes;
    ///
    /// // OctetString: MAC address
    /// let mac = Value::OctetString(Bytes::from_static(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
    /// assert_eq!(mac.format_with_hint("1x:"), Some("00:1a:2b:3c:4d:5e".into()));
    ///
    /// // Integer: Temperature with 2 decimal places
    /// let temp = Value::Integer(2350);
    /// assert_eq!(temp.format_with_hint("d-2"), Some("23.50".into()));
    ///
    /// // Integer: Hex format
    /// let int = Value::Integer(255);
    /// assert_eq!(int.format_with_hint("x"), Some("ff".into()));
    /// ```
    pub fn format_with_hint(&self, hint: &str) -> Option<String> {
        match self {
            Value::OctetString(bytes) => Some(crate::format::display_hint::apply(hint, bytes)),
            Value::Opaque(bytes) => Some(crate::format::display_hint::apply(hint, bytes)),
            Value::Integer(v) => crate::format::display_hint::apply_integer(hint, *v),
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
                    tracing::debug!(target: "async_snmp::value", { offset = decoder.offset(), kind = %DecodeErrorKind::InvalidNull }, "decode error");
                    return Err(Error::MalformedResponse {
                        target: UNKNOWN_TARGET,
                    }
                    .boxed());
                }
                Ok(Value::Null)
            }
            tag::universal::OBJECT_IDENTIFIER => {
                let oid = decoder.read_oid_value(len)?;
                Ok(Value::ObjectIdentifier(oid))
            }
            tag::application::IP_ADDRESS => {
                if len != 4 {
                    tracing::debug!(target: "async_snmp::value", { offset = decoder.offset(), length = len, kind = %DecodeErrorKind::InvalidIpAddressLength { length: len } }, "decode error");
                    return Err(Error::MalformedResponse {
                        target: UNKNOWN_TARGET,
                    }
                    .boxed());
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
            tag::universal::OCTET_STRING_CONSTRUCTED => {
                tracing::debug!(target: "async_snmp::value", { offset = decoder.offset(), kind = %DecodeErrorKind::ConstructedOctetString }, "decode error");
                Err(Error::MalformedResponse {
                    target: UNKNOWN_TARGET,
                }
                .boxed())
            }
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
                write!(f, "{}", crate::format::format_timeticks(*v))
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

/// Converts a 4-byte array into [`Value::IpAddress`].
///
/// The bytes are interpreted as a big-endian IPv4 address, matching the IpAddress
/// SNMP type (RFC 2578 Section 7.1.5). Use this when you already have an address
/// in `[u8; 4]` form (e.g., from `Ipv4Addr::octets()`).
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
        // Verify error is MalformedResponse (detailed error kind is logged via tracing)
        let err = result.unwrap_err();
        assert!(
            matches!(&*err, crate::Error::MalformedResponse { .. }),
            "expected MalformedResponse error, got: {:?}",
            err
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
        // 123456 hundredths = 1234.56 seconds = 20m 34.56s
        let v = Value::TimeTicks(123456);
        assert_eq!(format!("{}", v), "00:20:34.56");
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
    // Eq and Hash Tests
    // ========================================================================

    #[test]
    fn test_value_eq_and_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(Value::Integer(42));
        set.insert(Value::Integer(42)); // Duplicate
        set.insert(Value::Integer(100));

        assert_eq!(set.len(), 2);
        assert!(set.contains(&Value::Integer(42)));
        assert!(set.contains(&Value::Integer(100)));
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

    // ========================================================================
    // Numeric Extraction Method Tests
    // ========================================================================

    #[test]
    fn test_as_f64() {
        assert_eq!(Value::Integer(42).as_f64(), Some(42.0));
        assert_eq!(Value::Integer(-42).as_f64(), Some(-42.0));
        assert_eq!(Value::Counter32(1000).as_f64(), Some(1000.0));
        assert_eq!(Value::Gauge32(2000).as_f64(), Some(2000.0));
        assert_eq!(Value::TimeTicks(3000).as_f64(), Some(3000.0));
        assert_eq!(
            Value::Counter64(10_000_000_000).as_f64(),
            Some(10_000_000_000.0)
        );
        assert_eq!(Value::Null.as_f64(), None);
        assert_eq!(
            Value::OctetString(Bytes::from_static(b"test")).as_f64(),
            None
        );
    }

    #[test]
    fn test_as_f64_wrapped() {
        // Small values behave same as as_f64()
        assert_eq!(Value::Counter64(1000).as_f64_wrapped(), Some(1000.0));
        assert_eq!(Value::Counter32(1000).as_f64_wrapped(), Some(1000.0));
        assert_eq!(Value::Integer(42).as_f64_wrapped(), Some(42.0));

        // Large Counter64 wraps at 2^53
        let mantissa_limit = 1u64 << 53;
        assert_eq!(Value::Counter64(mantissa_limit).as_f64_wrapped(), Some(0.0));
        assert_eq!(
            Value::Counter64(mantissa_limit + 1).as_f64_wrapped(),
            Some(1.0)
        );
    }

    #[test]
    fn test_as_decimal() {
        assert_eq!(Value::Integer(2350).as_decimal(2), Some(23.50));
        assert_eq!(Value::Integer(9999).as_decimal(2), Some(99.99));
        assert_eq!(Value::Integer(12500).as_decimal(3), Some(12.5));
        assert_eq!(Value::Integer(-500).as_decimal(2), Some(-5.0));
        assert_eq!(Value::Counter32(1000).as_decimal(1), Some(100.0));
        assert_eq!(Value::Null.as_decimal(2), None);
    }

    #[test]
    fn test_as_duration() {
        use std::time::Duration;

        // 100 ticks = 1 second
        assert_eq!(
            Value::TimeTicks(100).as_duration(),
            Some(Duration::from_secs(1))
        );
        // 360000 ticks = 3600 seconds = 1 hour
        assert_eq!(
            Value::TimeTicks(360000).as_duration(),
            Some(Duration::from_secs(3600))
        );
        // 1 tick = 10 milliseconds
        assert_eq!(
            Value::TimeTicks(1).as_duration(),
            Some(Duration::from_millis(10))
        );

        // Non-TimeTicks return None
        assert_eq!(Value::Integer(100).as_duration(), None);
        assert_eq!(Value::Counter32(100).as_duration(), None);
    }

    // ========================================================================
    // Opaque Sub-type Extraction Tests
    // ========================================================================

    #[test]
    fn test_as_opaque_float() {
        // Opaque-encoded float for pi ≈ 3.14159
        // 0x40490fdb is IEEE 754 single-precision for ~3.14159
        let data = Bytes::from_static(&[0x9f, 0x78, 0x04, 0x40, 0x49, 0x0f, 0xdb]);
        let value = Value::Opaque(data);
        let pi = value.as_opaque_float().unwrap();
        assert!((pi - std::f32::consts::PI).abs() < 0.0001);

        // Non-Opaque returns None
        assert_eq!(Value::Integer(42).as_opaque_float(), None);

        // Wrong subtype returns None
        let wrong_type = Bytes::from_static(&[0x9f, 0x79, 0x04, 0x40, 0x49, 0x0f, 0xdb]);
        assert_eq!(Value::Opaque(wrong_type).as_opaque_float(), None);

        // Too short returns None
        let short = Bytes::from_static(&[0x9f, 0x78, 0x04, 0x40, 0x49]);
        assert_eq!(Value::Opaque(short).as_opaque_float(), None);
    }

    #[test]
    fn test_as_opaque_double() {
        // Opaque-encoded double for pi
        // 0x400921fb54442d18 is IEEE 754 double-precision for pi
        let data = Bytes::from_static(&[
            0x9f, 0x79, 0x08, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18,
        ]);
        let value = Value::Opaque(data);
        let pi = value.as_opaque_double().unwrap();
        assert!((pi - std::f64::consts::PI).abs() < 1e-10);

        // Non-Opaque returns None
        assert_eq!(Value::Integer(42).as_opaque_double(), None);
    }

    #[test]
    fn test_as_opaque_counter64() {
        // 8-byte Counter64
        let data = Bytes::from_static(&[
            0x9f, 0x76, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]);
        let value = Value::Opaque(data);
        assert_eq!(value.as_opaque_counter64(), Some(0x0123456789ABCDEF));

        // Shorter encoding (e.g., small value)
        let small = Bytes::from_static(&[0x9f, 0x76, 0x01, 0x42]);
        assert_eq!(Value::Opaque(small).as_opaque_counter64(), Some(0x42));

        // Zero
        let zero = Bytes::from_static(&[0x9f, 0x76, 0x01, 0x00]);
        assert_eq!(Value::Opaque(zero).as_opaque_counter64(), Some(0));
    }

    #[test]
    fn test_as_opaque_i64() {
        // Positive value
        let positive = Bytes::from_static(&[0x9f, 0x7a, 0x02, 0x01, 0x00]);
        assert_eq!(Value::Opaque(positive).as_opaque_i64(), Some(256));

        // Negative value (-1)
        let minus_one = Bytes::from_static(&[0x9f, 0x7a, 0x01, 0xFF]);
        assert_eq!(Value::Opaque(minus_one).as_opaque_i64(), Some(-1));

        // Full 8-byte negative
        let full_neg = Bytes::from_static(&[
            0x9f, 0x7a, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        assert_eq!(Value::Opaque(full_neg).as_opaque_i64(), Some(-1));

        // i64::MIN
        let min = Bytes::from_static(&[
            0x9f, 0x7a, 0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(Value::Opaque(min).as_opaque_i64(), Some(i64::MIN));
    }

    #[test]
    fn test_as_opaque_u64() {
        // 8-byte U64
        let data = Bytes::from_static(&[
            0x9f, 0x7b, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ]);
        let value = Value::Opaque(data);
        assert_eq!(value.as_opaque_u64(), Some(0x0123456789ABCDEF));

        // u64::MAX
        let max = Bytes::from_static(&[
            0x9f, 0x7b, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ]);
        assert_eq!(Value::Opaque(max).as_opaque_u64(), Some(u64::MAX));
    }

    #[test]
    fn test_format_with_hint_integer() {
        // Decimal places
        assert_eq!(
            Value::Integer(2350).format_with_hint("d-2"),
            Some("23.50".into())
        );
        assert_eq!(
            Value::Integer(-500).format_with_hint("d-2"),
            Some("-5.00".into())
        );

        // Basic formats
        assert_eq!(Value::Integer(255).format_with_hint("x"), Some("ff".into()));
        assert_eq!(Value::Integer(8).format_with_hint("o"), Some("10".into()));
        assert_eq!(Value::Integer(5).format_with_hint("b"), Some("101".into()));
        assert_eq!(Value::Integer(42).format_with_hint("d"), Some("42".into()));

        // Invalid hint
        assert_eq!(Value::Integer(42).format_with_hint("invalid"), None);

        // Counter32 etc. still return None (only Integer supported for INTEGER hints)
        assert_eq!(Value::Counter32(42).format_with_hint("d-2"), None);
    }

    #[test]
    fn test_as_truth_value() {
        // Valid TruthValue
        assert_eq!(Value::Integer(1).as_truth_value(), Some(true));
        assert_eq!(Value::Integer(2).as_truth_value(), Some(false));

        // Invalid integers
        assert_eq!(Value::Integer(0).as_truth_value(), None);
        assert_eq!(Value::Integer(3).as_truth_value(), None);
        assert_eq!(Value::Integer(-1).as_truth_value(), None);

        // Non-Integer types
        assert_eq!(Value::Null.as_truth_value(), None);
        assert_eq!(Value::Counter32(1).as_truth_value(), None);
        assert_eq!(Value::Gauge32(1).as_truth_value(), None);
    }

    // ========================================================================
    // RowStatus Tests
    // ========================================================================

    #[test]
    fn test_row_status_from_i32() {
        assert_eq!(RowStatus::from_i32(1), Some(RowStatus::Active));
        assert_eq!(RowStatus::from_i32(2), Some(RowStatus::NotInService));
        assert_eq!(RowStatus::from_i32(3), Some(RowStatus::NotReady));
        assert_eq!(RowStatus::from_i32(4), Some(RowStatus::CreateAndGo));
        assert_eq!(RowStatus::from_i32(5), Some(RowStatus::CreateAndWait));
        assert_eq!(RowStatus::from_i32(6), Some(RowStatus::Destroy));

        // Invalid values
        assert_eq!(RowStatus::from_i32(0), None);
        assert_eq!(RowStatus::from_i32(7), None);
        assert_eq!(RowStatus::from_i32(-1), None);
    }

    #[test]
    fn test_row_status_into_value() {
        let v: Value = RowStatus::Active.into();
        assert_eq!(v, Value::Integer(1));

        let v: Value = RowStatus::Destroy.into();
        assert_eq!(v, Value::Integer(6));
    }

    #[test]
    fn test_row_status_display() {
        assert_eq!(format!("{}", RowStatus::Active), "active");
        assert_eq!(format!("{}", RowStatus::NotInService), "notInService");
        assert_eq!(format!("{}", RowStatus::NotReady), "notReady");
        assert_eq!(format!("{}", RowStatus::CreateAndGo), "createAndGo");
        assert_eq!(format!("{}", RowStatus::CreateAndWait), "createAndWait");
        assert_eq!(format!("{}", RowStatus::Destroy), "destroy");
    }

    #[test]
    fn test_as_row_status() {
        // Valid RowStatus values
        assert_eq!(Value::Integer(1).as_row_status(), Some(RowStatus::Active));
        assert_eq!(Value::Integer(6).as_row_status(), Some(RowStatus::Destroy));

        // Invalid integers
        assert_eq!(Value::Integer(0).as_row_status(), None);
        assert_eq!(Value::Integer(7).as_row_status(), None);

        // Non-Integer types
        assert_eq!(Value::Null.as_row_status(), None);
        assert_eq!(Value::Counter32(1).as_row_status(), None);
    }

    // ========================================================================
    // StorageType Tests
    // ========================================================================

    #[test]
    fn test_storage_type_from_i32() {
        assert_eq!(StorageType::from_i32(1), Some(StorageType::Other));
        assert_eq!(StorageType::from_i32(2), Some(StorageType::Volatile));
        assert_eq!(StorageType::from_i32(3), Some(StorageType::NonVolatile));
        assert_eq!(StorageType::from_i32(4), Some(StorageType::Permanent));
        assert_eq!(StorageType::from_i32(5), Some(StorageType::ReadOnly));

        // Invalid values
        assert_eq!(StorageType::from_i32(0), None);
        assert_eq!(StorageType::from_i32(6), None);
        assert_eq!(StorageType::from_i32(-1), None);
    }

    #[test]
    fn test_storage_type_into_value() {
        let v: Value = StorageType::Volatile.into();
        assert_eq!(v, Value::Integer(2));

        let v: Value = StorageType::NonVolatile.into();
        assert_eq!(v, Value::Integer(3));
    }

    #[test]
    fn test_storage_type_display() {
        assert_eq!(format!("{}", StorageType::Other), "other");
        assert_eq!(format!("{}", StorageType::Volatile), "volatile");
        assert_eq!(format!("{}", StorageType::NonVolatile), "nonVolatile");
        assert_eq!(format!("{}", StorageType::Permanent), "permanent");
        assert_eq!(format!("{}", StorageType::ReadOnly), "readOnly");
    }

    #[test]
    fn test_as_storage_type() {
        // Valid StorageType values
        assert_eq!(
            Value::Integer(2).as_storage_type(),
            Some(StorageType::Volatile)
        );
        assert_eq!(
            Value::Integer(3).as_storage_type(),
            Some(StorageType::NonVolatile)
        );

        // Invalid integers
        assert_eq!(Value::Integer(0).as_storage_type(), None);
        assert_eq!(Value::Integer(6).as_storage_type(), None);

        // Non-Integer types
        assert_eq!(Value::Null.as_storage_type(), None);
        assert_eq!(Value::Counter32(1).as_storage_type(), None);
    }
}
