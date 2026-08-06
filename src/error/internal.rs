//! Internal error types for tracing and debugging.
//!
//! These types are not part of the public API. They are used internally
//! to provide detailed diagnostic information via tracing.

/// Authentication error kinds (`SNMPv3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthErrorKind {
    /// No credentials configured for this operation.
    NoCredentials,
    /// No authentication key available.
    NoAuthKey,
    /// HMAC verification failed.
    HmacMismatch,
    /// Could not locate auth params in message.
    AuthParamsNotFound,
}

impl std::fmt::Display for AuthErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredentials => write!(f, "no credentials configured"),
            Self::NoAuthKey => write!(f, "no authentication key available"),
            Self::HmacMismatch => write!(f, "HMAC verification failed"),
            Self::AuthParamsNotFound => write!(f, "could not locate auth params in message"),
        }
    }
}

/// Cryptographic error kinds (encryption/decryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoErrorKind {
    /// No privacy key available.
    NoPrivKey,
}

impl std::fmt::Display for CryptoErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPrivKey => write!(f, "no privacy key available"),
        }
    }
}

/// BER decode error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeErrorKind {
    /// Expected different tag.
    UnexpectedTag { expected: u8, actual: u8 },
    /// Data truncated unexpectedly.
    TruncatedData,
    /// Invalid BER length encoding.
    InvalidLength,
    /// Indefinite length not supported.
    IndefiniteLength,
    /// Integer value overflow.
    IntegerOverflow,
    /// Integer value outside a field's ASN.1 constraint.
    IntegerOutOfRange {
        value: i64,
        minimum: i32,
        maximum: i32,
    },
    /// Zero-length integer.
    ZeroLengthInteger,
    /// Unknown SNMP version.
    UnknownVersion(i32),
    /// Unknown PDU type.
    UnknownPduType(u8),
    /// Constructed OCTET STRING not supported.
    ConstructedOctetString,
    /// Missing required PDU.
    MissingPdu,
    /// Invalid msgFlags (priv without auth).
    InvalidMsgFlags,
    /// Unknown security model.
    UnknownSecurityModel(i32),
    /// msgUserName exceeds RFC 3414 maximum length (SIZE(0..32)).
    InvalidUserNameLength { length: usize },
    /// NULL with non-zero length.
    InvalidNull,
    /// Invalid IP address length.
    InvalidIpAddressLength { length: usize },
    /// Length field too long.
    LengthTooLong { octets: usize },
    /// Length exceeds maximum.
    LengthExceedsMax { length: usize, max: usize },
    /// Integer64 too long.
    Integer64TooLong { length: usize },
    /// Empty response.
    EmptyResponse,
    /// TLV extends past end of data.
    TlvOverflow,
    /// Insufficient data for read.
    InsufficientData { needed: usize, available: usize },
    /// Invalid OID in notification varbinds.
    InvalidOid,
    /// OID exceeds maximum arc count during decode.
    OidTooLong { count: usize, max: usize },
    /// Signed integer encoding exceeds 4 bytes.
    IntegerTooLong { length: usize },
    /// Unsigned 32-bit integer encoding exceeds 5 bytes.
    Unsigned32TooLong { length: usize },
    /// 9-octet integer64 encoding is missing required leading zero byte.
    Integer64MissingLeadingZero,
    /// 5-octet unsigned32 encoding is missing required leading zero byte.
    Unsigned32MissingLeadingZero,
}

impl std::fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedTag { expected, actual } => {
                write!(f, "expected tag 0x{expected:02X}, got 0x{actual:02X}")
            }
            Self::TruncatedData => write!(f, "unexpected end of data"),
            Self::InvalidLength => write!(f, "invalid length encoding"),
            Self::IndefiniteLength => write!(f, "indefinite length encoding not supported"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::IntegerOutOfRange {
                value,
                minimum,
                maximum,
            } => write!(
                f,
                "integer {value} outside constrained range {minimum}..{maximum}"
            ),
            Self::ZeroLengthInteger => write!(f, "zero-length integer"),
            Self::UnknownVersion(v) => write!(f, "unknown SNMP version: {v}"),
            Self::UnknownPduType(t) => write!(f, "unknown PDU type: 0x{t:02X}"),
            Self::ConstructedOctetString => {
                write!(f, "constructed OCTET STRING (0x24) not supported")
            }
            Self::MissingPdu => write!(f, "missing PDU in message"),
            Self::InvalidMsgFlags => write!(f, "invalid msgFlags: privacy without authentication"),
            Self::UnknownSecurityModel(m) => write!(f, "unknown security model: {m}"),
            Self::InvalidUserNameLength { length } => {
                write!(f, "msgUserName length {length} exceeds maximum 32")
            }
            Self::InvalidNull => write!(f, "NULL with non-zero length"),
            Self::InvalidIpAddressLength { length } => {
                write!(f, "IP address must be 4 bytes, got {length}")
            }
            Self::LengthTooLong { octets } => {
                write!(f, "length encoding too long ({octets} octets)")
            }
            Self::LengthExceedsMax { length, max } => {
                write!(f, "length {length} exceeds maximum {max}")
            }
            Self::Integer64TooLong { length } => {
                write!(f, "integer64 too long: {length} bytes")
            }
            Self::EmptyResponse => write!(f, "empty response"),
            Self::TlvOverflow => write!(f, "TLV extends past end of data"),
            Self::InsufficientData { needed, available } => {
                write!(f, "need {needed} bytes but only {available} remaining")
            }
            Self::InvalidOid => write!(f, "invalid OID in notification varbinds"),
            Self::OidTooLong { count, max } => {
                write!(f, "OID has {count} arcs, exceeds maximum {max}")
            }
            Self::IntegerTooLong { length } => {
                write!(f, "integer encoding too long: {length} bytes (max 8)")
            }
            Self::Unsigned32TooLong { length } => {
                write!(f, "unsigned32 encoding too long: {length} bytes (max 9)")
            }
            Self::Integer64MissingLeadingZero => {
                write!(f, "9-octet integer64 missing required leading zero byte")
            }
            Self::Unsigned32MissingLeadingZero => {
                write!(f, "5-octet unsigned32 missing required leading zero byte")
            }
        }
    }
}

/// BER encode error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeErrorKind {
    /// Could not locate auth params position in encoded message.
    MissingAuthParams,
}

impl std::fmt::Display for EncodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthParams => {
                write!(f, "could not find auth params position in encoded message")
            }
        }
    }
}
