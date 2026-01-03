//! Internal error types for tracing and debugging.
//!
//! These types are not part of the public API. They are used internally
//! to provide detailed diagnostic information via tracing.

/// Authentication error kinds (SNMPv3).
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
    /// msgMaxSize below RFC 3412 minimum (484 octets).
    MsgMaxSizeTooSmall { value: i32, minimum: i32 },
    /// msgMaxSize above RFC 3412 maximum (2147483647).
    MsgMaxSizeTooLarge { value: i32 },
    /// msgID outside RFC 3412 range (0..2147483647).
    InvalidMsgId { value: i32 },
    /// msgAuthoritativeEngineBoots outside RFC 3414 range (0..2147483647).
    InvalidEngineBoots { value: i32 },
    /// msgAuthoritativeEngineTime outside RFC 3414 range (0..2147483647).
    InvalidEngineTime { value: i32 },
    /// NULL with non-zero length.
    InvalidNull,
    /// Expected plaintext, got encrypted.
    UnexpectedEncryption,
    /// Expected encrypted, got plaintext.
    ExpectedEncryption,
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
    /// Negative error_index in PDU.
    NegativeErrorIndex { value: i32 },
    /// error_index exceeds number of varbinds.
    ErrorIndexOutOfBounds { index: i32, varbind_count: usize },
    /// Negative non_repeaters in GETBULK PDU.
    NegativeNonRepeaters { value: i32 },
    /// Negative max_repetitions in GETBULK PDU.
    NegativeMaxRepetitions { value: i32 },
    /// OID exceeds maximum arc count during decode.
    OidTooLong { count: usize, max: usize },
}

impl std::fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedTag { expected, actual } => {
                write!(f, "expected tag 0x{:02X}, got 0x{:02X}", expected, actual)
            }
            Self::TruncatedData => write!(f, "unexpected end of data"),
            Self::InvalidLength => write!(f, "invalid length encoding"),
            Self::IndefiniteLength => write!(f, "indefinite length encoding not supported"),
            Self::IntegerOverflow => write!(f, "integer overflow"),
            Self::ZeroLengthInteger => write!(f, "zero-length integer"),
            Self::UnknownVersion(v) => write!(f, "unknown SNMP version: {}", v),
            Self::UnknownPduType(t) => write!(f, "unknown PDU type: 0x{:02X}", t),
            Self::ConstructedOctetString => {
                write!(f, "constructed OCTET STRING (0x24) not supported")
            }
            Self::MissingPdu => write!(f, "missing PDU in message"),
            Self::InvalidMsgFlags => write!(f, "invalid msgFlags: privacy without authentication"),
            Self::UnknownSecurityModel(m) => write!(f, "unknown security model: {}", m),
            Self::MsgMaxSizeTooSmall { value, minimum } => {
                write!(f, "msgMaxSize {} below RFC 3412 minimum {}", value, minimum)
            }
            Self::MsgMaxSizeTooLarge { value } => {
                write!(f, "msgMaxSize {} above RFC 3412 maximum 2147483647", value)
            }
            Self::InvalidMsgId { value } => {
                write!(f, "msgID {} outside RFC 3412 range 0..2147483647", value)
            }
            Self::InvalidEngineBoots { value } => {
                write!(
                    f,
                    "msgAuthoritativeEngineBoots {} outside RFC 3414 range 0..2147483647",
                    value
                )
            }
            Self::InvalidEngineTime { value } => {
                write!(
                    f,
                    "msgAuthoritativeEngineTime {} outside RFC 3414 range 0..2147483647",
                    value
                )
            }
            Self::InvalidNull => write!(f, "NULL with non-zero length"),
            Self::UnexpectedEncryption => write!(f, "expected plaintext scoped PDU"),
            Self::ExpectedEncryption => write!(f, "expected encrypted scoped PDU"),
            Self::InvalidIpAddressLength { length } => {
                write!(f, "IP address must be 4 bytes, got {}", length)
            }
            Self::LengthTooLong { octets } => {
                write!(f, "length encoding too long ({} octets)", octets)
            }
            Self::LengthExceedsMax { length, max } => {
                write!(f, "length {} exceeds maximum {}", length, max)
            }
            Self::Integer64TooLong { length } => {
                write!(f, "integer64 too long: {} bytes", length)
            }
            Self::EmptyResponse => write!(f, "empty response"),
            Self::TlvOverflow => write!(f, "TLV extends past end of data"),
            Self::InsufficientData { needed, available } => {
                write!(f, "need {} bytes but only {} remaining", needed, available)
            }
            Self::InvalidOid => write!(f, "invalid OID in notification varbinds"),
            Self::NegativeErrorIndex { value } => {
                write!(f, "negative error_index: {}", value)
            }
            Self::ErrorIndexOutOfBounds {
                index,
                varbind_count,
            } => {
                write!(
                    f,
                    "error_index {} exceeds varbind count {}",
                    index, varbind_count
                )
            }
            Self::NegativeNonRepeaters { value } => {
                write!(f, "negative non_repeaters: {}", value)
            }
            Self::NegativeMaxRepetitions { value } => {
                write!(f, "negative max_repetitions: {}", value)
            }
            Self::OidTooLong { count, max } => {
                write!(f, "OID has {} arcs, exceeds maximum {}", count, max)
            }
        }
    }
}

/// BER encode error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EncodeErrorKind {
    /// V3 security not configured.
    NoSecurityConfig,
    /// Engine not discovered.
    EngineNotDiscovered,
    /// Keys not derived.
    KeysNotDerived,
    /// Auth key not available for encoding.
    MissingAuthKey,
    /// Privacy key not available.
    NoPrivKey,
    /// Could not locate auth params position in encoded message.
    MissingAuthParams,
}

impl std::fmt::Display for EncodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSecurityConfig => write!(f, "V3 security config not set"),
            Self::EngineNotDiscovered => write!(f, "engine not discovered"),
            Self::KeysNotDerived => write!(f, "keys not derived"),
            Self::MissingAuthKey => write!(f, "auth key not available for encoding"),
            Self::NoPrivKey => write!(f, "privacy key not available"),
            Self::MissingAuthParams => {
                write!(f, "could not find auth params position in encoded message")
            }
        }
    }
}
