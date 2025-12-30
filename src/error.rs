//! Error types for async-snmp.
//!
//! All errors are `#[non_exhaustive]` to allow adding new variants without breaking changes.

use std::net::SocketAddr;
use std::time::Duration;

/// Result type alias using the library's Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Authentication error kinds (SNMPv3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthErrorKind {
    /// No credentials configured for this operation.
    NoCredentials,
    /// No authentication key available.
    NoAuthKey,
    /// User not found in USM table.
    NoUser,
    /// HMAC verification failed.
    HmacMismatch,
    /// Authentication parameters wrong length.
    WrongMacLength { expected: usize, actual: usize },
    /// Could not locate auth params in message.
    AuthParamsNotFound,
}

impl std::fmt::Display for AuthErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredentials => write!(f, "no credentials configured"),
            Self::NoAuthKey => write!(f, "no authentication key available"),
            Self::NoUser => write!(f, "user not found"),
            Self::HmacMismatch => write!(f, "HMAC verification failed"),
            Self::WrongMacLength { expected, actual } => {
                write!(f, "wrong MAC length: expected {}, got {}", expected, actual)
            }
            Self::AuthParamsNotFound => write!(f, "could not locate auth params in message"),
        }
    }
}

/// Cryptographic error kinds (encryption/decryption).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoErrorKind {
    /// No privacy key available.
    NoPrivKey,
    /// Invalid padding in decrypted data.
    InvalidPadding,
    /// Invalid key length for cipher.
    InvalidKeyLength,
    /// Invalid IV length for cipher.
    InvalidIvLength,
    /// Cipher operation failed.
    CipherError,
    /// Unsupported privacy protocol.
    UnsupportedProtocol,
    /// Invalid priv params length.
    InvalidPrivParamsLength { expected: usize, actual: usize },
    /// Ciphertext length not a multiple of block size.
    InvalidCiphertextLength { length: usize, block_size: usize },
}

impl std::fmt::Display for CryptoErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPrivKey => write!(f, "no privacy key available"),
            Self::InvalidPadding => write!(f, "invalid padding"),
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::InvalidIvLength => write!(f, "invalid IV length"),
            Self::CipherError => write!(f, "cipher operation failed"),
            Self::UnsupportedProtocol => write!(f, "unsupported privacy protocol"),
            Self::InvalidPrivParamsLength { expected, actual } => {
                write!(
                    f,
                    "invalid privParameters length: expected {}, got {}",
                    expected, actual
                )
            }
            Self::InvalidCiphertextLength { length, block_size } => {
                write!(
                    f,
                    "ciphertext length {} not multiple of block size {}",
                    length, block_size
                )
            }
        }
    }
}

/// BER decode error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeErrorKind {
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
    /// Invalid OID encoding.
    InvalidOidEncoding,
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
            Self::InvalidOidEncoding => write!(f, "invalid OID encoding"),
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
        }
    }
}

/// BER encode error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeErrorKind {
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

/// OID validation error kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidErrorKind {
    /// Empty OID string.
    Empty,
    /// Invalid arc value.
    InvalidArc,
    /// First arc must be 0, 1, or 2.
    InvalidFirstArc(u32),
    /// Second arc too large for first arc value.
    InvalidSecondArc { first: u32, second: u32 },
    /// OID too short (minimum 2 arcs).
    TooShort,
    /// OID has too many arcs (exceeds MAX_OID_LEN).
    TooManyArcs { count: usize, max: usize },
    /// Subidentifier overflow during encoding.
    SubidentifierOverflow,
}

impl std::fmt::Display for OidErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "empty OID"),
            Self::InvalidArc => write!(f, "invalid arc value"),
            Self::InvalidFirstArc(v) => write!(f, "first arc must be 0, 1, or 2, got {}", v),
            Self::InvalidSecondArc { first, second } => {
                write!(f, "second arc {} too large for first arc {}", second, first)
            }
            Self::TooShort => write!(f, "OID must have at least 2 arcs"),
            Self::TooManyArcs { count, max } => {
                write!(f, "OID has {} arcs, exceeds maximum {}", count, max)
            }
            Self::SubidentifierOverflow => write!(f, "subidentifier overflow"),
        }
    }
}

/// SNMP error status codes (RFC 3416).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorStatus {
    NoError,
    TooBig,
    NoSuchName,
    BadValue,
    ReadOnly,
    GenErr,
    NoAccess,
    WrongType,
    WrongLength,
    WrongEncoding,
    WrongValue,
    NoCreation,
    InconsistentValue,
    ResourceUnavailable,
    CommitFailed,
    UndoFailed,
    AuthorizationError,
    NotWritable,
    InconsistentName,
    /// Unknown/future error status code.
    Unknown(i32),
}

impl ErrorStatus {
    /// Create from raw status code.
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::NoError,
            1 => Self::TooBig,
            2 => Self::NoSuchName,
            3 => Self::BadValue,
            4 => Self::ReadOnly,
            5 => Self::GenErr,
            6 => Self::NoAccess,
            7 => Self::WrongType,
            8 => Self::WrongLength,
            9 => Self::WrongEncoding,
            10 => Self::WrongValue,
            11 => Self::NoCreation,
            12 => Self::InconsistentValue,
            13 => Self::ResourceUnavailable,
            14 => Self::CommitFailed,
            15 => Self::UndoFailed,
            16 => Self::AuthorizationError,
            17 => Self::NotWritable,
            18 => Self::InconsistentName,
            other => Self::Unknown(other),
        }
    }

    /// Convert to raw status code.
    pub fn as_i32(&self) -> i32 {
        match self {
            Self::NoError => 0,
            Self::TooBig => 1,
            Self::NoSuchName => 2,
            Self::BadValue => 3,
            Self::ReadOnly => 4,
            Self::GenErr => 5,
            Self::NoAccess => 6,
            Self::WrongType => 7,
            Self::WrongLength => 8,
            Self::WrongEncoding => 9,
            Self::WrongValue => 10,
            Self::NoCreation => 11,
            Self::InconsistentValue => 12,
            Self::ResourceUnavailable => 13,
            Self::CommitFailed => 14,
            Self::UndoFailed => 15,
            Self::AuthorizationError => 16,
            Self::NotWritable => 17,
            Self::InconsistentName => 18,
            Self::Unknown(code) => *code,
        }
    }
}

impl std::fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoError => write!(f, "noError"),
            Self::TooBig => write!(f, "tooBig"),
            Self::NoSuchName => write!(f, "noSuchName"),
            Self::BadValue => write!(f, "badValue"),
            Self::ReadOnly => write!(f, "readOnly"),
            Self::GenErr => write!(f, "genErr"),
            Self::NoAccess => write!(f, "noAccess"),
            Self::WrongType => write!(f, "wrongType"),
            Self::WrongLength => write!(f, "wrongLength"),
            Self::WrongEncoding => write!(f, "wrongEncoding"),
            Self::WrongValue => write!(f, "wrongValue"),
            Self::NoCreation => write!(f, "noCreation"),
            Self::InconsistentValue => write!(f, "inconsistentValue"),
            Self::ResourceUnavailable => write!(f, "resourceUnavailable"),
            Self::CommitFailed => write!(f, "commitFailed"),
            Self::UndoFailed => write!(f, "undoFailed"),
            Self::AuthorizationError => write!(f, "authorizationError"),
            Self::NotWritable => write!(f, "notWritable"),
            Self::InconsistentName => write!(f, "inconsistentName"),
            Self::Unknown(code) => write!(f, "unknown({})", code),
        }
    }
}

/// Library error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error during communication.
    #[error("I/O error{}: {source}", target.map(|t| format!(" communicating with {}", t)).unwrap_or_default())]
    Io {
        target: Option<SocketAddr>,
        #[source]
        source: std::io::Error,
    },

    /// Request timed out (after retries if configured).
    #[error("timeout after {elapsed:?}{} (request_id={request_id}, retries={retries})", target.map(|t| format!(" waiting for {}", t)).unwrap_or_default())]
    Timeout {
        target: Option<SocketAddr>,
        elapsed: Duration,
        request_id: i32,
        retries: u32,
    },

    /// SNMP protocol error returned by agent.
    #[error("SNMP error{}: {status} at index {index}", target.map(|t| format!(" from {}", t)).unwrap_or_default())]
    Snmp {
        target: Option<SocketAddr>,
        status: ErrorStatus,
        index: u32,
        oid: Option<crate::oid::Oid>,
    },

    /// Invalid OID format.
    #[error("invalid OID: {kind}")]
    InvalidOid {
        kind: OidErrorKind,
        input: Option<Box<str>>, // Only allocated when parsing string input
    },

    /// BER decoding error.
    #[error("decode error at offset {offset}: {kind}")]
    Decode {
        offset: usize,
        kind: DecodeErrorKind,
    },

    /// BER encoding error.
    #[error("encode error: {kind}")]
    Encode { kind: EncodeErrorKind },

    /// Response request ID doesn't match.
    #[error("request ID mismatch: expected {expected}, got {actual}")]
    RequestIdMismatch { expected: i32, actual: i32 },

    /// Response version doesn't match request.
    #[error("version mismatch: expected {expected:?}, got {actual:?}")]
    VersionMismatch {
        expected: crate::version::Version,
        actual: crate::version::Version,
    },

    /// Message exceeds maximum size.
    #[error("message too large: {size} bytes exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    /// Unknown engine ID (SNMPv3).
    #[error("unknown engine ID")]
    UnknownEngineId { target: Option<SocketAddr> },

    /// Message outside time window (SNMPv3).
    #[error("message not in time window")]
    NotInTimeWindow { target: Option<SocketAddr> },

    /// Authentication failed (SNMPv3).
    #[error("authentication failed: {kind}")]
    AuthenticationFailed {
        target: Option<SocketAddr>,
        kind: AuthErrorKind,
    },

    /// Decryption failed (SNMPv3).
    #[error("decryption failed: {kind}")]
    DecryptionFailed {
        target: Option<SocketAddr>,
        kind: CryptoErrorKind,
    },

    /// Encryption failed (SNMPv3).
    #[error("encryption failed: {kind}")]
    EncryptionFailed {
        target: Option<SocketAddr>,
        kind: CryptoErrorKind,
    },

    /// Invalid community string.
    #[error("invalid community")]
    InvalidCommunity { target: Option<SocketAddr> },

    /// Non-increasing OID detected during walk (agent misbehavior).
    ///
    /// Returned when a walk operation receives an OID that is not
    /// lexicographically greater than the previous OID, which would
    /// cause an infinite loop. This indicates a non-conformant SNMP agent.
    #[error("walk detected non-increasing OID: {previous} >= {current}")]
    NonIncreasingOid {
        previous: crate::oid::Oid,
        current: crate::oid::Oid,
    },
}

impl Error {
    /// Create a decode error.
    pub fn decode(offset: usize, kind: DecodeErrorKind) -> Self {
        Self::Decode { offset, kind }
    }

    /// Create an encode error.
    pub fn encode(kind: EncodeErrorKind) -> Self {
        Self::Encode { kind }
    }

    /// Create an authentication error.
    pub fn auth(target: Option<SocketAddr>, kind: AuthErrorKind) -> Self {
        Self::AuthenticationFailed { target, kind }
    }

    /// Create a decryption error.
    pub fn decrypt(target: Option<SocketAddr>, kind: CryptoErrorKind) -> Self {
        Self::DecryptionFailed { target, kind }
    }

    /// Create an encryption error.
    pub fn encrypt(target: Option<SocketAddr>, kind: CryptoErrorKind) -> Self {
        Self::EncryptionFailed { target, kind }
    }

    /// Create an invalid OID error from a kind (no input string).
    pub fn invalid_oid(kind: OidErrorKind) -> Self {
        Self::InvalidOid { kind, input: None }
    }

    /// Create an invalid OID error with the input string that failed.
    pub fn invalid_oid_with_input(kind: OidErrorKind, input: impl Into<Box<str>>) -> Self {
        Self::InvalidOid {
            kind,
            input: Some(input.into()),
        }
    }

    /// Get the target address if this error has one.
    pub fn target(&self) -> Option<SocketAddr> {
        match self {
            Self::Io { target, .. } => *target,
            Self::Timeout { target, .. } => *target,
            Self::Snmp { target, .. } => *target,
            Self::UnknownEngineId { target } => *target,
            Self::NotInTimeWindow { target } => *target,
            Self::AuthenticationFailed { target, .. } => *target,
            Self::DecryptionFailed { target, .. } => *target,
            Self::EncryptionFailed { target, .. } => *target,
            Self::InvalidCommunity { target } => *target,
            _ => None,
        }
    }
}
