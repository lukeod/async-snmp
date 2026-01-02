//! Error types for async-snmp.
//!
//! This module provides comprehensive error handling for SNMP operations, including:
//!
//! - [`Error`] - The main error type for all library operations
//! - [`ErrorStatus`] - SNMP protocol errors returned by agents (RFC 3416)
//! - Helper types for authentication, encryption, and encoding errors
//!
//! All errors are `#[non_exhaustive]` to allow adding new variants without breaking changes.
//!
//! # Error Handling Patterns
//!
//! ## Basic Error Matching
//!
//! Most applications should match on specific error variants to provide appropriate responses:
//!
//! ```no_run
//! use async_snmp::{Auth, Client, Error, ErrorStatus, oid};
//!
//! # async fn example() -> async_snmp::Result<()> {
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .connect()
//!     .await?;
//!
//! match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!     Ok(varbind) => {
//!         println!("Value: {:?}", varbind.value);
//!     }
//!     Err(Error::Timeout { elapsed, retries, .. }) => {
//!         println!("Request timed out after {:?} ({} retries)", elapsed, retries);
//!     }
//!     Err(Error::Snmp { status, index, .. }) => {
//!         println!("SNMP error: {} at index {}", status, index);
//!     }
//!     Err(e) => {
//!         println!("Other error: {}", e);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## SNMP Protocol Errors
//!
//! [`ErrorStatus`] represents errors returned by SNMP agents. Common cases include:
//!
//! ```no_run
//! use async_snmp::{Auth, Client, Error, ErrorStatus, Value, oid};
//!
//! # async fn example() -> async_snmp::Result<()> {
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("private"))
//!     .connect()
//!     .await?;
//!
//! let result = client.set(&oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), Value::from("admin@example.com")).await;
//!
//! if let Err(Error::Snmp { status, oid, .. }) = result {
//!     match status {
//!         ErrorStatus::NoSuchName => {
//!             println!("OID does not exist");
//!         }
//!         ErrorStatus::NotWritable => {
//!             println!("Object is read-only");
//!         }
//!         ErrorStatus::AuthorizationError => {
//!             println!("Access denied - check community string");
//!         }
//!         ErrorStatus::WrongType | ErrorStatus::WrongValue => {
//!             println!("Invalid value for this OID");
//!         }
//!         _ => {
//!             println!("SNMP error: {}", status);
//!         }
//!     }
//!     if let Some(oid) = oid {
//!         println!("Problematic OID: {}", oid);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Timeout Handling
//!
//! Timeouts include retry information to help diagnose connectivity issues:
//!
//! ```no_run
//! use async_snmp::{Auth, Client, Error, Retry, oid};
//! use std::time::Duration;
//!
//! # async fn example() {
//! let client = Client::builder("192.168.1.1:161", Auth::v2c("public"))
//!     .timeout(Duration::from_secs(2))
//!     .retry(Retry::fixed(3, Duration::ZERO))
//!     .connect()
//!     .await
//!     .expect("failed to create client");
//!
//! match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!     Err(Error::Timeout { target, elapsed, request_id, retries }) => {
//!         if let Some(addr) = target {
//!             println!("No response from {} after {:?}", addr, elapsed);
//!         }
//!         println!("Request ID {} failed after {} retries", request_id, retries);
//!         // Consider: is the host reachable? Is SNMP enabled? Is the port correct?
//!     }
//!     _ => {}
//! }
//! # }
//! ```
//!
//! ## SNMPv3 Errors
//!
//! SNMPv3 operations can fail with authentication or encryption errors:
//!
//! ```no_run
//! use async_snmp::{Auth, AuthProtocol, Client, Error, AuthErrorKind, oid};
//!
//! # async fn example() {
//! let client = Client::builder(
//!     "192.168.1.1:161",
//!     Auth::usm("admin").auth(AuthProtocol::Sha256, "wrongpassword"),
//! )
//! .connect()
//! .await
//! .expect("failed to create client");
//!
//! match client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await {
//!     Err(Error::AuthenticationFailed { kind, .. }) => {
//!         match kind {
//!             AuthErrorKind::HmacMismatch => {
//!                 println!("Wrong password or credentials");
//!             }
//!             AuthErrorKind::NoUser => {
//!                 println!("User not configured on agent");
//!             }
//!             _ => {
//!                 println!("Auth failed: {}", kind);
//!             }
//!         }
//!     }
//!     Err(Error::NotInTimeWindow { .. }) => {
//!         println!("Clock skew between client and agent");
//!     }
//!     Err(Error::UnknownEngineId { .. }) => {
//!         println!("Engine discovery failed");
//!     }
//!     _ => {}
//! }
//! # }
//! ```

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

/// SNMP protocol error status codes (RFC 3416).
///
/// These codes are returned by SNMP agents to indicate the result of an operation.
/// The error status is included in the [`Error::Snmp`] variant along with an error
/// index indicating which varbind caused the error.
///
/// # Error Categories
///
/// ## SNMPv1 Errors (0-5)
///
/// - `NoError` - Operation succeeded
/// - `TooBig` - Response too large for transport
/// - `NoSuchName` - OID not found (v1 only; v2c+ uses exceptions)
/// - `BadValue` - Invalid value in SET
/// - `ReadOnly` - Attempted write to read-only object
/// - `GenErr` - Unspecified error
///
/// ## SNMPv2c/v3 Errors (6-18)
///
/// These provide more specific error information for SET operations:
///
/// - `NoAccess` - Object not accessible (access control)
/// - `WrongType` - Value has wrong ASN.1 type
/// - `WrongLength` - Value has wrong length
/// - `WrongValue` - Value out of range or invalid
/// - `NotWritable` - Object does not support SET
/// - `AuthorizationError` - Access denied by VACM
///
/// # Example
///
/// ```
/// use async_snmp::ErrorStatus;
///
/// let status = ErrorStatus::from_i32(2);
/// assert_eq!(status, ErrorStatus::NoSuchName);
/// assert_eq!(status.as_i32(), 2);
/// println!("Error: {}", status); // prints "noSuchName"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorStatus {
    /// Operation completed successfully (status = 0).
    NoError,
    /// Response message would be too large for transport (status = 1).
    TooBig,
    /// Requested OID not found (status = 2). SNMPv1 only; v2c+ uses exception values.
    NoSuchName,
    /// Invalid value provided in SET request (status = 3).
    BadValue,
    /// Attempted to SET a read-only object (status = 4).
    ReadOnly,
    /// Unspecified error occurred (status = 5).
    GenErr,
    /// Object exists but access is denied (status = 6).
    NoAccess,
    /// SET value has wrong ASN.1 type (status = 7).
    WrongType,
    /// SET value has incorrect length (status = 8).
    WrongLength,
    /// SET value uses wrong encoding (status = 9).
    WrongEncoding,
    /// SET value is out of range or otherwise invalid (status = 10).
    WrongValue,
    /// Object does not support row creation (status = 11).
    NoCreation,
    /// Value is inconsistent with other managed objects (status = 12).
    InconsistentValue,
    /// Resource required for SET is unavailable (status = 13).
    ResourceUnavailable,
    /// SET commit phase failed (status = 14).
    CommitFailed,
    /// SET undo phase failed (status = 15).
    UndoFailed,
    /// Access denied by VACM (status = 16).
    AuthorizationError,
    /// Object does not support modification (status = 17).
    NotWritable,
    /// Named object cannot be created (status = 18).
    InconsistentName,
    /// Unknown or future error status code.
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

/// The main error type for all async-snmp operations.
///
/// This enum covers all possible error conditions including network issues,
/// protocol errors, encoding/decoding failures, and SNMPv3 security errors.
///
/// # Common Patterns
///
/// ## Checking Error Type
///
/// Use pattern matching to handle specific error conditions:
///
/// ```
/// use async_snmp::{Error, ErrorStatus};
///
/// fn is_retriable(error: &Error) -> bool {
///     matches!(error,
///         Error::Timeout { .. } |
///         Error::Io { .. } |
///         Error::NotInTimeWindow { .. }
///     )
/// }
///
/// fn is_access_error(error: &Error) -> bool {
///     matches!(error,
///         Error::Snmp { status: ErrorStatus::NoAccess | ErrorStatus::AuthorizationError, .. } |
///         Error::AuthenticationFailed { .. } |
///         Error::InvalidCommunity { .. }
///     )
/// }
/// ```
///
/// ## Extracting Target Address
///
/// Many errors include the target address for diagnostics:
///
/// ```
/// use async_snmp::Error;
///
/// fn log_error(error: &Error) {
///     if let Some(addr) = error.target() {
///         println!("Error from {}: {}", addr, error);
///     } else {
///         println!("Error: {}", error);
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// I/O error during network communication.
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
    ///
    /// Only occurs with `OidOrdering::Strict` (the default).
    #[error("walk detected non-increasing OID: {previous} >= {current}")]
    NonIncreasingOid {
        previous: crate::oid::Oid,
        current: crate::oid::Oid,
    },

    /// Walk detected a cycle (same OID returned twice).
    ///
    /// Only occurs with `OidOrdering::AllowNonIncreasing`, which uses
    /// a HashSet to track all seen OIDs and detect cycles.
    #[error("walk cycle detected: OID {oid} returned twice")]
    DuplicateOid { oid: crate::oid::Oid },

    /// GETBULK not supported in SNMPv1.
    ///
    /// Returned when `WalkMode::GetBulk` is explicitly requested with an SNMPv1 client.
    /// GETBULK is only available in SNMPv2c and SNMPv3.
    #[error("GETBULK is not supported in SNMPv1")]
    GetBulkNotSupportedInV1,

    /// Invalid SNMPv1 trap data.
    ///
    /// Returned when trap PDU fields cannot be converted to valid SNMPv2 format
    /// (e.g., generic_trap overflow, negative specific_trap).
    #[error("invalid trap: {reason}")]
    InvalidTrap { reason: &'static str },

    /// Configuration error.
    ///
    /// Returned when client configuration is invalid (e.g., privacy
    /// without authentication, missing passwords).
    #[error("configuration error: {0}")]
    Config(String),
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
    ///
    /// Returns `Some(addr)` for network-related errors that have a known target,
    /// `None` for errors like OID parsing or encoding that aren't target-specific.
    ///
    /// # Example
    ///
    /// ```
    /// use async_snmp::Error;
    /// use std::time::Duration;
    ///
    /// let error = Error::Timeout {
    ///     target: Some("192.168.1.1:161".parse().unwrap()),
    ///     elapsed: Duration::from_secs(5),
    ///     request_id: 42,
    ///     retries: 3,
    /// };
    ///
    /// assert_eq!(
    ///     error.target().map(|a| a.to_string()),
    ///     Some("192.168.1.1:161".to_string())
    /// );
    /// ```
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
