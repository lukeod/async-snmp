//! Error types for async-snmp.
//!
//! This module provides:
//!
//! - [`Error`] - The main error type (8 variants covering all failure modes)
//! - [`ErrorStatus`] - SNMP protocol errors returned by agents (RFC 3416)
//! - [`WalkAbortReason`] - Reasons a walk operation was aborted
//!
//! # Error Handling
//!
//! Errors are boxed for efficiency: `Result<T> = Result<T, Box<Error>>`.
//!
//! ```rust
//! use async_snmp::{Error, Result};
//!
//! fn handle_error(result: Result<()>) {
//!     match result {
//!         Ok(()) => println!("Success"),
//!         Err(e) => match &*e {
//!             Error::Timeout { target, retries, .. } => {
//!                 println!("{} unreachable after {} retries", target, retries);
//!             }
//!             Error::Auth { target } => {
//!                 println!("Authentication failed for {}", target);
//!             }
//!             _ => println!("Error: {}", e),
//!         }
//!     }
//! }
//! ```

pub(crate) mod internal;

use std::net::SocketAddr;
use std::time::Duration;

use crate::oid::Oid;

/// Placeholder target address used when no target is known.
///
/// This sentinel value (0.0.0.0:0) is used in error contexts where the
/// target address cannot be determined (e.g., parsing failures before
/// the source address is known).
pub(crate) const UNKNOWN_TARGET: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);

// Pattern for converting detailed internal errors to simplified public errors:
//
// tracing::debug!(
//     target: "async_snmp::ber",  // or ::auth, ::crypto, etc.
//     snmp.offset = 42,
//     snmp.decode_error = "ZeroLengthInteger",
//     "decode error details here"
// );
// return Err(Error::MalformedResponse { target }.boxed());

/// Result type alias using the library's boxed Error type.
pub type Result<T> = std::result::Result<T, Box<Error>>;

/// Reason a walk operation was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkAbortReason {
    /// Agent returned an OID that is not greater than the previous OID.
    NonIncreasing,
    /// Agent returned an OID that was already seen (cycle detected).
    Cycle,
}

impl std::fmt::Display for WalkAbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonIncreasing => write!(f, "non-increasing OID"),
            Self::Cycle => write!(f, "cycle detected"),
        }
    }
}

/// The main error type for all async-snmp operations.
///
/// This enum covers all possible error conditions including network issues,
/// protocol errors, authentication failures, and configuration problems.
///
/// Errors are boxed (via [`Result`]) to keep the size small on the stack.
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
///         Error::Network { .. }
///     )
/// }
///
/// fn is_access_error(error: &Error) -> bool {
///     matches!(error,
///         Error::Snmp { status: ErrorStatus::NoAccess | ErrorStatus::AuthorizationError, .. } |
///         Error::Auth { .. }
///     )
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Network failure (connection refused, unreachable, etc.)
    #[error("network error communicating with {target}: {source}")]
    Network {
        target: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// Request timed out after retries.
    #[error("timeout after {elapsed:?} waiting for {target} ({retries} retries)")]
    Timeout {
        target: SocketAddr,
        elapsed: Duration,
        retries: u32,
    },

    /// SNMP protocol error from agent.
    #[error("SNMP error from {target}: {status} at index {index}")]
    Snmp {
        target: SocketAddr,
        status: ErrorStatus,
        index: u32,
        oid: Option<Oid>,
    },

    /// Authentication/authorization failed.
    #[error("authentication failed for {target}")]
    Auth { target: SocketAddr },

    /// Malformed response from agent.
    #[error("malformed response from {target}")]
    MalformedResponse { target: SocketAddr },

    /// Walk aborted due to agent misbehavior.
    #[error("walk aborted for {target}: {reason}")]
    WalkAborted {
        target: SocketAddr,
        reason: WalkAbortReason,
    },

    /// Invalid configuration.
    #[error("configuration error: {0}")]
    Config(Box<str>),

    /// Invalid OID format.
    #[error("invalid OID: {0}")]
    InvalidOid(Box<str>),
}

impl Error {
    /// Box this error (convenience for constructing boxed errors).
    pub fn boxed(self) -> Box<Self> {
        Box::new(self)
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
            other => {
                tracing::warn!(snmp.error_status = other, "unknown SNMP error status");
                Self::Unknown(other)
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_size_budget() {
        // Error size should stay bounded to avoid bloating Result types.
        // The largest variant is Error::Snmp which contains Option<Oid>.
        assert!(
            std::mem::size_of::<Error>() <= 128,
            "Error size {} exceeds 128-byte budget",
            std::mem::size_of::<Error>()
        );

        // Result<(), Box<Error>> should be pointer-sized (8 bytes on 64-bit).
        assert_eq!(
            std::mem::size_of::<Result<()>>(),
            std::mem::size_of::<*const ()>(),
            "Result<()> should be pointer-sized"
        );
    }
}
