//! Error types for async-snmp.
//!
//! This module provides:
//!
//! - [`Error`] - The main error type covering all failure modes
//! - [`DecodeError`] - Structured packet-decoding diagnostics
//! - [`ConstructionStage`] - The phase active at a construction deadline
//! - [`AuthoritativeEnginePersistenceError`](crate::AuthoritativeEnginePersistenceError) -
//!   Authoritative-engine durable storage failures
//! - [`ErrorStatus`] - SNMP protocol errors returned by agents (RFC 3416)
//! - [`WalkAbortReason`] - Reasons a walk operation was aborted
//!
//! # Error Handling
//!
//! Errors are boxed so `Result<T>` stays compact and async state machines that
//! retain an error across a suspension point do not embed the full [`Error`]
//! enum. This trades one heap allocation on error construction for smaller
//! success values and futures. The `error_representation` benchmark measures
//! that trade-off.
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
use crate::v3::ReportStatus;

/// Result type alias using the library's boxed Error type.
pub type Result<T> = std::result::Result<T, Box<Error>>;

/// Coordinate system used by a [`DecodeError`] offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeErrorOrigin {
    /// Offset from the beginning of the received or standalone encoded message.
    Packet,
    /// Offset from the beginning of a decrypted SNMPv3 scoped-PDU plaintext.
    DecryptedScopedPdu,
}

impl std::fmt::Display for DecodeErrorOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Packet => f.write_str("packet"),
            Self::DecryptedScopedPdu => f.write_str("decrypted scoped-PDU plaintext"),
        }
    }
}

/// The specific reason packet decoding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// A TLV used a tag other than the required tag.
    UnexpectedTag {
        /// Required single-octet tag.
        expected: u8,
        /// Received single-octet tag.
        actual: u8,
    },
    /// Input ended before the next required byte.
    TruncatedData,
    /// A BER length field is structurally invalid.
    InvalidLength,
    /// Indefinite-length BER is unsupported by SNMP.
    IndefiniteLength,
    /// An encoded integer cannot fit its BER intermediate representation.
    IntegerOverflow,
    /// An integer violates an ASN.1 field constraint.
    IntegerOutOfRange {
        /// Decoded integer.
        value: i64,
        /// Inclusive lower bound.
        minimum: i32,
        /// Inclusive upper bound.
        maximum: i32,
    },
    /// An unsigned integer violates an ASN.1 field constraint.
    UnsignedIntegerOutOfRange {
        /// Complete decoded unsigned value.
        value: u64,
        /// Inclusive lower bound.
        minimum: u32,
        /// Inclusive upper bound.
        maximum: u32,
    },
    /// An INTEGER-like value has no content octets.
    ZeroLengthInteger,
    /// The SNMP version number is unknown or invalid in this envelope.
    UnknownVersion(i32),
    /// The context-specific PDU tag is unknown or invalid for the version.
    UnknownPduType(u8),
    /// Constructed OCTET STRING encoding is unsupported.
    ConstructedOctetString,
    /// A required PDU or notification field is absent.
    MissingPdu,
    /// SNMPv3 message flags are internally inconsistent.
    InvalidMsgFlags,
    /// The SNMPv3 msgFlags OCTET STRING does not contain exactly one octet.
    InvalidMsgFlagsLength {
        /// Received content length.
        length: usize,
    },
    /// The SNMPv3 security model is unsupported.
    UnknownSecurityModel(i32),
    /// A USM user name exceeds its ASN.1 size constraint.
    InvalidUserNameLength {
        /// Received name length in octets.
        length: usize,
    },
    /// A NULL value has content octets.
    InvalidNull,
    /// An IpAddress value does not contain four octets.
    InvalidIpAddressLength {
        /// Received content length.
        length: usize,
    },
    /// A BER long-form length uses too many length octets.
    LengthTooLong {
        /// Number of length octets.
        octets: usize,
    },
    /// A Counter64 encoding uses too many content octets.
    Integer64TooLong {
        /// Received content length.
        length: usize,
    },
    /// A declared TLV extends beyond its enclosing bytes.
    TlvOverflow,
    /// A fixed-size read exceeds its enclosing bytes.
    InsufficientData {
        /// Requested byte count.
        needed: usize,
        /// Remaining byte count.
        available: usize,
    },
    /// An OBJECT IDENTIFIER is structurally invalid.
    InvalidOid,
    /// An OBJECT IDENTIFIER exceeds the supported arc count.
    OidTooLong {
        /// Decoded arc count.
        count: usize,
        /// Maximum supported arc count.
        max: usize,
    },
    /// A signed INTEGER encoding uses too many content octets.
    IntegerTooLong {
        /// Received content length.
        length: usize,
    },
    /// An Unsigned32 encoding uses too many content octets.
    Unsigned32TooLong {
        /// Received content length.
        length: usize,
    },
    /// A nine-octet Counter64 lacks its required zero prefix.
    Integer64MissingLeadingZero,
    /// A nine-octet generic Unsigned32 input lacks its required zero prefix.
    ///
    /// The compatible generic-value decoder accepts the net-snmp unsigned
    /// intermediate width of eight value octets plus one sign-protection
    /// octet before applying the public `u32` representation.
    Unsigned32MissingLeadingZero,
    /// A tag selects BER's unsupported high-tag-number form.
    UnsupportedMultiOctetTag {
        /// First tag octet, whose low five bits are all set.
        first_octet: u8,
    },
    /// Bytes remain inside an envelope that must be completely consumed.
    TrailingData {
        /// Number of unconsumed octets.
        remaining: usize,
    },
    /// A received encoded message exceeds the configured receive limit.
    MessageTooLarge {
        /// Received encoded size.
        size: usize,
        /// Configured maximum encoded size.
        maximum: usize,
    },
    /// An encoded value violates a protocol-level invariant.
    InvalidValue,
    /// The encoding form is recognized but unsupported.
    UnsupportedEncoding,
}

impl std::fmt::Display for DecodeErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedTag { expected, actual } => {
                write!(f, "expected tag 0x{expected:02X}, got 0x{actual:02X}")
            }
            Self::TruncatedData => f.write_str("unexpected end of data"),
            Self::InvalidLength => f.write_str("invalid length encoding"),
            Self::IndefiniteLength => f.write_str("indefinite length encoding not supported"),
            Self::IntegerOverflow => f.write_str("integer overflow"),
            Self::IntegerOutOfRange {
                value,
                minimum,
                maximum,
            } => write!(
                f,
                "integer {value} outside constrained range {minimum}..{maximum}"
            ),
            Self::UnsignedIntegerOutOfRange {
                value,
                minimum,
                maximum,
            } => write!(
                f,
                "unsigned integer {value} outside constrained range {minimum}..{maximum}"
            ),
            Self::ZeroLengthInteger => f.write_str("zero-length integer"),
            Self::UnknownVersion(value) => write!(f, "unknown SNMP version: {value}"),
            Self::UnknownPduType(tag) => write!(f, "unknown PDU type: 0x{tag:02X}"),
            Self::ConstructedOctetString => {
                f.write_str("constructed OCTET STRING is not supported")
            }
            Self::MissingPdu => f.write_str("missing PDU in message"),
            Self::InvalidMsgFlags => f.write_str("invalid msgFlags"),
            Self::InvalidMsgFlagsLength { length } => {
                write!(f, "msgFlags must contain exactly one octet, got {length}")
            }
            Self::UnknownSecurityModel(model) => write!(f, "unknown security model: {model}"),
            Self::InvalidUserNameLength { length } => {
                write!(f, "msgUserName length {length} exceeds maximum 32")
            }
            Self::InvalidNull => f.write_str("NULL with non-zero length"),
            Self::InvalidIpAddressLength { length } => {
                write!(f, "IP address must be 4 bytes, got {length}")
            }
            Self::LengthTooLong { octets } => {
                write!(f, "length encoding too long ({octets} octets)")
            }
            Self::Integer64TooLong { length } => write!(f, "integer64 too long: {length} bytes"),
            Self::TlvOverflow => f.write_str("TLV extends past end of data"),
            Self::InsufficientData { needed, available } => {
                write!(f, "need {needed} bytes but only {available} remaining")
            }
            Self::InvalidOid => f.write_str("invalid object identifier"),
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
                f.write_str("9-octet integer64 missing required leading zero byte")
            }
            Self::Unsigned32MissingLeadingZero => {
                f.write_str("9-octet unsigned32 input missing required leading zero byte")
            }
            Self::UnsupportedMultiOctetTag { first_octet } => {
                write!(
                    f,
                    "unsupported multi-octet tag starting with 0x{first_octet:02X}"
                )
            }
            Self::TrailingData { remaining } => write!(f, "{remaining} unconsumed bytes"),
            Self::MessageTooLarge { size, maximum } => {
                write!(f, "message size {size} exceeds receive limit {maximum}")
            }
            Self::InvalidValue => f.write_str("invalid encoded value"),
            Self::UnsupportedEncoding => f.write_str("unsupported encoding"),
        }
    }
}

/// A decoding failure with an explicit offset coordinate system.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("decode error at {origin} offset {offset}: {kind}{peer_suffix}", peer_suffix = peer.map(|value| format!(" from {value}")).unwrap_or_default())]
pub struct DecodeError {
    /// Coordinate system in which `offset` is measured.
    pub origin: DecodeErrorOrigin,
    /// Zero-based offset in `origin`.
    pub offset: usize,
    /// Structured failure reason.
    pub kind: DecodeErrorKind,
    /// Sending peer when decoding occurred at a network boundary.
    pub peer: Option<SocketAddr>,
}

impl DecodeError {
    /// Construct a standalone decode error without peer context.
    #[must_use]
    pub const fn new(offset: usize, kind: DecodeErrorKind) -> Self {
        Self {
            origin: DecodeErrorOrigin::Packet,
            offset,
            kind,
            peer: None,
        }
    }

    /// Construct a decode error in an explicit coordinate system.
    #[must_use]
    pub const fn with_origin(
        origin: DecodeErrorOrigin,
        offset: usize,
        kind: DecodeErrorKind,
    ) -> Self {
        Self {
            origin,
            offset,
            kind,
            peer: None,
        }
    }

    /// Attach the sending peer at a network boundary.
    #[must_use]
    pub const fn with_peer(mut self, peer: SocketAddr) -> Self {
        self.peer = Some(peer);
        self
    }
}

/// Reason a walk operation was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WalkAbortReason {
    /// Agent returned an OID that is not greater than the previous OID.
    NonIncreasing,
    /// Agent returned an OID that was already seen (cycle detected).
    Cycle,
    /// A one-candidate look-ahead found more in-subtree data after the limit.
    ResultLimitExceeded {
        /// Configured maximum number of yielded bindings.
        limit: usize,
    },
}

impl std::fmt::Display for WalkAbortReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonIncreasing => write!(f, "non-increasing OID"),
            Self::Cycle => write!(f, "cycle detected"),
            Self::ResultLimitExceeded { limit } => {
                write!(f, "result limit of {limit} exceeded")
            }
        }
    }
}

impl std::error::Error for WalkAbortReason {}

/// Asynchronous phase active when bounded client construction timed out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConstructionStage {
    /// Resolving the original target into socket addresses.
    Resolve,
    /// Binding a local UDP socket.
    Bind,
    /// Establishing a TCP connection.
    Connect,
}

/// Payload-free classification of a top-level [`Error`].
///
/// This does not define retryability or severity. Exchange metadata and shared
/// operation wrappers report the underlying failure's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Network I/O failure.
    Network,
    /// Request or standalone-send timeout.
    Timeout,
    /// Bounded client-construction timeout.
    ConstructionTimeout,
    /// Closed or poisoned transport.
    Closed,
    /// Duplicate live request identifier.
    RequestIdInUse,
    /// Locally encoded message exceeds the effective outbound limit.
    OutboundMessageTooLarge,
    /// SNMP protocol error status.
    Snmp,
    /// Authentication or authorization failure.
    Auth,
    /// Terminal SNMPv3 Report.
    Report,
    /// Packet decoding failure.
    Decode,
    /// A decoded response violates operation semantics.
    MalformedResponse,
    /// Fixed-cardinality response-shape violation.
    ResponseShape,
    /// Walk abort.
    WalkAborted,
    /// Invalid configuration.
    Config,
    /// Authoritative-engine state could not be persisted.
    AuthoritativeEnginePersistence,
    /// Privacy sender-state allocation or encryption failure.
    Privacy,
    /// Operating-system random source failure.
    RandomSource,
    /// Available even when the `agent` feature is disabled.
    AgentAlreadyRunning,
    /// Invalid outbound SNMP message.
    InvalidMessage,
    /// Invalid OID.
    InvalidOid,
}

impl ErrorKind {
    /// Returns the stable snake_case name for this error kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Timeout => "timeout",
            Self::ConstructionTimeout => "construction_timeout",
            Self::Closed => "transport_closed",
            Self::RequestIdInUse => "request_id_in_use",
            Self::OutboundMessageTooLarge => "outbound_message_too_large",
            Self::Snmp => "snmp",
            Self::Auth => "authentication",
            Self::Report => "v3_report",
            Self::Decode => "decode",
            Self::MalformedResponse => "malformed_response",
            Self::ResponseShape => "response_shape",
            Self::WalkAborted => "walk_aborted",
            Self::Config => "configuration",
            Self::AuthoritativeEnginePersistence => "authoritative_engine_persistence",
            Self::Privacy => "privacy",
            Self::RandomSource => "random_source",
            Self::AgentAlreadyRunning => "agent_already_running",
            Self::InvalidMessage => "invalid_message",
            Self::InvalidOid => "invalid_oid",
        }
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
/// use async_snmp::{Error, ErrorKind, ErrorStatus};
///
/// fn is_retriable(error: &Error) -> bool {
///     matches!(error.kind(),
///         ErrorKind::Timeout |
///         ErrorKind::Network
///     )
/// }
///
/// fn is_access_error(error: &Error) -> bool {
///     matches!(error.exchange_source(),
///         Error::Snmp { status: ErrorStatus::NoAccess | ErrorStatus::AuthorizationError, .. } |
///         Error::Auth { .. }
///     )
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A failure shared by concurrent participants in one internal operation.
    #[error("{source}")]
    SharedOperation {
        /// Original structured failure shared without lossy reconstruction.
        #[source]
        source: std::sync::Arc<Error>,
    },

    /// An exchange consumed one or more accepted responses before ending in an
    /// error that has no response metadata of its own.
    ///
    /// [`Error::kind`] reports the wrapped error's kind, and the wrapped error
    /// remains available through both `source` and [`Error::exchange_source`].
    /// SNMP protocol errors, terminal Reports, and response-shape errors retain
    /// metadata in their existing structured fields instead of using this
    /// wrapper.
    #[error("{source}")]
    Exchange {
        /// Underlying local, transport, authentication, or semantic failure.
        #[source]
        source: Box<Error>,
        /// Accepted deviations in exchange order before the failure.
        metadata: Box<crate::client::ResponseMetadata>,
    },

    /// Network failure (connection refused, unreachable, etc.)
    #[error("network error communicating with {target}: {source}")]
    Network {
        target: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    /// Request or standalone send exceeded its operation deadline.
    #[error("timeout after {elapsed:?} waiting for {target} ({retries} retries)")]
    Timeout {
        target: SocketAddr,
        elapsed: Duration,
        retries: u32,
    },

    /// Client construction exceeded its single total deadline.
    #[error("construction timed out during {stage:?} after {elapsed:?} for {target}")]
    ConstructionTimeout {
        /// Original builder target, retained even when it is unresolved.
        target: crate::client::Target,
        /// Phase active when the absolute construction deadline expired.
        stage: ConstructionStage,
        /// Total time elapsed since bounded construction began.
        elapsed: Duration,
    },

    /// Transport was shut down while a request was pending.
    ///
    /// Not retriable: the transport will never deliver a response again.
    /// Recovery requires creating a new transport.
    #[error("transport closed while waiting for {target}")]
    Closed { target: SocketAddr },

    /// A UDP request or alias ID is already reserved by another live exchange.
    #[error("request ID {request_id} is already in use")]
    RequestIdInUse { request_id: i32 },

    /// An exactly encoded message exceeds the effective local outbound limit.
    ///
    /// For SNMPv1/v2c and unconfirmed notifications, `limit` is the transport's
    /// configured send capacity. For an SNMPv3 request after discovery, it is
    /// the smaller of that capacity and the remote engine's advertised
    /// `msgMaxSize`.
    #[error("encoded outbound message size {size} exceeds limit {limit}")]
    OutboundMessageTooLarge {
        /// Exact encoded message size in octets.
        size: usize,
        /// Effective outbound limit in octets.
        limit: usize,
    },

    /// SNMP protocol error from agent.
    #[error("SNMP error from {target}: {status} at index {index}")]
    Snmp {
        target: SocketAddr,
        status: ErrorStatus,
        index: u32,
        oid: Option<Box<Oid>>,
        /// Accepted deviations in all messages consumed by the exchange before
        /// this response-derived protocol error.
        metadata: Box<crate::client::ResponseMetadata>,
    },

    /// Authentication/authorization failed.
    #[error("authentication failed for {target}")]
    Auth { target: SocketAddr },

    /// A structurally valid SNMPv3 Report terminated the operation.
    #[error("SNMPv3 Report from {target}: {status}")]
    Report {
        target: SocketAddr,
        status: Box<ReportStatus>,
        /// Accepted deviations in all messages consumed by the exchange,
        /// including this terminal Report.
        metadata: Box<crate::client::ResponseMetadata>,
    },

    /// A packet could not be decoded.
    #[error("{0}")]
    Decode(
        #[from]
        #[source]
        DecodeError,
    ),

    /// A decoded response violates operation-specific semantics.
    #[error("malformed response from {target}")]
    MalformedResponse { target: SocketAddr },

    /// A fixed-cardinality response violated the configured shape policy.
    ///
    /// The response retains every decoded binding and all structured anomaly
    /// diagnostics so strict rejection remains observable.
    #[error("response shape anomaly from {target}: {response:?}")]
    ResponseShape {
        target: SocketAddr,
        response: crate::client::FixedCardinalityResponse,
    },

    /// Walk aborted before observed natural completion.
    #[error("walk aborted for {target}: {reason}")]
    WalkAborted {
        target: SocketAddr,
        reason: WalkAbortReason,
    },

    /// Invalid configuration.
    #[error("configuration error: {0}")]
    Config(Box<str>),

    /// An authoritative-engine state transition could not be persisted.
    #[error(transparent)]
    AuthoritativeEnginePersistence(#[from] crate::v3::AuthoritativeEnginePersistenceError),

    /// Privacy sender-state allocation or encryption failed.
    #[error(transparent)]
    Privacy(#[from] crate::v3::PrivacyError),

    /// The operating system could not provide random bytes.
    #[error("OS random source unavailable: {source}")]
    RandomSource {
        #[source]
        source: getrandom::Error,
    },

    /// Another [`Agent::run`](crate::agent::Agent::run) call is already active.
    #[cfg(feature = "agent")]
    #[error("agent is already running")]
    AgentAlreadyRunning,

    /// Message cannot be represented by the selected SNMP version.
    #[error("invalid SNMP message: {0}")]
    InvalidMessage(Box<str>),

    /// Invalid OID format.
    #[error("invalid OID: {0}")]
    InvalidOid(Box<str>),
}

impl Error {
    /// Returns the payload-free kind of this error.
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::SharedOperation { source } => source.kind(),
            Self::Exchange { source, .. } => source.kind(),
            Self::Network { .. } => ErrorKind::Network,
            Self::Timeout { .. } => ErrorKind::Timeout,
            Self::ConstructionTimeout { .. } => ErrorKind::ConstructionTimeout,
            Self::Closed { .. } => ErrorKind::Closed,
            Self::RequestIdInUse { .. } => ErrorKind::RequestIdInUse,
            Self::OutboundMessageTooLarge { .. } => ErrorKind::OutboundMessageTooLarge,
            Self::Snmp { .. } => ErrorKind::Snmp,
            Self::Auth { .. } => ErrorKind::Auth,
            Self::Report { .. } => ErrorKind::Report,
            Self::Decode(_) => ErrorKind::Decode,
            Self::MalformedResponse { .. } => ErrorKind::MalformedResponse,
            Self::ResponseShape { .. } => ErrorKind::ResponseShape,
            Self::WalkAborted { .. } => ErrorKind::WalkAborted,
            Self::Config(_) => ErrorKind::Config,
            Self::AuthoritativeEnginePersistence(_) => ErrorKind::AuthoritativeEnginePersistence,
            Self::Privacy(_) => ErrorKind::Privacy,
            Self::RandomSource { .. } => ErrorKind::RandomSource,
            #[cfg(feature = "agent")]
            Self::AgentAlreadyRunning => ErrorKind::AgentAlreadyRunning,
            Self::InvalidMessage(_) => ErrorKind::InvalidMessage,
            Self::InvalidOid(_) => ErrorKind::InvalidOid,
        }
    }

    /// Return metadata retained from accepted responses in this operation.
    ///
    /// Protocol errors and response-shape failures expose their native
    /// metadata through the same accessor. Errors that occurred before any
    /// response was accepted return `None`.
    #[must_use]
    pub fn response_metadata(&self) -> Option<&crate::client::ResponseMetadata> {
        match self {
            Self::SharedOperation { source } => source.response_metadata(),
            Self::Exchange { metadata, .. }
            | Self::Snmp { metadata, .. }
            | Self::Report { metadata, .. } => Some(metadata.as_ref()),
            Self::ResponseShape { response, .. } => Some(&response.metadata),
            _ => None,
        }
    }

    /// Return the underlying failure carried by an exchange metadata or shared
    /// operation wrapper.
    ///
    /// For unwrapped errors, this returns `self`. Prefer this accessor or
    /// [`Self::kind`] when matching failures that may be shared by concurrent
    /// participants.
    #[must_use]
    pub fn exchange_source(&self) -> &Error {
        match self {
            Self::SharedOperation { source } => source.exchange_source(),
            Self::Exchange { source, .. } => source.exchange_source(),
            _ => self,
        }
    }

    /// Return the authoritative-engine persistence failure, if this is one.
    ///
    /// Exchange metadata and shared operation wrappers are traversed in the same way as
    /// [`Error::exchange_source`].
    #[must_use]
    pub fn authoritative_engine_persistence(
        &self,
    ) -> Option<&crate::v3::AuthoritativeEnginePersistenceError> {
        match self.exchange_source() {
            Self::AuthoritativeEnginePersistence(error) => Some(error),
            _ => None,
        }
    }

    pub(crate) fn with_prior_response_metadata(
        mut self: Box<Self>,
        prior: &crate::client::ResponseMetadata,
    ) -> Box<Self> {
        if prior.decode_anomalies.is_empty() {
            return self;
        }

        match self.as_mut() {
            Self::Exchange { metadata, .. }
            | Self::Snmp { metadata, .. }
            | Self::Report { metadata, .. } => {
                let mut combined = prior.clone();
                combined.append(std::mem::take(metadata.as_mut()));
                **metadata = combined;
                self
            }
            Self::ResponseShape { response, .. } => {
                let mut combined = prior.clone();
                combined.append(std::mem::take(&mut response.metadata));
                response.metadata = combined;
                self
            }
            _ => Box::new(Self::Exchange {
                source: self,
                metadata: Box::new(prior.clone()),
            }),
        }
    }

    /// Box this error (convenience for constructing boxed errors).
    #[must_use]
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
/// ## `SNMPv1` Errors (0-5)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorStatus {
    /// Operation completed successfully (status = 0).
    NoError,
    /// Response message would be too large for transport (status = 1).
    TooBig,
    /// Requested OID not found (status = 2). `SNMPv1` only; v2c+ uses exception values.
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
    /// Create from a raw status code without logging or other side effects.
    ///
    /// Unknown and future values are preserved in [`Self::Unknown`] for the
    /// protocol caller to classify or report at the appropriate boundary.
    #[must_use]
    pub const fn from_i32(value: i32) -> Self {
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
    #[must_use]
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

    /// Map a v2c+ error status to its v1 equivalent per RFC 2576 Section 4.3.
    ///
    /// V1-native statuses (0-5) pass through unchanged.
    #[must_use]
    pub fn to_v1(&self) -> Self {
        match self {
            // V1-native statuses
            Self::NoError
            | Self::TooBig
            | Self::NoSuchName
            | Self::BadValue
            | Self::ReadOnly
            | Self::GenErr => *self,

            // Value errors -> BadValue
            Self::WrongType
            | Self::WrongLength
            | Self::WrongEncoding
            | Self::WrongValue
            | Self::InconsistentValue => Self::BadValue,

            // Access/creation errors -> NoSuchName
            Self::NoAccess
            | Self::NotWritable
            | Self::NoCreation
            | Self::InconsistentName
            | Self::AuthorizationError => Self::NoSuchName,

            // Resource/commit errors -> GenErr
            Self::ResourceUnavailable | Self::CommitFailed | Self::UndoFailed => Self::GenErr,

            Self::Unknown(_) => Self::GenErr,
        }
    }

    /// Return the canonical SMI name for this status code.
    ///
    /// For `Unknown` variants, returns `None`; callers should format the
    /// numeric code directly in that case.
    #[must_use]
    pub fn as_str(&self) -> Option<&'static str> {
        match self {
            Self::NoError => Some("noError"),
            Self::TooBig => Some("tooBig"),
            Self::NoSuchName => Some("noSuchName"),
            Self::BadValue => Some("badValue"),
            Self::ReadOnly => Some("readOnly"),
            Self::GenErr => Some("genErr"),
            Self::NoAccess => Some("noAccess"),
            Self::WrongType => Some("wrongType"),
            Self::WrongLength => Some("wrongLength"),
            Self::WrongEncoding => Some("wrongEncoding"),
            Self::WrongValue => Some("wrongValue"),
            Self::NoCreation => Some("noCreation"),
            Self::InconsistentValue => Some("inconsistentValue"),
            Self::ResourceUnavailable => Some("resourceUnavailable"),
            Self::CommitFailed => Some("commitFailed"),
            Self::UndoFailed => Some("undoFailed"),
            Self::AuthorizationError => Some("authorizationError"),
            Self::NotWritable => Some("notWritable"),
            Self::InconsistentName => Some("inconsistentName"),
            Self::Unknown(_) => None,
        }
    }
}

impl std::fmt::Display for ErrorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.as_str() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown({})", self.as_i32()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_metadata_wrapper_preserves_kind_source_and_metadata() {
        let target = "127.0.0.1:161".parse().unwrap();
        let metadata = crate::client::ResponseMetadata::from_decode_anomalies(vec![
            crate::DecodeAnomaly::TrailingBytes {
                original_length: 3,
                canonical_length: 0,
            },
        ]);
        let error = Error::Closed { target }
            .boxed()
            .with_prior_response_metadata(&metadata);

        assert_eq!(error.kind(), ErrorKind::Closed);
        assert!(matches!(error.exchange_source(), Error::Closed { .. }));
        assert_eq!(error.response_metadata(), Some(&metadata));
        let source = std::error::Error::source(error.as_ref())
            .expect("wrapper must preserve the standard error source chain");
        assert_eq!(source.to_string(), Error::Closed { target }.to_string());
    }

    #[test]
    fn error_kind_exhaustively_maps_non_agent_variants() {
        let target = "127.0.0.1:161".parse().unwrap();
        let cases = vec![
            (
                Error::Network {
                    target,
                    source: std::io::Error::other("network"),
                },
                ErrorKind::Network,
            ),
            (
                Error::Timeout {
                    target,
                    elapsed: Duration::from_secs(1),
                    retries: 2,
                },
                ErrorKind::Timeout,
            ),
            (
                Error::ConstructionTimeout {
                    target: crate::client::Target::from("unresolved.example"),
                    stage: ConstructionStage::Connect,
                    elapsed: Duration::from_secs(2),
                },
                ErrorKind::ConstructionTimeout,
            ),
            (Error::Closed { target }, ErrorKind::Closed),
            (
                Error::RequestIdInUse { request_id: 7 },
                ErrorKind::RequestIdInUse,
            ),
            (
                Error::OutboundMessageTooLarge {
                    size: 1500,
                    limit: 1472,
                },
                ErrorKind::OutboundMessageTooLarge,
            ),
            (
                Error::Snmp {
                    target,
                    status: ErrorStatus::GenErr,
                    index: 1,
                    oid: Some(Box::new(Oid::from_slice(&[1, 3, 6, 1]))),
                    metadata: Box::new(crate::client::ResponseMetadata::default()),
                },
                ErrorKind::Snmp,
            ),
            (Error::Auth { target }, ErrorKind::Auth),
            (
                Error::Report {
                    target,
                    status: Box::new(crate::v3::ReportStatus::UnknownEngineId { counter: 1 }),
                    metadata: Box::new(crate::client::ResponseMetadata::default()),
                },
                ErrorKind::Report,
            ),
            (
                Error::MalformedResponse { target },
                ErrorKind::MalformedResponse,
            ),
            (
                Error::Decode(DecodeError::new(3, DecodeErrorKind::TruncatedData)),
                ErrorKind::Decode,
            ),
            (
                Error::ResponseShape {
                    target,
                    response: crate::client::FixedCardinalityResponse {
                        operation: crate::client::FixedCardinalityOperation::Get,
                        varbinds: Vec::new(),
                        anomalies: Vec::new(),
                        metadata: crate::client::ResponseMetadata::default(),
                    },
                },
                ErrorKind::ResponseShape,
            ),
            (
                Error::WalkAborted {
                    target,
                    reason: WalkAbortReason::Cycle,
                },
                ErrorKind::WalkAborted,
            ),
            (Error::Config("config".into()), ErrorKind::Config),
            (
                *crate::v3::AuthoritativeEngine::install(b"error-kind-engine".to_vec(), |_| {
                    Err(std::io::Error::other("persistence"))
                })
                .unwrap_err(),
                ErrorKind::AuthoritativeEnginePersistence,
            ),
            (
                Error::RandomSource {
                    source: getrandom::Error::UNEXPECTED,
                },
                ErrorKind::RandomSource,
            ),
            (
                Error::InvalidMessage("message".into()),
                ErrorKind::InvalidMessage,
            ),
            (Error::InvalidOid("oid".into()), ErrorKind::InvalidOid),
        ];

        for (error, expected) in cases {
            assert_eq!(error.kind(), expected);
        }
    }

    #[test]
    fn error_kind_canonical_names_and_display_are_total() {
        let cases = [
            (ErrorKind::Network, "network"),
            (ErrorKind::Timeout, "timeout"),
            (ErrorKind::ConstructionTimeout, "construction_timeout"),
            (ErrorKind::Closed, "transport_closed"),
            (ErrorKind::RequestIdInUse, "request_id_in_use"),
            (
                ErrorKind::OutboundMessageTooLarge,
                "outbound_message_too_large",
            ),
            (ErrorKind::Snmp, "snmp"),
            (ErrorKind::Auth, "authentication"),
            (ErrorKind::Report, "v3_report"),
            (ErrorKind::Decode, "decode"),
            (ErrorKind::MalformedResponse, "malformed_response"),
            (ErrorKind::ResponseShape, "response_shape"),
            (ErrorKind::WalkAborted, "walk_aborted"),
            (ErrorKind::Config, "configuration"),
            (
                ErrorKind::AuthoritativeEnginePersistence,
                "authoritative_engine_persistence",
            ),
            (ErrorKind::RandomSource, "random_source"),
            (ErrorKind::AgentAlreadyRunning, "agent_already_running"),
            (ErrorKind::InvalidMessage, "invalid_message"),
            (ErrorKind::InvalidOid, "invalid_oid"),
        ];

        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected);
            assert_eq!(kind.to_string(), expected);
        }
    }

    #[test]
    fn error_kind_names_are_const() {
        const NAME: &str = ErrorKind::ConstructionTimeout.as_str();
        assert_eq!(NAME, "construction_timeout");
    }

    #[cfg(feature = "agent")]
    #[test]
    fn agent_error_maps_to_always_nameable_kind() {
        assert_eq!(
            Error::AgentAlreadyRunning.kind(),
            ErrorKind::AgentAlreadyRunning
        );
        assert_eq!(
            ErrorKind::AgentAlreadyRunning.as_str(),
            "agent_already_running"
        );
    }

    #[test]
    fn walk_abort_reason_is_error() {
        let reason = WalkAbortReason::NonIncreasing;
        let err: &dyn std::error::Error = &reason;
        assert_eq!(err.to_string(), "non-increasing OID");
    }

    #[test]
    fn error_status_conversion_is_const_and_preserves_unknown_values() {
        const KNOWN: ErrorStatus = ErrorStatus::from_i32(2);
        const FUTURE: ErrorStatus = ErrorStatus::from_i32(99);
        const NEGATIVE: ErrorStatus = ErrorStatus::from_i32(-1);

        assert_eq!(KNOWN, ErrorStatus::NoSuchName);
        assert_eq!(FUTURE, ErrorStatus::Unknown(99));
        assert_eq!(NEGATIVE, ErrorStatus::Unknown(-1));
    }

    #[test]
    fn error_status_to_v1_mapping() {
        // RFC 2576 Section 4.3 mappings
        // V1 statuses (0-5) pass through unchanged
        assert_eq!(ErrorStatus::NoError.to_v1(), ErrorStatus::NoError);
        assert_eq!(ErrorStatus::TooBig.to_v1(), ErrorStatus::TooBig);
        assert_eq!(ErrorStatus::NoSuchName.to_v1(), ErrorStatus::NoSuchName);
        assert_eq!(ErrorStatus::BadValue.to_v1(), ErrorStatus::BadValue);
        assert_eq!(ErrorStatus::ReadOnly.to_v1(), ErrorStatus::ReadOnly);
        assert_eq!(ErrorStatus::GenErr.to_v1(), ErrorStatus::GenErr);

        // WrongValue/WrongType/WrongLength/WrongEncoding/InconsistentValue -> BadValue
        assert_eq!(ErrorStatus::WrongValue.to_v1(), ErrorStatus::BadValue);
        assert_eq!(ErrorStatus::WrongType.to_v1(), ErrorStatus::BadValue);
        assert_eq!(ErrorStatus::WrongLength.to_v1(), ErrorStatus::BadValue);
        assert_eq!(ErrorStatus::WrongEncoding.to_v1(), ErrorStatus::BadValue);
        assert_eq!(
            ErrorStatus::InconsistentValue.to_v1(),
            ErrorStatus::BadValue
        );

        // NoAccess/NotWritable/NoCreation/InconsistentName/AuthorizationError -> NoSuchName
        assert_eq!(ErrorStatus::NoAccess.to_v1(), ErrorStatus::NoSuchName);
        assert_eq!(ErrorStatus::NotWritable.to_v1(), ErrorStatus::NoSuchName);
        assert_eq!(ErrorStatus::NoCreation.to_v1(), ErrorStatus::NoSuchName);
        assert_eq!(
            ErrorStatus::InconsistentName.to_v1(),
            ErrorStatus::NoSuchName
        );
        assert_eq!(
            ErrorStatus::AuthorizationError.to_v1(),
            ErrorStatus::NoSuchName
        );

        // ResourceUnavailable/CommitFailed/UndoFailed -> GenErr
        assert_eq!(
            ErrorStatus::ResourceUnavailable.to_v1(),
            ErrorStatus::GenErr
        );
        assert_eq!(ErrorStatus::CommitFailed.to_v1(), ErrorStatus::GenErr);
        assert_eq!(ErrorStatus::UndoFailed.to_v1(), ErrorStatus::GenErr);
    }

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
