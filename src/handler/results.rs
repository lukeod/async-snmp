//! Result types for MIB handler operations.
//!
//! This module provides the result types returned by [`MibHandler`](super::MibHandler)
//! methods:
//!
//! - [`GetResult`] - Result of a GET operation
//! - [`GetNextResult`] - Result of a GETNEXT operation
//! - [`SetTestError`] / [`SetTestResult`] - SET validation failures and prepared state
//! - [`SetCommitResult`] / [`SetUndoResult`] - Phase-specific apply and rollback results
//! - [`HandlerError`] / [`HandlerResult`] - Handler processing failures (mapped to `genErr`)

use std::borrow::Cow;

use crate::error::ErrorStatus;
use crate::value::Value;
use crate::varbind::VarBind;

/// A handler processing failure, reported to the manager as a `genErr` Response.
///
/// Returned as the `Err` side of [`HandlerResult`] from
/// [`MibHandler::get`](super::MibHandler::get) and
/// [`MibHandler::get_next`](super::MibHandler::get_next) when the handler
/// *failed to process* the request — the backing store was unreachable, a lock
/// was poisoned, a hardware read timed out. It is distinct from the RFC 3416
/// exception values, which are successful answers about the MIB:
///
/// | Situation | Return |
/// |-----------|--------|
/// | Object/instance doesn't exist | `Ok(GetResult::NoSuchObject / NoSuchInstance)` |
/// | No more OIDs in the subtree | `Ok(GetNextResult::EndOfMibView)` |
/// | Couldn't find out (backend failure) | `Err(HandlerError)` |
///
/// When a handler returns an error, the agent answers the whole request with
/// error-status `genErr` and error-index set to the failing variable binding
/// (RFC 3416 Section 4.2.1), for all protocol versions. The message and source
/// are logged by the agent; they are never sent on the wire — `genErr` carries
/// no detail.
///
/// # Construction
///
/// Any [`std::error::Error`] converts via `?`, or build one from a message:
///
/// ```rust
/// use async_snmp::handler::{HandlerError, HandlerResult, GetResult};
///
/// fn read_backend() -> std::io::Result<i32> {
///     Err(std::io::Error::other("device bus timeout"))
/// }
///
/// fn get_value() -> HandlerResult<GetResult> {
///     let raw = read_backend()?; // io::Error -> HandlerError
///     Ok(GetResult::Value(async_snmp::Value::Integer(raw)))
/// }
///
/// let err: HandlerError = HandlerError::new("cache poisoned");
/// assert_eq!(err.message(), "cache poisoned");
/// assert!(get_value().is_err());
/// ```
///
/// `HandlerError` intentionally does not implement [`std::error::Error`]:
/// that keeps the blanket `From<E: std::error::Error>` conversion (and with it
/// `?` on arbitrary error types) possible, the same trade-off `anyhow::Error`
/// makes. It is a terminal type — the agent consumes it; nothing converts out
/// of it.
pub struct HandlerError {
    message: Cow<'static, str>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl HandlerError {
    /// Create an error from a message describing what failed.
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// The failure message (used for agent-side logging only; never sent on
    /// the wire).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The underlying error this was converted from, if any.
    #[must_use]
    pub fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl std::fmt::Display for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Debug for HandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerError")
            .field("message", &self.message)
            .field("source", &self.source)
            .finish()
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for HandlerError {
    fn from(err: E) -> Self {
        Self {
            message: err.to_string().into(),
            source: Some(Box::new(err)),
        }
    }
}

/// Result type returned by [`MibHandler::get`](super::MibHandler::get) and
/// [`MibHandler::get_next`](super::MibHandler::get_next).
///
/// `Err` means the handler failed to process the request and the agent must
/// answer `genErr`; see [`HandlerError`] for when to return which.
pub type HandlerResult<T> = Result<T, HandlerError>;

/// Result of preparing one SET varbind.
///
/// `Ok` carries request-owned state that the agent retains through the commit
/// phase. `Err` is the protocol failure for this varbind and must not leave a
/// reservation behind.
pub type SetTestResult = Result<Box<dyn super::PreparedSet>, SetTestError>;

/// A protocol validation failure from the SET test phase.
///
/// This type deliberately cannot represent successful validation, or failures
/// that only make sense after commit begins. Consequently `Err` from
/// [`MibHandler::test_set`](super::MibHandler::test_set) can never accidentally
/// encode `noError`, `commitFailed`, or `undoFailed`.
///
/// ```compile_fail
/// use async_snmp::{SetCommitError, SetTestResult};
///
/// let _: SetTestResult = Err(SetCommitError::Failed);
/// ```
///
/// Commit- and undo-only failures are likewise different types:
///
/// ```compile_fail
/// use async_snmp::{SetCommitError, SetTestError};
///
/// let _: SetTestError = SetCommitError::Failed;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetTestError {
    /// Validation or its backing service failed without a more specific status.
    ///
    /// Maps to `genErr`. Use a more specific variant whenever the failure is a
    /// protocol validation outcome rather than an internal/backend failure.
    GeneralFailure,
    /// Access denied by the handler's application policy.
    NoAccess,
    /// Object is inherently read-only.
    NotWritable,
    /// Value has the wrong ASN.1 type.
    WrongType,
    /// Value violates a length constraint.
    WrongLength,
    /// Value encoding is invalid.
    WrongEncoding,
    /// Value fails semantic validation.
    WrongValue,
    /// The requested object or row cannot be created.
    NoCreation,
    /// Value conflicts with other state or varbinds.
    InconsistentValue,
    /// A reservation needed for the transaction is unavailable.
    ResourceUnavailable,
    /// Row or instance name is inconsistent with existing data.
    InconsistentName,
}

impl SetTestError {
    /// Convert this validation failure to its protocol response status.
    #[must_use]
    pub const fn to_error_status(self) -> ErrorStatus {
        match self {
            Self::GeneralFailure => ErrorStatus::GenErr,
            Self::NoAccess => ErrorStatus::NoAccess,
            Self::NotWritable => ErrorStatus::NotWritable,
            Self::WrongType => ErrorStatus::WrongType,
            Self::WrongLength => ErrorStatus::WrongLength,
            Self::WrongEncoding => ErrorStatus::WrongEncoding,
            Self::WrongValue => ErrorStatus::WrongValue,
            Self::NoCreation => ErrorStatus::NoCreation,
            Self::InconsistentValue => ErrorStatus::InconsistentValue,
            Self::ResourceUnavailable => ErrorStatus::ResourceUnavailable,
            Self::InconsistentName => ErrorStatus::InconsistentName,
        }
    }
}

/// Result of applying one prepared SET varbind.
///
/// Validation failures cannot be returned from this phase:
///
/// ```compile_fail
/// use async_snmp::{SetCommitResult, SetTestError};
///
/// let _: SetCommitResult = Err(SetTestError::GeneralFailure);
/// ```
pub type SetCommitResult = Result<(), SetCommitError>;

/// Failure from the SET commit phase.
///
/// The dedicated type prevents a commit callback from returning validation or
/// undo-only statuses. The agent maps this failure to `commitFailed` and uses
/// the failed varbind's one-based index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetCommitError {
    /// Applying the prepared change failed and may have partially mutated state.
    Failed,
}

impl SetCommitError {
    /// Convert this commit failure to its protocol response status.
    #[must_use]
    pub const fn to_error_status(self) -> ErrorStatus {
        match self {
            Self::Failed => ErrorStatus::CommitFailed,
        }
    }
}

/// Result of rolling back one attempted SET commit.
///
/// Commit failures cannot be returned from this phase:
///
/// ```compile_fail
/// use async_snmp::{SetCommitError, SetUndoResult};
///
/// let _: SetUndoResult = Err(SetCommitError::Failed);
/// ```
pub type SetUndoResult = Result<(), SetUndoError>;

/// Failure from the SET undo phase.
///
/// The dedicated type prevents an undo callback from returning validation or
/// commit-only statuses. The agent maps this failure to `undoFailed` with
/// error-index zero for SNMPv2c/v3. For SNMPv1, RFC 2576 downgrades the status
/// to `genErr` and uses the failed undo binding's one-based index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetUndoError {
    /// Rolling back the attempted change failed.
    Failed,
}

impl SetUndoError {
    /// Convert this undo failure to its protocol response status.
    #[must_use]
    pub const fn to_error_status(self) -> ErrorStatus {
        match self {
            Self::Failed => ErrorStatus::UndoFailed,
        }
    }
}

/// Result of a GET operation on a specific OID (RFC 3416).
///
/// This enum distinguishes between the RFC 3416-mandated exception types:
/// - `Value`: The OID exists and has the given value
/// - `NoSuchObject`: The OID's object type is not supported (agent doesn't implement this MIB)
/// - `NoSuchInstance`: The object type exists but this specific instance doesn't
///   (e.g., table row doesn't exist)
///
/// # Version Differences
///
/// - **`SNMPv1`**: Both exception types result in a `noSuchName` error response
/// - **SNMPv2c/v3**: Returns the appropriate exception value in the response varbind
///
/// # Choosing `NoSuchObject` vs `NoSuchInstance`
///
/// | Situation | Variant |
/// |-----------|---------|
/// | OID prefix not recognized | [`NoSuchObject`](GetResult::NoSuchObject) |
/// | Scalar object not implemented | [`NoSuchObject`](GetResult::NoSuchObject) |
/// | Table column not implemented | [`NoSuchObject`](GetResult::NoSuchObject) |
/// | Table row doesn't exist | [`NoSuchInstance`](GetResult::NoSuchInstance) |
/// | Scalar has no value (optional) | [`NoSuchInstance`](GetResult::NoSuchInstance) |
///
/// # Example: Scalar Objects
///
/// ```rust
/// use async_snmp::handler::GetResult;
/// use async_snmp::{Value, oid};
///
/// fn get_scalar(oid: &async_snmp::Oid) -> GetResult {
///     if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {  // sysDescr.0
///         GetResult::Value(Value::OctetString("My SNMP Agent".into()))
///     } else if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 2, 0) {  // sysObjectID.0
///         GetResult::Value(Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)))
///     } else {
///         GetResult::NoSuchObject
///     }
/// }
/// ```
///
/// # Example: Table Objects
///
/// ```rust
/// use async_snmp::handler::GetResult;
/// use async_snmp::{Value, Oid, oid};
///
/// struct IfTable {
///     entries: Vec<(u32, String)>,  // (index, description)
/// }
///
/// impl IfTable {
///     fn get(&self, oid: &Oid) -> GetResult {
///         let if_descr_prefix = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2);
///
///         if !oid.starts_with(&if_descr_prefix) {
///             return GetResult::NoSuchObject;  // Not our column
///         }
///
///         // Extract index from OID (position after prefix)
///         let arcs = oid.arcs();
///         if arcs.len() != if_descr_prefix.len() + 1 {
///             return GetResult::NoSuchInstance;  // Wrong index format
///         }
///
///         let index = arcs[if_descr_prefix.len()];
///         match self.entries.iter().find(|(i, _)| *i == index) {
///             Some((_, desc)) => GetResult::Value(Value::OctetString(desc.clone().into())),
///             None => GetResult::NoSuchInstance,  // Row doesn't exist
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum GetResult {
    /// The OID exists and has this value.
    Value(Value),
    /// The object type is not implemented by this agent.
    ///
    /// Use this when the OID prefix (object type) is not recognized.
    /// This typically means the handler doesn't implement this part of the MIB.
    NoSuchObject,
    /// The object type exists but this specific instance doesn't.
    ///
    /// Use this when the OID prefix is valid but the instance identifier
    /// (e.g., table index) doesn't exist. This is common for table objects
    /// where the row has been deleted or never existed.
    NoSuchInstance,
}

impl From<Value> for GetResult {
    fn from(value: Value) -> Self {
        GetResult::Value(value)
    }
}

/// Result of a GETNEXT operation (RFC 3416).
///
/// GETNEXT retrieves the lexicographically next OID after the requested one.
/// This is the foundation of SNMP walking (iterating through MIB subtrees)
/// and is also used internally by GETBULK.
///
/// # Version Differences
///
/// - **`SNMPv1`**: `EndOfMibView` results in a `noSuchName` error response
/// - **SNMPv2c/v3**: Returns the `endOfMibView` exception value in the response
///
/// # Lexicographic Ordering
///
/// OIDs are compared arc-by-arc as unsigned integers:
/// - `1.3.6.1.2` < `1.3.6.1.2.1` (shorter is less than longer with same prefix)
/// - `1.3.6.1.2.1` < `1.3.6.1.3` (compare at first differing arc)
/// - `1.3.6.1.10` > `1.3.6.1.9` (numeric comparison, not lexicographic string)
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::GetNextResult;
/// use async_snmp::{Value, VarBind, Oid, oid};
///
/// struct SimpleTable {
///     oids: Vec<(Oid, Value)>,  // Must be sorted!
/// }
///
/// impl SimpleTable {
///     fn get_next(&self, after: &Oid) -> GetNextResult {
///         // Find first OID that is strictly greater than 'after'
///         for (oid, value) in &self.oids {
///             if oid > after {
///                 return GetNextResult::Value(VarBind::new(oid.clone(), value.clone()));
///             }
///         }
///         GetNextResult::EndOfMibView
///     }
/// }
///
/// let table = SimpleTable {
///     oids: vec![
///         (oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), Value::OctetString("sysDescr".into())),
///         (oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), Value::TimeTicks(12345)),
///     ],
/// };
///
/// // Before first OID - returns first
/// let result = table.get_next(&oid!(1, 3, 6, 1, 2, 1, 1, 0));
/// assert!(result.is_value());
///
/// // After last OID - returns EndOfMibView
/// let result = table.get_next(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0));
/// assert!(result.is_end_of_mib_view());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum GetNextResult {
    /// The next OID/value pair in the MIB tree.
    ///
    /// The returned OID must be strictly greater than the input OID.
    Value(VarBind),
    /// No more OIDs after the given one (end of MIB view).
    ///
    /// Return this when the requested OID is at or past the last OID
    /// in your handler's subtree.
    EndOfMibView,
}

impl GetNextResult {
    /// Returns `true` if this is a value result.
    pub fn is_value(&self) -> bool {
        matches!(self, GetNextResult::Value(_))
    }

    /// Returns `true` if this is end of MIB view.
    pub fn is_end_of_mib_view(&self) -> bool {
        matches!(self, GetNextResult::EndOfMibView)
    }
}

impl From<VarBind> for GetNextResult {
    fn from(vb: VarBind) -> Self {
        GetNextResult::Value(vb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    #[test]
    fn test_get_result_from_value() {
        let result: GetResult = Value::Integer(42).into();
        assert!(matches!(result, GetResult::Value(Value::Integer(42))));
    }

    #[test]
    fn test_get_next_result_from_varbind() {
        let vb = VarBind::new(oid!(1, 3, 6, 1), Value::Integer(42));
        let result: GetNextResult = vb.clone().into();
        assert!(result.is_value());
        if let GetNextResult::Value(inner) = result {
            assert_eq!(inner.oid, oid!(1, 3, 6, 1));
        }
    }

    #[test]
    fn set_phase_errors_map_exhaustively() {
        fn test_status(error: SetTestError) -> ErrorStatus {
            match error {
                SetTestError::GeneralFailure => ErrorStatus::GenErr,
                SetTestError::NoAccess => ErrorStatus::NoAccess,
                SetTestError::NotWritable => ErrorStatus::NotWritable,
                SetTestError::WrongType => ErrorStatus::WrongType,
                SetTestError::WrongLength => ErrorStatus::WrongLength,
                SetTestError::WrongEncoding => ErrorStatus::WrongEncoding,
                SetTestError::WrongValue => ErrorStatus::WrongValue,
                SetTestError::NoCreation => ErrorStatus::NoCreation,
                SetTestError::InconsistentValue => ErrorStatus::InconsistentValue,
                SetTestError::ResourceUnavailable => ErrorStatus::ResourceUnavailable,
                SetTestError::InconsistentName => ErrorStatus::InconsistentName,
            }
        }

        for error in [
            SetTestError::GeneralFailure,
            SetTestError::NoAccess,
            SetTestError::NotWritable,
            SetTestError::WrongType,
            SetTestError::WrongLength,
            SetTestError::WrongEncoding,
            SetTestError::WrongValue,
            SetTestError::NoCreation,
            SetTestError::InconsistentValue,
            SetTestError::ResourceUnavailable,
            SetTestError::InconsistentName,
        ] {
            assert_eq!(error.to_error_status(), test_status(error));
        }
        assert_eq!(
            SetCommitError::Failed.to_error_status(),
            ErrorStatus::CommitFailed
        );
        assert_eq!(
            SetUndoError::Failed.to_error_status(),
            ErrorStatus::UndoFailed
        );
    }

    #[test]
    fn test_handler_error_message_only() {
        let err = HandlerError::new("backend down");
        assert_eq!(err.message(), "backend down");
        assert!(err.source().is_none());
        assert_eq!(err.to_string(), "backend down");
    }

    #[test]
    fn test_handler_error_from_std_error() {
        let io_err = std::io::Error::other("bus timeout");
        let err: HandlerError = io_err.into();
        assert_eq!(err.message(), "bus timeout");
        assert!(err.source().is_some());
        assert_eq!(err.to_string(), "bus timeout");
    }

    #[test]
    fn test_handler_error_question_mark_conversion() {
        fn inner() -> HandlerResult<GetResult> {
            Err(std::io::Error::other("no route"))?;
            unreachable!()
        }
        let err = inner().unwrap_err();
        assert_eq!(err.message(), "no route");
    }
}
