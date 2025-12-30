//! Result types for MIB handler operations.

use crate::error::ErrorStatus;
use crate::value::Value;
use crate::varbind::VarBind;

/// Result of a SET operation phase.
///
/// This enum is used by the three-phase SET protocol:
/// - `test_set`: Returns Ok if the SET would succeed
/// - `commit_set`: Returns Ok if the change was applied
/// - `undo_set`: Does not return SetResult (best-effort rollback)
///
/// The variants map to RFC 3416 error status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetResult {
    /// Operation succeeded.
    Ok,
    /// Access denied (security/authorization failure).
    ///
    /// Use this when the request lacks sufficient access rights to modify
    /// the object, based on the security context (user, community, etc.).
    /// Maps to RFC 3416 error status code 6 (noAccess).
    NoAccess,
    /// Object is inherently read-only (not writable by design).
    ///
    /// Use this when the object cannot be modified regardless of who
    /// is making the request. Maps to RFC 3416 error status code 17 (notWritable).
    NotWritable,
    /// Value has wrong ASN.1 type for this OID.
    WrongType,
    /// Value has wrong length for this OID.
    WrongLength,
    /// Value encoding is incorrect.
    WrongEncoding,
    /// Value is not valid for this OID (semantic check failed).
    WrongValue,
    /// Cannot create new row (table doesn't support row creation).
    NoCreation,
    /// Value is inconsistent with other values in the same SET.
    InconsistentValue,
    /// Resource unavailable (memory, locks, etc.).
    ResourceUnavailable,
    /// Commit failed (internal error during apply).
    CommitFailed,
    /// Undo failed (internal error during rollback).
    UndoFailed,
    /// Row name is inconsistent with existing data.
    InconsistentName,
}

impl SetResult {
    /// Check if this result indicates success.
    pub fn is_ok(&self) -> bool {
        matches!(self, SetResult::Ok)
    }

    /// Convert to an ErrorStatus code.
    pub fn to_error_status(&self) -> ErrorStatus {
        match self {
            SetResult::Ok => ErrorStatus::NoError,
            SetResult::NoAccess => ErrorStatus::NoAccess,
            SetResult::NotWritable => ErrorStatus::NotWritable,
            SetResult::WrongType => ErrorStatus::WrongType,
            SetResult::WrongLength => ErrorStatus::WrongLength,
            SetResult::WrongEncoding => ErrorStatus::WrongEncoding,
            SetResult::WrongValue => ErrorStatus::WrongValue,
            SetResult::NoCreation => ErrorStatus::NoCreation,
            SetResult::InconsistentValue => ErrorStatus::InconsistentValue,
            SetResult::ResourceUnavailable => ErrorStatus::ResourceUnavailable,
            SetResult::CommitFailed => ErrorStatus::CommitFailed,
            SetResult::UndoFailed => ErrorStatus::UndoFailed,
            SetResult::InconsistentName => ErrorStatus::InconsistentName,
        }
    }
}

/// Response to return from a handler.
///
/// This is typically built internally by the agent based on handler results.
#[derive(Debug, Clone)]
pub struct Response {
    /// Variable bindings in the response
    pub varbinds: Vec<VarBind>,
    /// Error status (0 = no error)
    pub error_status: ErrorStatus,
    /// Error index (1-based index of problematic varbind, 0 if no error)
    pub error_index: i32,
}

impl Response {
    /// Create a successful response with the given varbinds.
    pub fn success(varbinds: Vec<VarBind>) -> Self {
        Self {
            varbinds,
            error_status: ErrorStatus::NoError,
            error_index: 0,
        }
    }

    /// Create an error response.
    pub fn error(error_status: ErrorStatus, error_index: i32, varbinds: Vec<VarBind>) -> Self {
        Self {
            varbinds,
            error_status,
            error_index,
        }
    }
}

/// Result of a GET operation on a specific OID.
///
/// This enum distinguishes between the RFC 3416-mandated exception types:
/// - `Value`: The OID exists and has the given value
/// - `NoSuchObject`: The OID's object type is not supported (agent doesn't implement this MIB)
/// - `NoSuchInstance`: The object type exists but this specific instance doesn't
///   (e.g., table row doesn't exist)
///
/// For SNMPv1, both exception types result in a `noSuchName` error response.
/// For SNMPv2c/v3, they result in the appropriate exception value in the response.
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, BoxFuture};
/// use async_snmp::{Oid, Value, VarBind, oid};
///
/// struct IfTableHandler {
///     // Simulates interface table with indices 1 and 2
///     interfaces: Vec<u32>,
/// }
///
/// impl MibHandler for IfTableHandler {
///     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
///         Box::pin(async move {
///             let if_descr_prefix = oid!(1, 3, 6, 1, 2, 1, 2, 2, 1, 2);
///
///             if oid.starts_with(&if_descr_prefix) {
///                 // Extract index from OID
///                 if let Some(&index) = oid.arcs().get(if_descr_prefix.len()) {
///                     if self.interfaces.contains(&index) {
///                         return GetResult::Value(Value::OctetString(
///                             format!("eth{}", index - 1).into()
///                         ));
///                     }
///                     // Index exists in MIB but not in our table
///                     return GetResult::NoSuchInstance;
///                 }
///             }
///             // OID is not in our MIB at all
///             GetResult::NoSuchObject
///         })
///     }
///
///     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, _oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
///         Box::pin(async move { GetNextResult::EndOfMibView }) // Simplified
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
    NoSuchObject,
    /// The object type exists but this specific instance doesn't.
    ///
    /// Use this when the OID prefix is valid but the instance identifier
    /// (e.g., table index) doesn't exist.
    NoSuchInstance,
}

impl GetResult {
    /// Create a `GetResult` from an `Option<Value>`.
    ///
    /// This is a convenience method for migrating from the previous
    /// `Option<Value>` interface. `None` is treated as `NoSuchObject`.
    pub fn from_option(value: Option<Value>) -> Self {
        match value {
            Some(v) => GetResult::Value(v),
            None => GetResult::NoSuchObject,
        }
    }
}

impl From<Value> for GetResult {
    fn from(value: Value) -> Self {
        GetResult::Value(value)
    }
}

impl From<Option<Value>> for GetResult {
    fn from(value: Option<Value>) -> Self {
        GetResult::from_option(value)
    }
}

/// Result of a GETNEXT operation.
///
/// This enum provides symmetry with [`GetResult`] for the GETNEXT operation:
/// - `Value`: Returns the next OID/value pair in the MIB tree
/// - `EndOfMibView`: No more OIDs after the given one in this handler's subtree
///
/// For SNMPv1, `EndOfMibView` results in a `noSuchName` error response.
/// For SNMPv2c/v3, it results in the `endOfMibView` exception value.
#[derive(Debug, Clone, PartialEq)]
pub enum GetNextResult {
    /// The next OID/value pair in the MIB tree.
    Value(VarBind),
    /// No more OIDs after the given one (end of MIB view).
    EndOfMibView,
}

impl GetNextResult {
    /// Create a `GetNextResult` from an `Option<VarBind>`.
    ///
    /// This is a convenience method for migrating from the previous
    /// `Option<VarBind>` interface. `None` is treated as `EndOfMibView`.
    pub fn from_option(value: Option<VarBind>) -> Self {
        match value {
            Some(vb) => GetNextResult::Value(vb),
            None => GetNextResult::EndOfMibView,
        }
    }

    /// Returns `true` if this is a value result.
    pub fn is_value(&self) -> bool {
        matches!(self, GetNextResult::Value(_))
    }

    /// Returns `true` if this is end of MIB view.
    pub fn is_end_of_mib_view(&self) -> bool {
        matches!(self, GetNextResult::EndOfMibView)
    }

    /// Converts to an `Option<VarBind>`.
    pub fn into_option(self) -> Option<VarBind> {
        match self {
            GetNextResult::Value(vb) => Some(vb),
            GetNextResult::EndOfMibView => None,
        }
    }
}

impl From<VarBind> for GetNextResult {
    fn from(vb: VarBind) -> Self {
        GetNextResult::Value(vb)
    }
}

impl From<Option<VarBind>> for GetNextResult {
    fn from(value: Option<VarBind>) -> Self {
        GetNextResult::from_option(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oid;

    #[test]
    fn test_response_success() {
        let response = Response::success(vec![VarBind::new(oid!(1, 3, 6, 1), Value::Integer(1))]);
        assert_eq!(response.error_status, ErrorStatus::NoError);
        assert_eq!(response.error_index, 0);
        assert_eq!(response.varbinds.len(), 1);
    }

    #[test]
    fn test_response_error() {
        let response = Response::error(
            ErrorStatus::NoSuchName,
            1,
            vec![VarBind::new(oid!(1, 3, 6, 1), Value::Null)],
        );
        assert_eq!(response.error_status, ErrorStatus::NoSuchName);
        assert_eq!(response.error_index, 1);
    }

    #[test]
    fn test_get_result_from_option() {
        let result = GetResult::from_option(Some(Value::Integer(42)));
        assert!(matches!(result, GetResult::Value(Value::Integer(42))));

        let result = GetResult::from_option(None);
        assert!(matches!(result, GetResult::NoSuchObject));
    }

    #[test]
    fn test_get_result_from_value() {
        let result: GetResult = Value::Integer(42).into();
        assert!(matches!(result, GetResult::Value(Value::Integer(42))));
    }

    #[test]
    fn test_get_next_result_from_option() {
        let vb = VarBind::new(oid!(1, 3, 6, 1), Value::Integer(42));
        let result = GetNextResult::from_option(Some(vb.clone()));
        assert!(result.is_value());
        assert_eq!(result.into_option(), Some(vb));

        let result = GetNextResult::from_option(None);
        assert!(result.is_end_of_mib_view());
        assert_eq!(result.into_option(), None);
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
    fn test_set_result_to_error_status() {
        assert_eq!(SetResult::Ok.to_error_status(), ErrorStatus::NoError);
        assert_eq!(SetResult::NoAccess.to_error_status(), ErrorStatus::NoAccess);
        assert_eq!(
            SetResult::NotWritable.to_error_status(),
            ErrorStatus::NotWritable
        );
        assert_eq!(
            SetResult::WrongType.to_error_status(),
            ErrorStatus::WrongType
        );
        assert_eq!(
            SetResult::CommitFailed.to_error_status(),
            ErrorStatus::CommitFailed
        );
    }

    #[test]
    fn test_set_result_is_ok() {
        assert!(SetResult::Ok.is_ok());
        assert!(!SetResult::NoAccess.is_ok());
        assert!(!SetResult::NotWritable.is_ok());
    }
}
