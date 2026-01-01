//! Result types for MIB handler operations.
//!
//! This module provides the result types returned by [`MibHandler`](super::MibHandler)
//! methods:
//!
//! - [`GetResult`] - Result of a GET operation
//! - [`GetNextResult`] - Result of a GETNEXT operation
//! - [`SetResult`] - Result of SET test/commit phases
//! - [`Response`] - Internal response type (typically not used directly)

use crate::error::ErrorStatus;
use crate::value::Value;
use crate::varbind::VarBind;

/// Result of a SET operation phase (RFC 3416).
///
/// This enum is used by the two-phase SET protocol:
/// - [`MibHandler::test_set`](super::MibHandler::test_set): Returns `Ok` if the SET would succeed
/// - [`MibHandler::commit_set`](super::MibHandler::commit_set): Returns `Ok` if the change was applied
/// - [`MibHandler::undo_set`](super::MibHandler::undo_set): Does not return `SetResult` (best-effort)
///
/// # Choosing the Right Error
///
/// | Situation | Variant |
/// |-----------|---------|
/// | SET succeeded | [`Ok`](SetResult::Ok) |
/// | User lacks permission | [`NoAccess`](SetResult::NoAccess) |
/// | Object is read-only by design | [`NotWritable`](SetResult::NotWritable) |
/// | Wrong ASN.1 type (e.g., String for Integer) | [`WrongType`](SetResult::WrongType) |
/// | Value too long/short | [`WrongLength`](SetResult::WrongLength) |
/// | Value encoding error | [`WrongEncoding`](SetResult::WrongEncoding) |
/// | Semantic validation failed | [`WrongValue`](SetResult::WrongValue) |
/// | Cannot create table row | [`NoCreation`](SetResult::NoCreation) |
/// | Values conflict within request | [`InconsistentValue`](SetResult::InconsistentValue) |
/// | Out of memory, lock contention | [`ResourceUnavailable`](SetResult::ResourceUnavailable) |
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::SetResult;
/// use async_snmp::Value;
///
/// fn validate_admin_status(value: &Value) -> SetResult {
///     match value {
///         Value::Integer(v) if *v == 1 || *v == 2 => SetResult::Ok, // up(1) or down(2)
///         Value::Integer(_) => SetResult::WrongValue, // Invalid admin status
///         _ => SetResult::WrongType, // Must be Integer
///     }
/// }
///
/// assert_eq!(validate_admin_status(&Value::Integer(1)), SetResult::Ok);
/// assert_eq!(validate_admin_status(&Value::Integer(99)), SetResult::WrongValue);
/// assert_eq!(validate_admin_status(&Value::OctetString("up".into())), SetResult::WrongType);
/// ```
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
    ///
    /// Use when the provided value type doesn't match the expected type
    /// (e.g., OctetString provided for an Integer object).
    WrongType,
    /// Value has wrong length for this OID.
    ///
    /// Use when the value length violates constraints (e.g., DisplayString
    /// longer than 255 characters).
    WrongLength,
    /// Value encoding is incorrect.
    WrongEncoding,
    /// Value is not valid for this OID (semantic check failed).
    ///
    /// Use when the value type is correct but the value itself is invalid
    /// (e.g., negative value for an unsigned counter, or value outside
    /// an enumeration's valid range).
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
/// - **SNMPv1**: Both exception types result in a `noSuchName` error response
/// - **SNMPv2c/v3**: Returns the appropriate exception value in the response varbind
///
/// # Choosing NoSuchObject vs NoSuchInstance
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

/// Result of a GETNEXT operation (RFC 3416).
///
/// GETNEXT retrieves the lexicographically next OID after the requested one.
/// This is the foundation of SNMP walking (iterating through MIB subtrees)
/// and is also used internally by GETBULK.
///
/// # Version Differences
///
/// - **SNMPv1**: `EndOfMibView` results in a `noSuchName` error response
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
