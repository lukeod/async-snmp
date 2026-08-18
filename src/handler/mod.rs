//! Handler types and traits for SNMP MIB operations.
//!
//! Defines the interface for implementing SNMP agent handlers:
//!
//! - [`MibHandler`] - Trait for handling GET, GETNEXT, and SET operations
//! - [`RequestContext`] - Information about the incoming request
//! - [`PreparedSet`], [`SetTestResult`] - Request-owned SET transaction state
//! - [`GetResult`], [`GetNextResult`] - Read operation results
//! - [`SetTestResult`], [`SetCommitResult`], [`SetUndoResult`] - SET phase results
//! - [`HandlerError`], [`HandlerResult`] - Processing failures, reported as `genErr`
//! - [`OidTable`] - Helper for implementing GETNEXT with sorted OID storage
//!
//! # Overview
//!
//! Handlers are registered with an [`Agent`](crate::agent::Agent) using a prefix OID.
//! When the agent receives a request, it dispatches to the handler with the longest
//! matching prefix. Each handler implements the [`MibHandler`] trait to respond to
//! GET, GETNEXT, and optionally SET operations.
//!
//! GET and GETNEXT return [`HandlerResult`], so `?` works on any
//! [`std::error::Error`] inside a handler. `Ok` carries the protocol answer —
//! including the "doesn't exist" exception values — while `Err` means the
//! handler failed to produce one (e.g. its backing store was unreachable) and
//! makes the agent answer the request with `genErr` (RFC 3416 Section 4.2.1).
//!
//! # Basic handler example
//!
//! A minimal handler that provides two scalar values:
//!
//! ```rust
//! use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, BoxFuture};
//! use async_snmp::{Oid, Value, VarBind, oid};
//!
//! struct MyHandler;
//!
//! impl MibHandler for MyHandler {
//!     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
//!         Box::pin(async move {
//!             if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
//!                 return Ok(GetResult::Value(Value::Integer(42)));
//!             }
//!             Ok(GetResult::NoSuchObject)
//!         })
//!     }
//!
//!     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
//!         Box::pin(async move {
//!             let my_oid = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
//!             if oid < &my_oid {
//!                 return Ok(GetNextResult::Value(VarBind::new(my_oid, Value::Integer(42))));
//!             }
//!             Ok(GetNextResult::EndOfMibView)
//!         })
//!     }
//! }
//! ```
//!
//! Choose `GetResult::NoSuchObject` or `GetResult::NoSuchInstance`, and
//! `GetNextResult::EndOfMibView`, explicitly. `From<Value>` and
//! `From<VarBind>` provide conversions for unambiguous value results.
//!
//! # SET operations and multi-phase protocol
//!
//! SET operations follow a multi-phase protocol as defined in RFC 3416, modeled
//! after net-snmp's RESERVE/ACTION/COMMIT/FREE/UNDO phases:
//!
//! 1. **Test Phase**: [`MibHandler::test_set`] is called for ALL varbinds before any
//!    commits. Each successful test returns a request-owned [`PreparedSet`]. If a
//!    test fails, [`PreparedSet::free`] cleans earlier successful reservations
//!    in reverse order; a failing test must not leave resources behind.
//!
//! 2. **Commit Phase**: [`PreparedSet::commit`] is called for each varbind in order.
//!    A failed commit may have partially mutated state, so [`PreparedSet::undo`]
//!    cleans every attempted binding in reverse order, including the failed
//!    attempt. Later prepared bindings receive [`PreparedSet::free`] in reverse
//!    order. Cleanup continues if undo fails.
//!
//! 3. **Finalization Phase**: after all commits succeed, [`PreparedSet::finalize`]
//!    releases rollback data and reservations in reverse order.
//!
//! Explicit terminal callbacks perform normal protocol cleanup. Prepared
//! objects may implement idempotent `Drop` for synchronous reservation/resource
//! fallback on cancellation or panic, but `Drop` cannot await rollback or
//! promise transactional atomicity after commit starts.
//! By default, handlers are read-only (returning [`SetTestError::NotWritable`]).
//! See [`MibHandler`] documentation for implementation details.
//!
//! # Using `OidTable` for GETNEXT
//!
//! For handlers with static or slowly-changing data, [`OidTable`] simplifies
//! GETNEXT implementation by maintaining OIDs in sorted order:
//!
//! ```rust
//! use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, OidTable, BoxFuture};
//! use async_snmp::{Oid, Value, VarBind, oid};
//!
//! struct StaticHandler {
//!     table: OidTable<Value>,
//! }
//!
//! impl StaticHandler {
//!     fn new() -> Self {
//!         let mut table = OidTable::new();
//!         table.insert(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(100));
//!         table.insert(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::OctetString("test".into()));
//!         Self { table }
//!     }
//! }
//!
//! impl MibHandler for StaticHandler {
//!     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetResult>> {
//!         Box::pin(async move {
//!             Ok(self.table.get(oid)
//!                 .cloned()
//!                 .map(GetResult::Value)
//!                 .unwrap_or(GetResult::NoSuchObject))
//!         })
//!     }
//!
//!     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
//!         Box::pin(async move {
//!             Ok(self.table.get_next(oid)
//!                 .map(|(o, v)| GetNextResult::Value(VarBind::new(o.clone(), v.clone())))
//!                 .unwrap_or(GetNextResult::EndOfMibView))
//!         })
//!     }
//! }

mod context;
mod oid_table;
mod results;
mod traits;

pub use context::{RequestContext, SecurityName};
pub(crate) use context::{RequestLifecycle, RequestTaskPhase};
pub use oid_table::OidTable;
pub use results::{
    GetNextResult, GetResult, HandlerError, HandlerResult, SetCommitError, SetCommitResult,
    SetTestError, SetTestResult, SetUndoError, SetUndoResult,
};
pub use traits::{BoxFuture, MibHandler, PreparedSet};

/// Concrete security model used to authenticate an SNMP request (RFC 3411).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityModel {
    /// `SNMPv1` community-based security.
    V1 = 1,
    /// `SNMPv2c` community-based security.
    V2c = 2,
    /// `SNMPv3` User-based Security Model.
    Usm = 3,
}

impl From<crate::message::V3SecurityModel> for SecurityModel {
    fn from(model: crate::message::V3SecurityModel) -> Self {
        match model {
            crate::message::V3SecurityModel::Usm => Self::Usm,
        }
    }
}

#[cfg(test)]
mod security_model_tests {
    use super::SecurityModel;
    use crate::message::V3SecurityModel;

    #[test]
    fn v3_wire_model_converts_to_concrete_request_model() {
        assert_eq!(
            SecurityModel::from(V3SecurityModel::Usm),
            SecurityModel::Usm
        );
    }
}
