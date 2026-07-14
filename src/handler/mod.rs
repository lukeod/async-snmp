//! Handler types and traits for SNMP MIB operations.
//!
//! This module provides the interface for implementing SNMP agent handlers:
//!
//! - [`MibHandler`] - Trait for handling GET, GETNEXT, and SET operations
//! - [`RequestContext`] - Information about the incoming request
//! - [`GetResult`], [`GetNextResult`], [`SetResult`] - Operation results
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
//! # Basic Handler Example
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
//! # SET Operations and Multi-Phase Protocol
//!
//! SET operations follow a multi-phase protocol as defined in RFC 3416, modeled
//! after net-snmp's RESERVE/ACTION/COMMIT/FREE/UNDO phases:
//!
//! 1. **Test Phase**: [`MibHandler::test_set`] is called for ALL varbinds before any
//!    commits. If any test fails, [`MibHandler::free_set`] is called for all previously
//!    successful varbinds (in reverse order) to release resources, then the error is
//!    returned.
//!
//! 2. **Commit Phase**: [`MibHandler::commit_set`] is called for each varbind in order.
//!    If a commit fails, [`MibHandler::undo_set`] is called for all previously committed
//!    varbinds in reverse order.
//!
//! By default, handlers are read-only (returning [`SetResult::NotWritable`]).
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

pub use context::RequestContext;
pub use oid_table::OidTable;
pub use results::{GetNextResult, GetResult, HandlerError, HandlerResult, Response, SetResult};
pub use traits::{BoxFuture, MibHandler};

/// Security model identifiers (RFC 3411).
///
/// Used to specify which SNMP version/security mechanism a mapping applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityModel {
    /// Wildcard for VACM matching (matches any model).
    ///
    /// Use this when the same mapping should apply regardless of SNMP version.
    Any = 0,
    /// `SNMPv1`.
    V1 = 1,
    /// `SNMPv2c`.
    V2c = 2,
    /// `SNMPv3` User-based Security Model.
    Usm = 3,
}
