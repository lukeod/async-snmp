//! Handler types and traits for SNMP MIB operations.
//!
//! This module provides the interface for implementing SNMP agent handlers:
//!
//! - [`MibHandler`] - Trait for handling GET, GETNEXT, and SET operations
//! - [`RequestContext`] - Information about the incoming request
//! - [`GetResult`], [`GetNextResult`], [`SetResult`] - Operation results
//! - [`OidTable`] - Helper for implementing GETNEXT with sorted OID storage
//!
//! # Overview
//!
//! Handlers are registered with an [`Agent`](crate::agent::Agent) using a prefix OID.
//! When the agent receives a request, it dispatches to the handler with the longest
//! matching prefix. Each handler implements the [`MibHandler`] trait to respond to
//! GET, GETNEXT, and optionally SET operations.
//!
//! # Basic Handler Example
//!
//! A minimal handler that provides two scalar values:
//!
//! ```rust
//! use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, BoxFuture};
//! use async_snmp::{Oid, Value, VarBind, oid};
//!
//! struct MyHandler;
//!
//! impl MibHandler for MyHandler {
//!     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
//!         Box::pin(async move {
//!             if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
//!                 return GetResult::Value(Value::Integer(42));
//!             }
//!             GetResult::NoSuchObject
//!         })
//!     }
//!
//!     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
//!         Box::pin(async move {
//!             let my_oid = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
//!             if oid < &my_oid {
//!                 return GetNextResult::Value(VarBind::new(my_oid, Value::Integer(42)));
//!             }
//!             GetNextResult::EndOfMibView
//!         })
//!     }
//! }
//! ```
//!
//! # SET Operations and Two-Phase Commit
//!
//! SET operations follow a two-phase commit protocol as defined in RFC 3416:
//!
//! 1. **Test Phase**: [`MibHandler::test_set`] is called for ALL varbinds before any
//!    commits. If any test fails, no changes are made and the appropriate error is
//!    returned.
//!
//! 2. **Commit Phase**: [`MibHandler::commit_set`] is called for each varbind in order.
//!    If a commit fails, [`MibHandler::undo_set`] is called for all previously committed
//!    varbinds in reverse order.
//!
//! By default, handlers are read-only (returning [`SetResult::NotWritable`]).
//! See [`MibHandler`] documentation for implementation details.
//!
//! # Using OidTable for GETNEXT
//!
//! For handlers with static or slowly-changing data, [`OidTable`] simplifies
//! GETNEXT implementation by maintaining OIDs in sorted order:
//!
//! ```rust
//! use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, OidTable, BoxFuture};
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
//!     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
//!         Box::pin(async move {
//!             self.table.get(oid)
//!                 .cloned()
//!                 .map(GetResult::Value)
//!                 .unwrap_or(GetResult::NoSuchObject)
//!         })
//!     }
//!
//!     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
//!         Box::pin(async move {
//!             self.table.get_next(oid)
//!                 .map(|(o, v)| GetNextResult::Value(VarBind::new(o.clone(), v.clone())))
//!                 .unwrap_or(GetNextResult::EndOfMibView)
//!         })
//!     }
//! }

mod context;
mod oid_table;
mod results;
mod traits;

pub use context::RequestContext;
pub use oid_table::OidTable;
pub use results::{GetNextResult, GetResult, Response, SetResult};
pub use traits::{BoxFuture, MibHandler};

// Re-export SecurityModel from agent::vacm for convenience
pub use crate::agent::vacm::SecurityModel;
