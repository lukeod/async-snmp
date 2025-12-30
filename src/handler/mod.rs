//! Handler types and traits for SNMP MIB operations.
//!
//! This module provides the interface for implementing SNMP handlers:
//!
//! - [`MibHandler`] - Trait for handling GET, GETNEXT, and SET operations
//! - [`RequestContext`] - Information about the incoming request
//! - [`GetResult`], [`GetNextResult`], [`SetResult`] - Operation results
//! - [`OidTable`] - Helper for implementing GETNEXT with sorted OID storage
//!
//! # Example
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
