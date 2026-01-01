//! MibHandler trait and related types.

use std::future::Future;
use std::pin::Pin;

use crate::oid::Oid;
use crate::value::Value;

use super::{GetNextResult, GetResult, RequestContext, SetResult};

/// Type alias for boxed async return type (dyn-compatible).
///
/// This type is required because async trait methods cannot be object-safe.
/// All handler methods return `BoxFuture` to allow handlers to be stored
/// as trait objects in the agent.
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::{BoxFuture, GetResult};
///
/// fn example_async_fn<'a>(value: &'a i32) -> BoxFuture<'a, GetResult> {
///     Box::pin(async move {
///         // Async work here
///         GetResult::Value(async_snmp::Value::Integer(*value))
///     })
/// }
/// ```
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Handler for SNMP MIB operations.
///
/// Implement this trait to provide values for a subtree of OIDs.
/// Register handlers with [`AgentBuilder::handler()`](crate::agent::AgentBuilder::handler)
/// using a prefix OID.
///
/// # Required Methods
///
/// - [`get`](MibHandler::get): Handle GET requests for specific OIDs
/// - [`get_next`](MibHandler::get_next): Handle GETNEXT/GETBULK requests
///
/// # Optional Methods
///
/// - [`test_set`](MibHandler::test_set): Validate SET operations (default: read-only)
/// - [`commit_set`](MibHandler::commit_set): Apply SET operations (default: read-only)
/// - [`undo_set`](MibHandler::undo_set): Rollback failed SET operations
/// - [`handles`](MibHandler::handles): Custom OID matching logic
///
/// # GET Implementation
///
/// The [`get`](MibHandler::get) method should return:
/// - [`GetResult::Value`] if the OID exists and has a value
/// - [`GetResult::NoSuchObject`] if the object type is not implemented
/// - [`GetResult::NoSuchInstance`] if the object exists but this instance doesn't
///
/// # GETNEXT and Lexicographic Ordering
///
/// The [`get_next`](MibHandler::get_next) method must return the lexicographically
/// next OID after the requested one. OIDs are compared arc-by-arc as unsigned integers.
/// For example: `1.3.6.1.2` < `1.3.6.1.2.1` < `1.3.6.1.3`.
///
/// Key considerations:
/// - The returned OID must be strictly greater than the input OID
/// - GETBULK uses GETNEXT repeatedly, so efficient implementation matters
/// - Use [`OidTable`](super::OidTable) to simplify sorted OID management
///
/// # SET Two-Phase Commit (RFC 3416)
///
/// SET operations use a two-phase commit protocol for atomicity:
///
/// 1. **Test phase**: [`test_set`](MibHandler::test_set) is called for ALL varbinds
///    before any commits. If any test fails, no changes are made.
///
/// 2. **Commit phase**: [`commit_set`](MibHandler::commit_set) is called for each
///    varbind in order. If a commit fails, [`undo_set`](MibHandler::undo_set) is
///    called for all previously committed varbinds (in reverse order).
///
/// By default, handlers are read-only and return [`SetResult::NotWritable`].
///
/// # Bounds
///
/// The `'static` bound is required because handlers are stored as
/// `Arc<dyn MibHandler>` within the agent. This allows the agent to
/// hold handlers for its entire lifetime without lifetime annotations.
/// In practice, most handlers naturally satisfy this bound.
///
/// # Thread Safety
///
/// Handlers must be `Send + Sync` because the agent may process
/// requests concurrently from multiple tasks.
///
/// # Example: Read-Only Handler
///
/// ```rust
/// use async_snmp::handler::{MibHandler, RequestContext, GetResult, GetNextResult, BoxFuture};
/// use async_snmp::{Oid, Value, VarBind, oid};
///
/// struct SystemInfoHandler {
///     sys_descr: String,
///     sys_uptime: u32,
/// }
///
/// impl MibHandler for SystemInfoHandler {
///     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
///         Box::pin(async move {
///             // sysDescr.0
///             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
///                 return GetResult::Value(Value::OctetString(self.sys_descr.clone().into()));
///             }
///             // sysUpTime.0
///             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 3, 0) {
///                 return GetResult::Value(Value::TimeTicks(self.sys_uptime));
///             }
///             GetResult::NoSuchObject
///         })
///     }
///
///     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
///         Box::pin(async move {
///             let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
///             let sys_uptime = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0);
///
///             // Return the next OID in lexicographic order
///             if oid < &sys_descr {
///                 return GetNextResult::Value(VarBind::new(
///                     sys_descr,
///                     Value::OctetString("My System".into())
///                 ));
///             }
///             if oid < &sys_uptime {
///                 return GetNextResult::Value(VarBind::new(
///                     sys_uptime,
///                     Value::TimeTicks(12345)
///                 ));
///             }
///             GetNextResult::EndOfMibView
///         })
///     }
/// }
/// ```
///
/// # Example: Writable Handler
///
/// ```rust
/// use async_snmp::handler::{
///     MibHandler, RequestContext, GetResult, GetNextResult, SetResult, BoxFuture
/// };
/// use async_snmp::{Oid, Value, VarBind, oid};
/// use std::sync::atomic::{AtomicI32, Ordering};
///
/// struct WritableHandler {
///     counter: AtomicI32,
/// }
///
/// impl MibHandler for WritableHandler {
///     fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
///         Box::pin(async move {
///             if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
///                 return GetResult::Value(Value::Integer(
///                     self.counter.load(Ordering::Relaxed)
///                 ));
///             }
///             GetResult::NoSuchObject
///         })
///     }
///
///     fn get_next<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetNextResult> {
///         Box::pin(async move {
///             let my_oid = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
///             if oid < &my_oid {
///                 return GetNextResult::Value(VarBind::new(
///                     my_oid,
///                     Value::Integer(self.counter.load(Ordering::Relaxed))
///                 ));
///             }
///             GetNextResult::EndOfMibView
///         })
///     }
///
///     fn test_set<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         oid: &'a Oid,
///         value: &'a Value,
///     ) -> BoxFuture<'a, SetResult> {
///         Box::pin(async move {
///             if oid != &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
///                 return SetResult::NotWritable;
///             }
///             // Validate the value type
///             match value {
///                 Value::Integer(_) => SetResult::Ok,
///                 _ => SetResult::WrongType,
///             }
///         })
///     }
///
///     fn commit_set<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         _oid: &'a Oid,
///         value: &'a Value,
///     ) -> BoxFuture<'a, SetResult> {
///         Box::pin(async move {
///             if let Value::Integer(v) = value {
///                 self.counter.store(*v, Ordering::Relaxed);
///                 SetResult::Ok
///             } else {
///                 SetResult::CommitFailed
///             }
///         })
///     }
/// }
/// ```
pub trait MibHandler: Send + Sync + 'static {
    /// Handle a GET request for a specific OID.
    ///
    /// Return [`GetResult::Value`] if the OID exists, [`GetResult::NoSuchObject`]
    /// if the object type is not implemented, or [`GetResult::NoSuchInstance`]
    /// if the object type exists but this specific instance doesn't.
    ///
    /// See [`GetResult`] documentation for details on when to use each variant.
    fn get<'a>(&'a self, ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult>;

    /// Handle a GETNEXT request.
    ///
    /// Return [`GetNextResult::Value`] with the lexicographically next OID and value
    /// after `oid`, or [`GetNextResult::EndOfMibView`] if there are no more OIDs
    /// in this handler's subtree.
    fn get_next<'a>(
        &'a self,
        ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, GetNextResult>;

    /// Test if a SET operation would succeed (phase 1 of two-phase commit).
    ///
    /// Called for ALL varbinds before any commits. Must NOT modify state.
    /// Return `SetResult::Ok` if the SET would succeed, or an appropriate
    /// error otherwise.
    ///
    /// Default implementation returns `NotWritable` (read-only handler).
    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async { SetResult::NotWritable })
    }

    /// Commit a SET operation (phase 2 of two-phase commit).
    ///
    /// Only called after ALL `test_set` calls succeed. Should apply the change.
    /// If this fails, `undo_set` will be called for all previously committed
    /// varbinds in this request.
    ///
    /// Default implementation returns `NotWritable` (read-only handler).
    fn commit_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async { SetResult::NotWritable })
    }

    /// Undo a committed SET operation (rollback on partial failure).
    ///
    /// Called if a later `commit_set` fails. Should restore the previous value.
    /// This is best-effort: if undo fails, log a warning but continue.
    ///
    /// Default implementation does nothing (no rollback support).
    fn undo_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Check if this handler handles the given OID prefix.
    ///
    /// Default implementation returns true if the OID starts with
    /// the registered prefix or is lexicographically before it
    /// (for GETNEXT support). Override for more complex matching.
    fn handles(&self, registered_prefix: &Oid, oid: &Oid) -> bool {
        oid.starts_with(registered_prefix) || oid < registered_prefix
    }
}
