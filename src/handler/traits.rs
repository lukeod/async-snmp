//! `MibHandler` trait and related types.

use std::future::Future;
use std::pin::Pin;

use crate::oid::Oid;
use crate::value::Value;

use super::{GetNextResult, GetResult, HandlerResult, RequestContext, SetResult};

/// Type alias for boxed async return type (dyn-compatible).
///
/// This type is required because async trait methods cannot be object-safe.
/// All handler methods return `BoxFuture` to allow handlers to be stored
/// as trait objects in the agent.
///
/// # Example
///
/// ```rust
/// use async_snmp::handler::{BoxFuture, GetResult, HandlerResult};
///
/// fn example_async_fn<'a>(value: &'a i32) -> BoxFuture<'a, HandlerResult<GetResult>> {
///     Box::pin(async move {
///         // Async work here
///         Ok(GetResult::Value(async_snmp::Value::Integer(*value)))
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
/// - [`free_set`](MibHandler::free_set): Cleanup resources on test failure
/// - [`handles`](MibHandler::handles): Custom OID matching logic
///
/// # GET Implementation
///
/// The [`get`](MibHandler::get) method should return:
/// - `Ok(`[`GetResult::Value`]`)` if the OID exists and has a value
/// - `Ok(`[`GetResult::NoSuchObject`]`)` if the object type is not implemented
/// - `Ok(`[`GetResult::NoSuchInstance`]`)` if the object exists but this instance doesn't
/// - `Err(`[`HandlerError`](super::HandlerError)`)` if the handler failed to
///   determine an answer (backing store unreachable, hardware fault, ...)
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
/// # Error Handling
///
/// Both methods return [`HandlerResult`], so `?` works on any error type
/// implementing [`std::error::Error`]. Return `Err` only for *processing
/// failures* — "I could not find out" — never for "the object does not
/// exist", which is expressed by the `Ok` variants above. On `Err`, the
/// agent responds to the whole request with `genErr` and the error-index of
/// the failing variable binding (RFC 3416 Section 4.2.1), and logs the
/// error; the message is never sent to the manager.
///
/// # SET Two-Phase Commit (RFC 3416)
///
/// SET operations use a multi-phase protocol modeled after net-snmp's
/// RESERVE1/RESERVE2/ACTION/COMMIT/FREE/UNDO phases:
///
/// 1. **Test phase**: [`test_set`](MibHandler::test_set) is called for ALL varbinds
///    before any commits. If any test fails, [`free_set`](MibHandler::free_set)
///    is called for all previously successful varbinds (in reverse order) to
///    release resources allocated during the test phase.
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
/// use async_snmp::handler::{
///     MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, BoxFuture,
/// };
/// use async_snmp::{Oid, Value, VarBind, oid};
///
/// struct SystemInfoHandler {
///     sys_descr: String,
///     sys_uptime: u32,
/// }
///
/// impl MibHandler for SystemInfoHandler {
///     fn get<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         oid: &'a Oid,
///     ) -> BoxFuture<'a, HandlerResult<GetResult>> {
///         Box::pin(async move {
///             // sysDescr.0
///             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 1, 0) {
///                 return Ok(GetResult::Value(Value::OctetString(self.sys_descr.clone().into())));
///             }
///             // sysUpTime.0
///             if oid == &oid!(1, 3, 6, 1, 2, 1, 1, 3, 0) {
///                 return Ok(GetResult::Value(Value::TimeTicks(self.sys_uptime)));
///             }
///             Ok(GetResult::NoSuchObject)
///         })
///     }
///
///     fn get_next<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         oid: &'a Oid,
///     ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
///         Box::pin(async move {
///             let sys_descr = oid!(1, 3, 6, 1, 2, 1, 1, 1, 0);
///             let sys_uptime = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0);
///
///             // Return the next OID in lexicographic order
///             if oid < &sys_descr {
///                 return Ok(GetNextResult::Value(VarBind::new(
///                     sys_descr,
///                     Value::OctetString("My System".into())
///                 )));
///             }
///             if oid < &sys_uptime {
///                 return Ok(GetNextResult::Value(VarBind::new(
///                     sys_uptime,
///                     Value::TimeTicks(12345)
///                 )));
///             }
///             Ok(GetNextResult::EndOfMibView)
///         })
///     }
/// }
/// ```
///
/// # Example: Writable Handler
///
/// ```rust
/// use async_snmp::handler::{
///     MibHandler, RequestContext, GetResult, GetNextResult, HandlerResult, SetResult, BoxFuture
/// };
/// use async_snmp::{Oid, Value, VarBind, oid};
/// use std::sync::atomic::{AtomicI32, Ordering};
///
/// struct WritableHandler {
///     counter: AtomicI32,
/// }
///
/// impl MibHandler for WritableHandler {
///     fn get<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         oid: &'a Oid,
///     ) -> BoxFuture<'a, HandlerResult<GetResult>> {
///         Box::pin(async move {
///             if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
///                 return Ok(GetResult::Value(Value::Integer(
///                     self.counter.load(Ordering::Relaxed)
///                 )));
///             }
///             Ok(GetResult::NoSuchObject)
///         })
///     }
///
///     fn get_next<'a>(
///         &'a self,
///         _ctx: &'a RequestContext,
///         oid: &'a Oid,
///     ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
///         Box::pin(async move {
///             let my_oid = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
///             if oid < &my_oid {
///                 return Ok(GetNextResult::Value(VarBind::new(
///                     my_oid,
///                     Value::Integer(self.counter.load(Ordering::Relaxed))
///                 )));
///             }
///             Ok(GetNextResult::EndOfMibView)
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
    /// Return `Ok(`[`GetResult::Value`]`)` if the OID exists,
    /// `Ok(`[`GetResult::NoSuchObject`]`)` if the object type is not implemented,
    /// or `Ok(`[`GetResult::NoSuchInstance`]`)` if the object type exists but
    /// this specific instance doesn't.
    ///
    /// Return `Err(`[`HandlerError`](super::HandlerError)`)` only when the
    /// handler failed to determine an answer (e.g. its backing store is
    /// unreachable); the agent then responds to the whole request with
    /// `genErr` per RFC 3416 Section 4.2.1.
    ///
    /// See [`GetResult`] documentation for details on when to use each variant.
    fn get<'a>(
        &'a self,
        ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>>;

    /// Handle a GETNEXT request.
    ///
    /// Return `Ok(`[`GetNextResult::Value`]`)` with the lexicographically next
    /// OID and value after `oid`, or `Ok(`[`GetNextResult::EndOfMibView`]`)`
    /// if there are no more OIDs in this handler's subtree.
    ///
    /// Return `Err(`[`HandlerError`](super::HandlerError)`)` only when the
    /// handler failed to determine an answer; the agent then responds to the
    /// whole request (including GETBULK) with `genErr` per RFC 3416
    /// Section 4.2.1.
    fn get_next<'a>(
        &'a self,
        ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>>;

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
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async { SetResult::Ok })
    }

    /// Free resources allocated during `test_set` (cleanup on test failure).
    ///
    /// Called for varbinds whose `test_set` succeeded when a later varbind's
    /// `test_set` fails. This allows handlers to release any resources
    /// (locks, temporary allocations) acquired during the test phase.
    ///
    /// Called in reverse order, matching the `undo_set` convention.
    ///
    /// Default implementation does nothing.
    fn free_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Check if this handler handles the given OID.
    ///
    /// Default implementation returns true if the OID starts with
    /// the registered prefix (i.e., the OID is within this handler's subtree).
    /// Override for more complex matching.
    ///
    /// This method is used to route GET and SET requests. GETNEXT and GETBULK
    /// consult all handlers regardless of this method.
    fn handles(&self, registered_prefix: &Oid, oid: &Oid) -> bool {
        oid.starts_with(registered_prefix)
    }
}
