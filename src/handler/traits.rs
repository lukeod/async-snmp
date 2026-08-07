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
/// - [`undo_set`](MibHandler::undo_set): Roll back attempted SET operations
/// - [`free_set`](MibHandler::free_set): Release uncommitted test-phase resources
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
///    before any commits. Only a successful test enters pending state. If a test
///    fails, [`free_set`](MibHandler::free_set) is called in reverse order for
///    earlier successful tests. The failing test receives no cleanup callback.
///
/// 2. **Commit phase**: [`commit_set`](MibHandler::commit_set) is called for each
///    varbind in order. A failed commit may have partially mutated state. On
///    failure, [`undo_set`](MibHandler::undo_set) is called in reverse order for
///    every attempted commit, including the failed attempt. Later bindings that
///    passed testing but were never attempted receive [`free_set`](MibHandler::free_set)
///    in reverse order. Cleanup continues if an `undo_set` call fails.
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
    /// Called for ALL varbinds before any commits. Must NOT modify persistent
    /// state. It may reserve locks or temporary resources when returning
    /// `SetResult::Ok`. A non-`Ok` result must not leave resources for the
    /// framework to release because only successful tests enter pending state.
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
    /// Only called after ALL `test_set` calls succeed. Should apply the change
    /// and finalize any test-phase reservation on success. A non-`Ok` result
    /// may follow partial mutation; `undo_set` will be called for this binding
    /// and every earlier attempted binding in reverse order. Later tested
    /// bindings whose commit was never attempted receive `free_set` instead.
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

    /// Undo an attempted SET operation (rollback on partial failure).
    ///
    /// Called after a `commit_set` failure for each binding whose commit was
    /// attempted, including the binding that returned the failure. This is the
    /// binding's terminal failure callback: restore the previous value and
    /// release its test-phase resources. `free_set` will not also be called for
    /// this binding. Cleanup is best-effort and continues in reverse attempt
    /// order after an undo failure.
    ///
    /// Default implementation reports successful cleanup without doing work.
    fn undo_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async { SetResult::Ok })
    }

    /// Free resources allocated during `test_set` when commit was not attempted.
    ///
    /// Called for successful tests when a later test fails, or for bindings
    /// after a failed commit whose own commit was never attempted. This is the
    /// binding's terminal failure callback and must release its test-phase
    /// resources; it must not assume `commit_set` ran. Bindings whose commit was
    /// attempted receive `undo_set` instead, never both callbacks.
    ///
    /// Called in reverse binding order.
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
