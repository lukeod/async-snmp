//! `MibHandler` trait and related types.

use std::future::Future;
use std::pin::Pin;

use crate::oid::Oid;
use crate::value::Value;

use super::{
    GetNextResult, GetResult, HandlerResult, RequestContext, SetCommitResult, SetTestError,
    SetTestResult, SetUndoResult,
};

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

/// Request-owned state for one successfully tested SET varbind.
///
/// Implementations keep reservations, validated values, and rollback data in
/// this object. The agent stores heterogeneous prepared objects until every
/// varbind has passed [`MibHandler::test_set`], then drives the remaining
/// phases in RFC order.
///
/// The explicit async terminal methods [`undo`](Self::undo), [`free`](Self::free),
/// and [`finalize`](Self::finalize) perform protocol cleanup during normal
/// execution. `Drop` is only a synchronous fallback for reservations and local
/// resources if the request is cancelled or panics. It cannot await rollback
/// and therefore cannot guarantee transactional atomicity once commit has
/// started.
///
/// Terminal methods must disarm the `Drop` fallback *before* creating a future
/// that can reach an `.await`. Store fallback state in an `Option`, call
/// `take()` synchronously in the method body, then move the taken state into
/// the returned future. `Drop` must be idempotent when that `Option` is already
/// empty. The agent retains the prepared object while each callback runs and
/// drops all still-owned objects in reverse varbind order on cancellation.
pub trait PreparedSet: Send + 'static {
    /// Apply the prepared change.
    ///
    /// The agent retains ownership of this object after a successful commit so
    /// an earlier change can still be undone if a later binding fails. A
    /// failure may follow partial mutation and is followed by [`undo`](Self::undo).
    fn commit<'a>(
        &'a mut self,
        ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetCommitResult>;

    /// Roll back an attempted commit and release its reservation.
    ///
    /// Disarm synchronous fallback state before returning the future. On
    /// cancellation, the future and then the still-owned prepared object are
    /// dropped; `Drop` must tolerate the already-disarmed state.
    fn undo<'a>(
        &'a mut self,
        ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetUndoResult>;

    /// Release a reservation whose commit was never attempted.
    ///
    /// Disarm synchronous fallback state before returning the future. Override
    /// this when releasing a reservation must await I/O.
    fn free<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Release rollback data and reservations after every commit succeeds.
    ///
    /// This is the successful terminal path. It does not roll back the applied
    /// value. As with `undo` and `free`, take `Option`-held fallback state
    /// synchronously before returning a future that may await.
    fn finalize<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

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
///    fails, [`PreparedSet::free`] cleans earlier successful states in reverse
///    order. The failing test produces no state and receives no cleanup callback.
///
/// 2. **Commit phase**: [`PreparedSet::commit`] is called for each varbind in
///    order. A failed commit may have partially mutated state. On failure,
///    [`PreparedSet::undo`] cleans every attempted transaction in reverse
///    order, including the failed attempt. Later transactions whose commit was
///    never attempted are cleaned by [`PreparedSet::free`] in reverse order.
///    Cleanup continues if an `undo` call fails.
///
/// 3. **Successful finalization**: after every commit succeeds,
///    [`PreparedSet::finalize`] releases rollback data and reservations in
///    reverse order without undoing committed values.
///
/// The prepared object is owned by the request, so implementations can keep
/// reservations and rollback data directly in it instead of maintaining a
/// side table. Explicit terminal callbacks are the normal protocol cleanup.
/// Its [`Drop`] implementation is only a synchronous, idempotent fallback when
/// a request future is cancelled or panics; it cannot perform async rollback.
///
/// By default, handlers are read-only and return [`SetTestError::NotWritable`].
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
///     MibHandler, PreparedSet, RequestContext, GetResult, GetNextResult, HandlerResult,
///     SetCommitError, SetCommitResult, SetTestError, SetTestResult, SetUndoResult, BoxFuture,
/// };
/// use async_snmp::{Oid, Value, VarBind, oid};
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicI32, Ordering};
///
/// struct WritableHandler {
///     counter: Arc<AtomicI32>,
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
///     ) -> BoxFuture<'a, SetTestResult> {
///         Box::pin(async move {
///             if oid != &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
///                 return Err(SetTestError::NotWritable);
///             }
///             // Validate the value type
///             match value {
///                 Value::Integer(_) => Ok(Box::new(CounterUpdate {
///                     counter: self.counter.clone(),
///                     previous: None,
///                 }) as Box<dyn PreparedSet>),
///                 _ => Err(SetTestError::WrongType),
///             }
///         })
///     }
/// }
///
/// struct CounterUpdate {
///     counter: Arc<AtomicI32>,
///     previous: Option<i32>,
/// }
///
/// impl PreparedSet for CounterUpdate {
///     fn commit<'a>(
///         &'a mut self,
///         _ctx: &'a RequestContext,
///         _oid: &'a Oid,
///         value: &'a Value,
///     ) -> BoxFuture<'a, SetCommitResult> {
///         Box::pin(async move {
///             if let Value::Integer(v) = value {
///                 self.previous = Some(self.counter.swap(*v, Ordering::Relaxed));
///                 Ok(())
///             } else {
///                 Err(SetCommitError::Failed)
///             }
///         })
///     }
///
///     fn undo<'a>(
///         &'a mut self,
///         _ctx: &'a RequestContext,
///         _oid: &'a Oid,
///         _value: &'a Value,
///     ) -> BoxFuture<'a, SetUndoResult> {
///         Box::pin(async move {
///             if let Some(previous) = self.previous {
///                 self.counter.store(previous, Ordering::Relaxed);
///             }
///             Ok(())
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
    /// `Ok(prepared)`. The returned [`PreparedSet`] owns any reservation and
    /// rollback data for this varbind. `Err` must not leave resources for the
    /// framework to release because only successful tests enter pending state.
    /// If the test future acquires resources before it returns `Ok`, it must
    /// keep them in its own cancellation-safe guard until ownership transfers
    /// into the prepared object.
    ///
    /// Default implementation returns `NotWritable` (read-only handler).
    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetTestResult> {
        Box::pin(async { Err(SetTestError::NotWritable) })
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
