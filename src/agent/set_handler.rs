//! Multi-phase SET protocol (RFC 3416).
//!
//! Implements the SET phases modeled after net-snmp's approach:
//!
//! - **Test**: Each successful `test_set` returns request-owned prepared state.
//!   If a later test fails, clean earlier states through `PreparedSet::free` in
//!   reverse order.
//! - **Commit**: Apply each prepared state via `PreparedSet::commit`. If one
//!   fails, clean every attempted state through `PreparedSet::undo`, including
//!   the failing binding, in reverse order; clean later states through `free`.

use crate::error::{ErrorStatus, Result};
use crate::handler::{PreparedSet, RequestContext};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::value::Value;
use crate::version::Version;

use super::Agent;

struct PendingSet<'a> {
    prepared: Option<Box<dyn PreparedSet>>,
    oid: &'a Oid,
    value: &'a Value,
}

/// Owns all prepared states until their explicit terminal callback completes.
///
/// Manual popping makes cancellation and panic fallback order independent of
/// collection/destructor implementation details.
struct SetTransaction<'a> {
    pending: Vec<PendingSet<'a>>,
}

impl Drop for SetTransaction<'_> {
    fn drop(&mut self) {
        while let Some(mut pending) = self.pending.pop() {
            drop(pending.prepared.take());
        }
    }
}

impl Agent {
    /// Handle SET request with multi-phase commit protocol.
    ///
    /// On normal completion, the RFC 3416 SET phases provide atomic rollback:
    /// 1. **Test phase**: Call `test_set` for ALL varbinds. If any fails,
    ///    call `PreparedSet::free` for all previously successful varbinds (in reverse
    ///    order) to release resources, then return the error.
    /// 2. **Commit phase**: Call `PreparedSet::commit` for each varbind. If any
    ///    fails, call `PreparedSet::undo` for every attempted binding, including
    ///    the failing binding, in reverse order. Call `PreparedSet::free` for later
    ///    tested bindings whose commit was never attempted.
    ///
    /// Cancellation or panic instead invokes synchronous `Drop` fallback in
    /// reverse order. Since `Drop` cannot await protocol rollback, atomicity is
    /// not guaranteed if interruption occurs after commit starts.
    ///
    /// Per RFC 3416 Section 4.2.5 step (1), the size of the Response (which
    /// echoes the request varbinds) is checked up front: if it would exceed the
    /// message-size limit the operation terminates immediately with a `tooBig`
    /// Response, before the test or commit phases run, so an oversized SET is
    /// never applied.
    pub(super) async fn handle_set(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        // The message-envelope path performs an exact preflight encoding before
        // dispatch, so an oversized SET never reaches the test/commit phases.

        // One Agent owns one complete mutation lifecycle at a time. Keep this
        // guard through test, commit, rollback/free, and success finalization so
        // rollback from an older request cannot erase a newer SET.
        let _set_guard = self.inner.set_coordinator.lock().await;

        // The coordinator retains each object across async terminal callbacks.
        // Its Drop fallback releases every still-owned object in reverse order.
        let mut transaction = SetTransaction {
            pending: Vec::with_capacity(pdu.varbinds.len()),
        };

        // ========== PHASE 1: TEST ==========
        // Check VACM and call test_set for all varbinds
        for (index, vb) in pdu.varbinds.iter().enumerate() {
            // VACM write access check
            if let Some(vacm) = self.inner.authorization.vacm()
                && !vacm.check_access(ctx.write_view(), &vb.oid)
            {
                // Free resources for all previously successful varbinds
                while let Some(index) = transaction.pending.len().checked_sub(1) {
                    let p = &mut transaction.pending[index];
                    p.prepared
                        .as_mut()
                        .expect("pending SET state must be present")
                        .free(ctx, p.oid, p.value)
                        .await;
                    transaction.pending.pop();
                }
                // v2c/v3 report noAccess; v1 downgrades it to noSuchName.
                let status = ErrorStatus::NoAccess;
                let status = if ctx.version() == Version::V1 {
                    status.to_v1()
                } else {
                    status
                };
                return pdu.to_error_response(ctx.version(), status, index + 1);
            }

            let handler = self.find_handler(&vb.oid);

            if handler.is_none() {
                // Free resources for all previously successful varbinds
                while let Some(index) = transaction.pending.len().checked_sub(1) {
                    let p = &mut transaction.pending[index];
                    p.prepared
                        .as_mut()
                        .expect("pending SET state must be present")
                        .free(ctx, p.oid, p.value)
                        .await;
                    transaction.pending.pop();
                }
                // No handler for this OID: v2c/v3 report notWritable; v1
                // downgrades it to noSuchName.
                let status = ErrorStatus::NotWritable;
                let status = if ctx.version() == Version::V1 {
                    status.to_v1()
                } else {
                    status
                };
                return pdu.to_error_response(ctx.version(), status, index + 1);
            }

            let handler = handler.unwrap();
            let prepared = match handler.handler.test_set(ctx, &vb.oid, &vb.value).await {
                Ok(prepared) => prepared,
                Err(result) => {
                    // Free earlier successful reservations in reverse order.
                    while let Some(index) = transaction.pending.len().checked_sub(1) {
                        let p = &mut transaction.pending[index];
                        p.prepared
                            .as_mut()
                            .expect("pending SET state must be present")
                            .free(ctx, p.oid, p.value)
                            .await;
                        transaction.pending.pop();
                    }

                    let status = result.to_error_status();
                    let status = if ctx.version() == Version::V1 {
                        status.to_v1()
                    } else {
                        status
                    };
                    return pdu.to_error_response(ctx.version(), status, index + 1);
                }
            };

            transaction.pending.push(PendingSet {
                prepared: Some(prepared),
                oid: &vb.oid,
                value: &vb.value,
            });
        }

        // ========== PHASE 2: COMMIT ==========
        // All tests passed, now commit each varbind
        for index in 0..transaction.pending.len() {
            let p = &mut transaction.pending[index];
            let result = p
                .prepared
                .as_mut()
                .expect("pending SET state must be present")
                .commit(ctx, p.oid, p.value)
                .await;

            if let Err(commit_error) = result {
                // A failed commit may have partially mutated state. Undo every
                // attempted binding, including the failing one, in reverse order.
                let mut undo_failure = None;
                for (attempted_index, attempted) in
                    transaction.pending[..=index].iter_mut().enumerate().rev()
                {
                    let undo_result = attempted
                        .prepared
                        .as_mut()
                        .expect("attempted SET state must be present")
                        .undo(ctx, attempted.oid, attempted.value)
                        .await;
                    if let Err(error) = undo_result {
                        undo_failure.get_or_insert((error, attempted_index));
                        tracing::warn!(target: "async_snmp::agent", { oid = %attempted.oid }, "prepared SET undo failed during rollback");
                    }
                    drop(attempted.prepared.take());
                }

                // Later bindings passed test_set but were never committed, so
                // release their test-phase resources without attempting undo.
                for unattempted in transaction.pending[index + 1..].iter_mut().rev() {
                    unattempted
                        .prepared
                        .as_mut()
                        .expect("unattempted SET state must be present")
                        .free(ctx, unattempted.oid, unattempted.value)
                        .await;
                    drop(unattempted.prepared.take());
                }

                let (status, error_index) = match undo_failure {
                    Some((error, failed_undo_index)) => {
                        let status = error.to_error_status();
                        if ctx.version() == Version::V1 {
                            // RFC 2576 maps undoFailed to v1 genErr; retain the
                            // binding identity required by the v1 error.
                            (status.to_v1(), (failed_undo_index + 1) as i32)
                        } else {
                            // RFC 3416 4.2.5: native undoFailed responses carry
                            // error-index zero.
                            (status, 0)
                        }
                    }
                    None => {
                        let status = commit_error.to_error_status();
                        let status = if ctx.version() == Version::V1 {
                            status.to_v1()
                        } else {
                            status
                        };
                        // commitFailed, or its v1 genErr downgrade, identifies
                        // the binding whose commit failed.
                        (status, (index + 1) as i32)
                    }
                };
                return pdu.to_error_response(
                    ctx.version(),
                    status,
                    usize::try_from(error_index).unwrap_or(0),
                );
            }
        }

        // All commits succeeded. Explicitly finalize rollback state and
        // reservations; Drop is only a cancellation/panic fallback.
        while let Some(index) = transaction.pending.len().checked_sub(1) {
            let p = &mut transaction.pending[index];
            p.prepared
                .as_mut()
                .expect("pending SET state must be present")
                .finalize(ctx, p.oid, p.value)
                .await;
            transaction.pending.pop();
        }

        pdu.to_response(ctx.version())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

    use crate::Oid;
    use crate::agent::Agent;
    use crate::error::ErrorStatus;
    use crate::handler::{
        BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, PreparedSet,
        RequestContext, SetCommitError, SetCommitResult, SetTestError, SetTestResult, SetUndoError,
        SetUndoResult,
    };
    use crate::oid;
    use crate::pdu::{Pdu, PduType};
    use crate::value::Value;
    use crate::varbind::VarBind;
    use crate::version::Version;
    use tokio::sync::Semaphore;

    /// Handler that accepts `test_set` for .99999.1.0 but rejects .99999.2.0,
    /// tracking prepared-state `free` calls via an atomic counter.
    struct FreeSetTracker {
        free_count: Arc<AtomicU32>,
    }

    struct FreeTrackedSet {
        free_count: Arc<AtomicU32>,
    }

    impl PreparedSet for FreeTrackedSet {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            Box::pin(async { Ok(()) })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async { Ok(()) })
        }

        fn free<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.free_count.fetch_add(1, Ordering::Relaxed);
            })
        }
    }

    impl MibHandler for FreeSetTracker {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            Box::pin(async move {
                // Accept .99999.1.0, reject .99999.2.0
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    Err(SetTestError::WrongValue)
                } else {
                    Ok(Box::new(FreeTrackedSet {
                        free_count: self.free_count.clone(),
                    }) as Box<dyn PreparedSet>)
                }
            })
        }
    }

    fn test_ctx() -> RequestContext {
        crate::test_support::request_context(PduType::SetRequest)
    }

    struct GeneralFailureHandler;

    struct NoopPreparedSet;

    impl PreparedSet for NoopPreparedSet {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            Box::pin(async { Ok(()) })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async { Ok(()) })
        }
    }

    impl MibHandler for GeneralFailureHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            if oid == &set_oid(2) {
                Box::pin(async { Err(SetTestError::GeneralFailure) })
            } else {
                Box::pin(async { Ok(Box::new(NoopPreparedSet) as Box<dyn PreparedSet>) })
            }
        }
    }

    #[tokio::test]
    async fn general_test_failure_maps_to_gen_err_and_failed_index_for_all_versions() {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999),
                Arc::new(GeneralFailureHandler),
            )
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            vec![
                VarBind::new(set_oid(1), Value::Integer(1)),
                VarBind::new(set_oid(2), Value::Integer(2)),
            ],
        );

        for version in [Version::V1, Version::V2c, Version::V3] {
            let ctx =
                crate::test_support::request_context_for_version(version, PduType::SetRequest);
            let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
            assert_eq!(
                response.error_status(),
                ErrorStatus::GenErr.as_i32(),
                "status for {version:?}"
            );
            assert_eq!(response.error_index(), 2, "index for {version:?}");
        }
    }

    #[tokio::test]
    async fn test_free_set_called_on_test_failure() {
        let free_count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(FreeSetTracker {
            free_count: free_count.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // SET with two varbinds: first succeeds test_set, second fails.
        // PreparedSet::free should be called once (for the first varbind).
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(1)),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::Integer(2)),
            ],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // Should have error on varbind 2
        assert_eq!(response.error_index(), 2);
        // PreparedSet::free should have been called once for the first varbind.
        assert_eq!(free_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_free_set_not_called_on_success() {
        let free_count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(FreeSetTracker {
            free_count: free_count.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // SET with one varbind that passes test_set. No free_set should be called.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Integer(1),
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status(), 0);
        assert_eq!(free_count.load(Ordering::Relaxed), 0);
    }

    /// Handler that always accepts test_set and counts prepared commit invocations,
    /// used to prove the SET size check terminates before the commit phase.
    struct CommitTracker {
        commit_count: Arc<AtomicU32>,
    }

    struct CountedCommit {
        commit_count: Arc<AtomicU32>,
    }

    impl PreparedSet for CountedCommit {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            self.commit_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async { Ok(()) })
        }
    }

    impl MibHandler for CommitTracker {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            Box::pin(async move {
                Ok(Box::new(CountedCommit {
                    commit_count: self.commit_count.clone(),
                }) as Box<dyn PreparedSet>)
            })
        }
    }

    fn five_set_varbinds() -> Vec<VarBind> {
        (1u32..=5)
            .map(|i| {
                VarBind::new(
                    oid!(1, 3, 6, 1, 4, 1, 99999, i, 0),
                    Value::Integer(i as i32),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn test_set_too_big_returns_toobig_and_skips_commit() {
        let commit_count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(CommitTracker {
            commit_count: commit_count.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(80)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();

        // The echoed Response for five varbinds exceeds the 80-byte limit.
        // RFC 3416 Section 4.2.5 requires returning tooBig before any commit.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            five_set_varbinds(),
        );

        let request = crate::message::CommunityMessage::v2c(b"public".as_slice(), pdu)
            .unwrap()
            .encode()
            .unwrap();
        let response = agent
            .handle_v2c(request, "127.0.0.1:161".parse().unwrap())
            .await
            .unwrap()
            .unwrap();
        let response = crate::message::CommunityMessage::decode(response).unwrap();
        let response = response.pdu().standard().unwrap();
        assert_eq!(response.error_status(), ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index(), 0);
        assert!(response.varbinds.is_empty());
        // The commit phase must never run for an oversized SET.
        assert_eq!(commit_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_set_within_limit_commits() {
        let commit_count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(CommitTracker {
            commit_count: commit_count.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .max_message_size(150)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // A single-varbind SET fits within the limit and must commit normally.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Integer(1),
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), 0);
        assert_eq!(commit_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_free_set_not_called_when_first_varbind_fails() {
        let free_count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(FreeSetTracker {
            free_count: free_count.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // SET where the first varbind fails test_set. No free calls since
        // there are no previously successful varbinds.
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
                Value::Integer(1),
            )],
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_index(), 1);
        assert_eq!(free_count.load(Ordering::Relaxed), 0);
    }

    /// Handler for exercising the complete commit-failure lifecycle. Every
    /// callback is recorded by OID, and commit/undo failures can be injected.
    struct CommitFailHandler {
        fail_test_oid: Option<Oid>,
        fail_commit_oid: Oid,
        fail_undo_oids: Vec<Oid>,
        calls: Arc<Mutex<SetLifecycleCalls>>,
        values: Arc<Mutex<Vec<i32>>>,
    }

    struct FalliblePreparedSet {
        prepared_oid: Oid,
        fail_commit_oid: Oid,
        fail_undo_oids: Vec<Oid>,
        calls: Arc<Mutex<SetLifecycleCalls>>,
        values: Arc<Mutex<Vec<i32>>>,
        previous: Option<i32>,
    }

    impl Drop for FalliblePreparedSet {
        fn drop(&mut self) {
            self.calls
                .lock()
                .unwrap()
                .drop
                .push(self.prepared_oid.clone());
        }
    }

    impl PreparedSet for FalliblePreparedSet {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            assert_eq!(oid, &self.prepared_oid);
            self.calls.lock().unwrap().commit.push(oid.clone());
            let index = usize::try_from(oid.as_ref()[7] - 1).unwrap();
            let Value::Integer(value) = value else {
                unreachable!("test supplies integer values")
            };
            self.previous = Some(std::mem::replace(
                &mut self.values.lock().unwrap()[index],
                *value,
            ));
            let result = if oid == &self.fail_commit_oid {
                Err(SetCommitError::Failed)
            } else {
                Ok(())
            };
            Box::pin(async move { result })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async move {
                assert_eq!(oid, &self.prepared_oid);
                self.calls.lock().unwrap().undo.push(oid.clone());
                if self.fail_undo_oids.contains(oid) {
                    Err(SetUndoError::Failed)
                } else {
                    if let Some(previous) = self.previous.take() {
                        let index = usize::try_from(oid.as_ref()[7] - 1).unwrap();
                        self.values.lock().unwrap()[index] = previous;
                    }
                    Ok(())
                }
            })
        }

        fn free<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                assert_eq!(oid, &self.prepared_oid);
                self.calls.lock().unwrap().free.push(oid.clone());
            })
        }

        fn finalize<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            assert_eq!(oid, &self.prepared_oid);
            self.calls.lock().unwrap().finalize.push(oid.clone());
            Box::pin(async {})
        }
    }

    #[derive(Clone, Debug, Default)]
    struct SetLifecycleCalls {
        test: Vec<Oid>,
        commit: Vec<Oid>,
        undo: Vec<Oid>,
        free: Vec<Oid>,
        finalize: Vec<Oid>,
        drop: Vec<Oid>,
    }

    impl MibHandler for CommitFailHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            self.calls.lock().unwrap().test.push(oid.clone());
            if self.fail_test_oid.as_ref() == Some(oid) {
                return Box::pin(async { Err(SetTestError::WrongValue) });
            }
            Box::pin(async move {
                Ok(Box::new(FalliblePreparedSet {
                    prepared_oid: oid.clone(),
                    fail_commit_oid: self.fail_commit_oid.clone(),
                    fail_undo_oids: self.fail_undo_oids.clone(),
                    calls: self.calls.clone(),
                    values: self.values.clone(),
                    previous: None,
                }) as Box<dyn PreparedSet>)
            })
        }
    }

    fn set_oid(index: u32) -> Oid {
        oid!(1, 3, 6, 1, 4, 1, 99999, index, 0)
    }

    fn set_oids(indices: &[u32]) -> Vec<Oid> {
        indices.iter().copied().map(set_oid).collect()
    }

    fn three_set_varbinds() -> Vec<VarBind> {
        (1u32..=3)
            .map(|i| VarBind::new(set_oid(i), Value::Integer(i as i32)))
            .collect()
    }

    async fn run_commit_scenario(
        version: Version,
        fail_commit: u32,
        fail_undos: &[u32],
    ) -> (Pdu, SetLifecycleCalls, Vec<i32>) {
        let calls = Arc::new(Mutex::new(SetLifecycleCalls::default()));
        let values = Arc::new(Mutex::new(vec![10, 20, 30]));
        let handler = Arc::new(CommitFailHandler {
            fail_test_oid: None,
            fail_commit_oid: set_oid(fail_commit),
            fail_undo_oids: set_oids(fail_undos),
            calls: calls.clone(),
            values: values.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            three_set_varbinds(),
        );
        let ctx = crate::test_support::request_context_for_version(version, PduType::SetRequest);
        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        let calls = calls.lock().unwrap().clone();
        let values = values.lock().unwrap().clone();
        (response, calls, values)
    }

    fn assert_commit_failure_lifecycle(
        response: &Pdu,
        calls: &SetLifecycleCalls,
        failed_index: i32,
        expected_commits: &[u32],
        expected_undos: &[u32],
        expected_frees: &[u32],
    ) {
        assert_eq!(response.error_status(), ErrorStatus::CommitFailed.as_i32());
        assert_eq!(response.error_index(), failed_index);
        assert_eq!(calls.test, set_oids(&[1, 2, 3]));
        assert_eq!(calls.commit, set_oids(expected_commits));
        assert_eq!(calls.undo, set_oids(expected_undos));
        assert_eq!(calls.free, set_oids(expected_frees));
        assert!(calls.finalize.is_empty());
        assert_eq!(calls.drop.len(), 3);
        for oid in set_oids(&[1, 2, 3]) {
            assert_eq!(
                calls.drop.iter().filter(|dropped| **dropped == oid).count(),
                1
            );
        }

        // Every successfully tested binding receives exactly one terminal
        // callback, and attempted/unattempted bindings never overlap.
        assert_eq!(calls.undo.len() + calls.free.len(), 3);
        for oid in &calls.undo {
            assert_eq!(calls.undo.iter().filter(|call| *call == oid).count(), 1);
            assert!(!calls.free.contains(oid));
        }
        for oid in &calls.free {
            assert_eq!(calls.free.iter().filter(|call| *call == oid).count(), 1);
            assert!(!calls.undo.contains(oid));
        }
    }

    #[tokio::test]
    async fn test_commit_failure_at_first_undoes_failed_and_frees_trailing() {
        let (response, calls, values) = run_commit_scenario(Version::V2c, 1, &[]).await;
        assert_commit_failure_lifecycle(&response, &calls, 1, &[1], &[1], &[3, 2]);
        assert_eq!(values, [10, 20, 30]);
    }

    #[tokio::test]
    async fn test_commit_failure_in_middle_undoes_attempted_and_frees_trailing() {
        let (response, calls, values) = run_commit_scenario(Version::V2c, 2, &[]).await;
        assert_commit_failure_lifecycle(&response, &calls, 2, &[1, 2], &[2, 1], &[3]);
        assert_eq!(values, [10, 20, 30]);
    }

    #[tokio::test]
    async fn test_commit_failure_at_end_undoes_all_attempted() {
        let (response, calls, values) = run_commit_scenario(Version::V2c, 3, &[]).await;
        assert_commit_failure_lifecycle(&response, &calls, 3, &[1, 2, 3], &[3, 2, 1], &[]);
        assert_eq!(values, [10, 20, 30]);
    }

    #[tokio::test]
    async fn commit_failure_mapping_uses_commit_binding_for_all_versions() {
        for version in [Version::V1, Version::V2c, Version::V3] {
            let (response, calls, values) = run_commit_scenario(version, 2, &[]).await;
            let expected_status = if version == Version::V1 {
                ErrorStatus::GenErr
            } else {
                ErrorStatus::CommitFailed
            };

            assert_eq!(
                response.error_status(),
                expected_status.as_i32(),
                "status for {version:?}"
            );
            assert_eq!(response.error_index(), 2, "index for {version:?}");
            assert_eq!(calls.commit, set_oids(&[1, 2]));
            assert_eq!(calls.undo, set_oids(&[2, 1]));
            assert_eq!(calls.free, set_oids(&[3]));
            assert_eq!(values, [10, 20, 30]);
        }
    }

    #[tokio::test]
    async fn undo_failure_mapping_tracks_failed_undo_binding_for_all_versions() {
        for failed_undo in [2, 1] {
            for version in [Version::V1, Version::V2c, Version::V3] {
                let (response, calls, _values) =
                    run_commit_scenario(version, 2, &[failed_undo]).await;
                let (expected_status, expected_index) = if version == Version::V1 {
                    (ErrorStatus::GenErr, failed_undo as i32)
                } else {
                    (ErrorStatus::UndoFailed, 0)
                };

                assert_eq!(
                    response.error_status(),
                    expected_status.as_i32(),
                    "status for {version:?} with undo failure at {failed_undo}"
                );
                assert_eq!(
                    response.error_index(),
                    expected_index,
                    "index for {version:?} with undo failure at {failed_undo}"
                );
                assert_eq!(calls.test, set_oids(&[1, 2, 3]));
                assert_eq!(calls.commit, set_oids(&[1, 2]));
                assert_eq!(calls.undo, set_oids(&[2, 1]));
                assert_eq!(calls.free, set_oids(&[3]));
                assert!(calls.finalize.is_empty());
                assert_eq!(calls.undo.len() + calls.free.len(), 3);
                assert!(calls.undo.iter().all(|oid| !calls.free.contains(oid)));
                assert_eq!(calls.drop.len(), 3);
            }
        }
    }

    #[tokio::test]
    async fn multiple_undo_failures_report_first_failure_in_reverse_order() {
        for version in [Version::V1, Version::V2c, Version::V3] {
            let (response, calls, _values) = run_commit_scenario(version, 2, &[1, 2]).await;
            let (expected_status, expected_index) = if version == Version::V1 {
                (ErrorStatus::GenErr, 2)
            } else {
                (ErrorStatus::UndoFailed, 0)
            };

            assert_eq!(
                response.error_status(),
                expected_status.as_i32(),
                "status for {version:?}"
            );
            assert_eq!(
                response.error_index(),
                expected_index,
                "index for {version:?}"
            );
            assert_eq!(calls.undo, set_oids(&[2, 1]));
        }
    }

    #[tokio::test]
    async fn test_all_commits_succeed_finalize_in_reverse_order() {
        let (response, calls, values) = run_commit_scenario(Version::V2c, 99, &[]).await;

        assert_eq!(response.error_status(), 0);
        assert_eq!(calls.test, set_oids(&[1, 2, 3]));
        assert_eq!(calls.commit, set_oids(&[1, 2, 3]));
        assert!(calls.undo.is_empty());
        assert!(calls.free.is_empty());
        assert_eq!(calls.finalize, set_oids(&[3, 2, 1]));
        assert_eq!(calls.drop, set_oids(&[3, 2, 1]));
        assert_eq!(values, [1, 2, 3]);
    }

    #[tokio::test]
    async fn early_test_failure_frees_and_drops_only_earlier_prepared_state() {
        let calls = Arc::new(Mutex::new(SetLifecycleCalls::default()));
        let handler = Arc::new(CommitFailHandler {
            fail_test_oid: Some(set_oid(2)),
            fail_commit_oid: set_oid(99),
            fail_undo_oids: Vec::new(),
            calls: calls.clone(),
            values: Arc::new(Mutex::new(vec![10, 20, 30])),
        });
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            three_set_varbinds(),
        );

        let response = agent.dispatch_request(&test_ctx(), &pdu).await.unwrap();
        let calls = calls.lock().unwrap().clone();
        assert_eq!(response.error_status(), ErrorStatus::WrongValue.as_i32());
        assert_eq!(response.error_index(), 2);
        assert_eq!(calls.test, set_oids(&[1, 2]));
        assert!(calls.commit.is_empty());
        assert!(calls.undo.is_empty());
        assert!(calls.finalize.is_empty());
        assert_eq!(calls.free, set_oids(&[1]));
        assert_eq!(calls.drop, set_oids(&[1]));
    }

    type TypedEvents = Arc<Mutex<Vec<(u8, &'static str, i32, Oid)>>>;

    struct TypedHandler<const TAG: u8> {
        events: TypedEvents,
    }

    struct TypedPrepared<const TAG: u8> {
        events: TypedEvents,
        request_id: i32,
        oid: Oid,
    }

    impl<const TAG: u8> PreparedSet for TypedPrepared<TAG> {
        fn commit<'a>(
            &'a mut self,
            ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            assert_eq!(ctx.request_id(), self.request_id);
            assert_eq!(oid, &self.oid);
            self.events
                .lock()
                .unwrap()
                .push((TAG, "commit", ctx.request_id(), oid.clone()));
            Box::pin(async { Ok(()) })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async { Ok(()) })
        }
    }

    impl<const TAG: u8> MibHandler for TypedHandler<TAG> {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            self.events
                .lock()
                .unwrap()
                .push((TAG, "test", ctx.request_id(), oid.clone()));
            let prepared = TypedPrepared::<TAG> {
                events: self.events.clone(),
                request_id: ctx.request_id(),
                oid: oid.clone(),
            };
            Box::pin(async move { Ok(Box::new(prepared) as Box<dyn PreparedSet>) })
        }
    }

    #[tokio::test]
    async fn heterogeneous_handlers_keep_prepared_state_and_context_per_varbind() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1),
                Arc::new(TypedHandler::<1> {
                    events: events.clone(),
                }),
            )
            .handler(
                oid!(1, 3, 6, 1, 4, 1, 99999, 2),
                Arc::new(TypedHandler::<2> {
                    events: events.clone(),
                }),
            )
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            17,
            0,
            0,
            vec![
                VarBind::new(set_oid(1), Value::Integer(1)),
                VarBind::new(set_oid(2), Value::Integer(2)),
            ],
        );
        let ctx = crate::test_support::community_request_context_with(
            crate::CommunityVersion::V2c,
            crate::Community::from("public"),
            "127.0.0.1:12345".parse().unwrap(),
            17,
            PduType::SetRequest,
        );

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status(), ErrorStatus::NoError.as_i32());
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                (1, "test", 17, set_oid(1)),
                (2, "test", 17, set_oid(2)),
                (1, "commit", 17, set_oid(1)),
                (2, "commit", 17, set_oid(2)),
            ]
        );
    }

    struct SerializedSetHandler {
        value: Arc<AtomicI32>,
        first_commit_finished: Arc<Semaphore>,
        release_failed_commit: Arc<Semaphore>,
        undo_started: Arc<Semaphore>,
        release_undo: Arc<Semaphore>,
        second_test_started: Arc<Semaphore>,
    }

    struct SerializedPreparedSet {
        request_id: i32,
        oid: Oid,
        value: Arc<AtomicI32>,
        previous: Option<i32>,
        first_commit_finished: Arc<Semaphore>,
        release_failed_commit: Arc<Semaphore>,
        undo_started: Arc<Semaphore>,
        release_undo: Arc<Semaphore>,
    }

    impl PreparedSet for SerializedPreparedSet {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            Box::pin(async move {
                assert_eq!(oid, &self.oid);
                if self.request_id == 1 && oid == &set_oid(2) {
                    self.release_failed_commit
                        .acquire()
                        .await
                        .expect("failed-commit gate remains open")
                        .forget();
                    return Err(SetCommitError::Failed);
                }

                let Value::Integer(value) = value else {
                    unreachable!("test supplies integer values")
                };
                self.previous = Some(self.value.swap(*value, Ordering::SeqCst));
                if self.request_id == 1 {
                    self.first_commit_finished.add_permits(1);
                }
                Ok(())
            })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async move {
                assert_eq!(oid, &self.oid);
                if self.request_id == 1 && oid == &set_oid(1) {
                    self.undo_started.add_permits(1);
                    self.release_undo
                        .acquire()
                        .await
                        .expect("undo gate remains open")
                        .forget();
                }
                if let Some(previous) = self.previous.take() {
                    self.value.store(previous, Ordering::SeqCst);
                }
                Ok(())
            })
        }
    }

    impl MibHandler for SerializedSetHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async move {
                Ok(GetResult::Value(Value::Integer(
                    self.value.load(Ordering::SeqCst),
                )))
            })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            if ctx.request_id() == 2 {
                self.second_test_started.add_permits(1);
            }
            let prepared = SerializedPreparedSet {
                request_id: ctx.request_id(),
                oid: oid.clone(),
                value: self.value.clone(),
                previous: None,
                first_commit_finished: self.first_commit_finished.clone(),
                release_failed_commit: self.release_failed_commit.clone(),
                undo_started: self.undo_started.clone(),
                release_undo: self.release_undo.clone(),
            };
            Box::pin(async move { Ok(Box::new(prepared) as Box<dyn PreparedSet>) })
        }
    }

    #[tokio::test]
    async fn set_transactions_are_serialized_while_retrieval_remains_concurrent() {
        let value = Arc::new(AtomicI32::new(0));
        let first_commit_finished = Arc::new(Semaphore::new(0));
        let release_failed_commit = Arc::new(Semaphore::new(0));
        let undo_started = Arc::new(Semaphore::new(0));
        let release_undo = Arc::new(Semaphore::new(0));
        let second_test_started = Arc::new(Semaphore::new(0));
        let second_dispatch_started = Arc::new(Semaphore::new(0));
        let handler = Arc::new(SerializedSetHandler {
            value: value.clone(),
            first_commit_finished: first_commit_finished.clone(),
            release_failed_commit: release_failed_commit.clone(),
            undo_started: undo_started.clone(),
            release_undo: release_undo.clone(),
            second_test_started: second_test_started.clone(),
        });
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();

        let first_pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            vec![
                VarBind::new(set_oid(1), Value::Integer(10)),
                VarBind::new(set_oid(2), Value::Integer(11)),
            ],
        );
        let first_ctx = crate::test_support::community_request_context_with(
            crate::CommunityVersion::V2c,
            crate::Community::from("public"),
            "127.0.0.1:12345".parse().unwrap(),
            1,
            PduType::SetRequest,
        );
        let first_agent = agent.clone();
        let first =
            tokio::spawn(async move { first_agent.dispatch_request(&first_ctx, &first_pdu).await });
        first_commit_finished
            .acquire()
            .await
            .expect("first-commit signal remains open")
            .forget();

        let second_pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            2,
            0,
            0,
            vec![VarBind::new(set_oid(1), Value::Integer(20))],
        );
        let second_ctx = crate::test_support::community_request_context_with(
            crate::CommunityVersion::V2c,
            crate::Community::from("public"),
            "127.0.0.1:12346".parse().unwrap(),
            2,
            PduType::SetRequest,
        );
        let second_agent = agent.clone();
        let second_dispatch_signal = second_dispatch_started.clone();
        let second = tokio::spawn(async move {
            second_dispatch_signal.add_permits(1);
            second_agent
                .dispatch_request(&second_ctx, &second_pdu)
                .await
        });
        second_dispatch_started
            .acquire()
            .await
            .expect("second-dispatch signal remains open")
            .forget();

        let get_pdu = Pdu::standard(
            crate::pdu::StandardPduType::GetRequest,
            3,
            0,
            0,
            vec![VarBind::new(set_oid(1), Value::Null)],
        );
        let get_ctx = crate::test_support::request_context(PduType::GetRequest);
        let get_response = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            agent.dispatch_request(&get_ctx, &get_pdu),
        )
        .await
        .expect("retrieval must not wait for SET coordination")
        .unwrap();
        assert_eq!(get_response.varbinds[0].value, Value::Integer(10));

        release_failed_commit.add_permits(1);
        undo_started
            .acquire()
            .await
            .expect("undo signal remains open")
            .forget();
        assert!(
            second_test_started.try_acquire().is_err(),
            "a later SET entered its test phase during rollback"
        );

        release_undo.add_permits(1);
        let first_response = first.await.unwrap().unwrap();
        assert_eq!(
            first_response.error_status(),
            ErrorStatus::CommitFailed.as_i32()
        );
        second_test_started
            .acquire()
            .await
            .expect("second-test signal remains open")
            .forget();
        let second_response = second.await.unwrap().unwrap();
        assert_eq!(
            second_response.error_status(),
            ErrorStatus::NoError.as_i32()
        );
        assert_eq!(value.load(Ordering::SeqCst), 20);
    }

    #[derive(Clone, Copy)]
    enum DropProbeMode {
        BlockTest,
        BlockCommit,
        PanicCommit,
        BlockFree,
        BlockUndo,
        BlockFinalize,
    }

    struct DropProbeHandler {
        mode: DropProbeMode,
        active: Arc<AtomicU32>,
        drops: Arc<AtomicU32>,
        drop_order: Arc<Mutex<Vec<Oid>>>,
        callback_started: Arc<Semaphore>,
        release_callback: Arc<Semaphore>,
    }

    struct DropProbePrepared {
        mode: DropProbeMode,
        oid: Oid,
        active: Arc<AtomicU32>,
        drops: Arc<AtomicU32>,
        drop_order: Arc<Mutex<Vec<Oid>>>,
        callback_started: Arc<Semaphore>,
        release_callback: Arc<Semaphore>,
    }

    impl Drop for DropProbePrepared {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.drops.fetch_add(1, Ordering::SeqCst);
            self.drop_order.lock().unwrap().push(self.oid.clone());
        }
    }

    impl PreparedSet for DropProbePrepared {
        fn commit<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetCommitResult> {
            Box::pin(async move {
                match self.mode {
                    DropProbeMode::BlockCommit if self.oid == set_oid(1) => {
                        self.callback_started.add_permits(1);
                        self.release_callback
                            .acquire()
                            .await
                            .expect("release semaphore remains open")
                            .forget();
                        Ok(())
                    }
                    DropProbeMode::PanicCommit if self.oid == set_oid(1) => {
                        self.callback_started.add_permits(1);
                        panic!("intentional prepared SET panic");
                    }
                    DropProbeMode::BlockUndo if self.oid == set_oid(3) => {
                        Err(SetCommitError::Failed)
                    }
                    _ => Ok(()),
                }
            })
        }

        fn undo<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetUndoResult> {
            Box::pin(async move {
                if matches!(self.mode, DropProbeMode::BlockUndo) && self.oid == set_oid(3) {
                    self.callback_started.add_permits(1);
                    self.release_callback
                        .acquire()
                        .await
                        .expect("release semaphore remains open")
                        .forget();
                }
                Ok(())
            })
        }

        fn free<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                if matches!(self.mode, DropProbeMode::BlockFree) && self.oid == set_oid(3) {
                    self.callback_started.add_permits(1);
                    self.release_callback
                        .acquire()
                        .await
                        .expect("release semaphore remains open")
                        .forget();
                }
            })
        }

        fn finalize<'a>(
            &'a mut self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                if matches!(self.mode, DropProbeMode::BlockFinalize) && self.oid == set_oid(3) {
                    self.callback_started.add_permits(1);
                    self.release_callback
                        .acquire()
                        .await
                        .expect("release semaphore remains open")
                        .forget();
                }
            })
        }
    }

    impl MibHandler for DropProbeHandler {
        fn get<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetResult>> {
            Box::pin(async { Ok(GetResult::NoSuchObject) })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
            Box::pin(async { Ok(GetNextResult::EndOfMibView) })
        }

        fn test_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetTestResult> {
            Box::pin(async move {
                if matches!(self.mode, DropProbeMode::BlockTest) && oid == &set_oid(4) {
                    self.callback_started.add_permits(1);
                    self.release_callback
                        .acquire()
                        .await
                        .expect("release semaphore remains open")
                        .forget();
                }
                if matches!(self.mode, DropProbeMode::BlockFree) && oid == &set_oid(4) {
                    return Err(SetTestError::WrongValue);
                }
                self.active.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(DropProbePrepared {
                    mode: self.mode,
                    oid: oid.clone(),
                    active: self.active.clone(),
                    drops: self.drops.clone(),
                    drop_order: self.drop_order.clone(),
                    callback_started: self.callback_started.clone(),
                    release_callback: self.release_callback.clone(),
                }) as Box<dyn PreparedSet>)
            })
        }
    }

    async fn drop_probe(
        mode: DropProbeMode,
    ) -> (
        tokio::task::JoinHandle<crate::Result<Pdu>>,
        Arc<AtomicU32>,
        Arc<AtomicU32>,
        Arc<Mutex<Vec<Oid>>>,
        Arc<Semaphore>,
    ) {
        let active = Arc::new(AtomicU32::new(0));
        let drops = Arc::new(AtomicU32::new(0));
        let drop_order = Arc::new(Mutex::new(Vec::new()));
        let callback_started = Arc::new(Semaphore::new(0));
        let release_callback = Arc::new(Semaphore::new(0));
        let handler = Arc::new(DropProbeHandler {
            mode,
            active: active.clone(),
            drops: drops.clone(),
            drop_order: drop_order.clone(),
            callback_started: callback_started.clone(),
            release_callback,
        });
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .without_builtin_handlers()
            .allow_all_access()
            .build()
            .await
            .unwrap();
        let pdu = Pdu::standard(
            crate::pdu::StandardPduType::SetRequest,
            1,
            0,
            0,
            (1..=if matches!(mode, DropProbeMode::BlockTest | DropProbeMode::BlockFree) {
                4
            } else {
                3
            })
                .map(|index| VarBind::new(set_oid(index), Value::Integer(index as i32)))
                .collect(),
        );
        let task = tokio::spawn(async move { agent.dispatch_request(&test_ctx(), &pdu).await });
        (task, active, drops, drop_order, callback_started)
    }

    async fn assert_cancelled_reverse_fallback(mode: DropProbeMode) {
        let (task, active, drops, drop_order, callback_started) = drop_probe(mode).await;
        callback_started.acquire().await.unwrap().forget();
        assert_eq!(active.load(Ordering::SeqCst), 3);

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert_eq!(*drop_order.lock().unwrap(), set_oids(&[3, 2, 1]));
    }

    #[tokio::test]
    async fn cancellation_during_test_drops_prepared_states_in_reverse_order() {
        assert_cancelled_reverse_fallback(DropProbeMode::BlockTest).await;
    }

    #[tokio::test]
    async fn cancellation_drops_every_request_owned_reservation_once() {
        assert_cancelled_reverse_fallback(DropProbeMode::BlockCommit).await;
    }

    #[tokio::test]
    async fn panic_drops_every_request_owned_reservation_once() {
        let (task, active, drops, drop_order, callback_started) =
            drop_probe(DropProbeMode::PanicCommit).await;
        callback_started.acquire().await.unwrap().forget();
        let error = task.await.unwrap_err();
        assert!(error.is_panic());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        assert_eq!(*drop_order.lock().unwrap(), set_oids(&[3, 2, 1]));
    }

    #[tokio::test]
    async fn cancellation_of_async_free_drops_states_in_reverse_order() {
        assert_cancelled_reverse_fallback(DropProbeMode::BlockFree).await;
    }

    #[tokio::test]
    async fn cancellation_of_async_undo_drops_states_in_reverse_order() {
        assert_cancelled_reverse_fallback(DropProbeMode::BlockUndo).await;
    }

    #[tokio::test]
    async fn cancellation_of_async_finalize_drops_states_in_reverse_order() {
        assert_cancelled_reverse_fallback(DropProbeMode::BlockFinalize).await;
    }
}
