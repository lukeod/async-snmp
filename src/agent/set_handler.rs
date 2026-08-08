//! Multi-phase SET protocol (RFC 3416).
//!
//! Implements the SET phases modeled after net-snmp's approach:
//!
//! - **Test**: Validate each varbind via `test_set`. If any fails, call `free_set`
//!   on all previously successful varbinds (in reverse order) to release resources,
//!   then return the error.
//! - **Commit**: Apply each varbind via `commit_set`. If any fails, call `undo_set`
//!   on every attempted binding, including the failing binding, in reverse order;
//!   call `free_set` on later tested bindings whose commit was never attempted.

use std::sync::Arc;

use crate::error::{ErrorStatus, Result};
use crate::handler::{MibHandler, RequestContext};
use crate::oid::Oid;
use crate::pdu::Pdu;
use crate::value::Value;
use crate::version::Version;

use super::Agent;

impl Agent {
    /// Handle SET request with multi-phase commit protocol.
    ///
    /// Per RFC 3416, SET operations should be atomic. We implement this via:
    /// 1. **Test phase**: Call `test_set` for ALL varbinds. If any fails,
    ///    call `free_set` for all previously successful varbinds (in reverse
    ///    order) to release resources, then return the error.
    /// 2. **Commit phase**: Call `commit_set` for each varbind. If any fails,
    ///    call `undo_set` for every attempted binding, including the failing
    ///    binding, in reverse order. Call `free_set` in reverse order for later
    ///    tested bindings whose commit was never attempted.
    ///
    /// Per RFC 3416 Section 4.2.5 step (1), the size of the Response (which
    /// echoes the request varbinds) is checked up front: if it would exceed the
    /// message-size limit the operation terminates immediately with a `tooBig`
    /// Response, before the test or commit phases run, so an oversized SET is
    /// never applied.
    pub(super) async fn handle_set(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        // The message-envelope path performs an exact preflight encoding before
        // dispatch, so an oversized SET never reaches the test/commit phases.

        // Track which handlers we need to commit/undo
        struct PendingSet<'a> {
            handler: &'a Arc<dyn MibHandler>,
            oid: Oid,
            value: Value,
        }

        let mut pending: Vec<PendingSet> = Vec::with_capacity(pdu.varbinds.len());

        // ========== PHASE 1: TEST ==========
        // Check VACM and call test_set for all varbinds
        for (index, vb) in pdu.varbinds.iter().enumerate() {
            // VACM write access check
            if let Some(ref vacm) = self.inner.vacm
                && !vacm.check_access(ctx.write_view.as_ref(), &vb.oid)
            {
                // Free resources for all previously successful varbinds
                for p in pending.iter().rev() {
                    p.handler.free_set(ctx, &p.oid, &p.value).await;
                }
                // v2c/v3 report noAccess; v1 downgrades it to noSuchName.
                let status = ErrorStatus::NoAccess;
                let status = if ctx.version == Version::V1 {
                    status.to_v1()
                } else {
                    status
                };
                return Ok(pdu.to_error_response(status, (index + 1) as i32));
            }

            let handler = self.find_handler(&vb.oid);

            if handler.is_none() {
                // Free resources for all previously successful varbinds
                for p in pending.iter().rev() {
                    p.handler.free_set(ctx, &p.oid, &p.value).await;
                }
                // No handler for this OID: v2c/v3 report notWritable; v1
                // downgrades it to noSuchName.
                let status = ErrorStatus::NotWritable;
                let status = if ctx.version == Version::V1 {
                    status.to_v1()
                } else {
                    status
                };
                return Ok(pdu.to_error_response(status, (index + 1) as i32));
            }

            let handler = handler.unwrap();
            let result = handler.handler.test_set(ctx, &vb.oid, &vb.value).await;

            if !result.is_ok() {
                // Free resources for all previously successful varbinds (reverse order)
                for p in pending.iter().rev() {
                    p.handler.free_set(ctx, &p.oid, &p.value).await;
                }

                let status = result.to_error_status();
                let status = if ctx.version == Version::V1 {
                    status.to_v1()
                } else {
                    status
                };
                return Ok(pdu.to_error_response(status, (index + 1) as i32));
            }

            pending.push(PendingSet {
                handler: &handler.handler,
                oid: vb.oid.clone(),
                value: vb.value.clone(),
            });
        }

        // ========== PHASE 2: COMMIT ==========
        // All tests passed, now commit each varbind
        for (index, p) in pending.iter().enumerate() {
            let result = p.handler.commit_set(ctx, &p.oid, &p.value).await;

            if !result.is_ok() {
                // A failed commit may have partially mutated state. Undo every
                // attempted binding, including the failing one, in reverse order.
                let mut undo_failed = false;
                for attempted in pending[..=index].iter().rev() {
                    let undo_result = attempted
                        .handler
                        .undo_set(ctx, &attempted.oid, &attempted.value)
                        .await;
                    if !undo_result.is_ok() {
                        undo_failed = true;
                        tracing::warn!(target: "async_snmp::agent", { oid = %attempted.oid }, "undo_set failed during rollback");
                    }
                }

                // Later bindings passed test_set but were never committed, so
                // release their test-phase resources without attempting undo.
                for unattempted in pending[index + 1..].iter().rev() {
                    unattempted
                        .handler
                        .free_set(ctx, &unattempted.oid, &unattempted.value)
                        .await;
                }

                let status = if undo_failed {
                    ErrorStatus::UndoFailed
                } else {
                    ErrorStatus::CommitFailed
                };
                // RFC 3416 4.2.5: commitFailed carries the index of the failed
                // binding; undoFailed carries error-index zero.
                let error_index = if undo_failed { 0 } else { (index + 1) as i32 };
                let status = if ctx.version == Version::V1 {
                    status.to_v1()
                } else {
                    status
                };
                return Ok(pdu.to_error_response(status, error_index));
            }
        }

        // All commits succeeded
        Ok(pdu.to_response())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use bytes::Bytes;

    use crate::Oid;
    use crate::agent::Agent;
    use crate::error::ErrorStatus;
    use crate::handler::{
        BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
        SecurityModel, SetResult,
    };
    use crate::message::SecurityLevel;
    use crate::oid;
    use crate::pdu::{Pdu, PduType};
    use crate::value::Value;
    use crate::varbind::VarBind;
    use crate::version::Version;

    /// Handler that accepts `test_set` for .99999.1.0 but rejects .99999.2.0,
    /// tracking `free_set` calls via an atomic counter.
    struct FreeSetTracker {
        free_count: Arc<AtomicU32>,
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
        ) -> BoxFuture<'a, SetResult> {
            Box::pin(async move {
                // Accept .99999.1.0, reject .99999.2.0
                if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0) {
                    SetResult::WrongValue
                } else {
                    SetResult::Ok
                }
            })
        }

        fn commit_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetResult> {
            Box::pin(async { SetResult::Ok })
        }

        fn free_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            self.free_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {})
        }
    }

    fn test_ctx() -> RequestContext {
        RequestContext {
            source: "127.0.0.1:12345".parse().unwrap(),
            version: Version::V2c,
            security_model: SecurityModel::V2c,
            security_name: Bytes::from_static(b"public"),
            security_level: SecurityLevel::NoAuthNoPriv,
            context_name: Bytes::new(),
            request_id: 1,
            pdu_type: PduType::SetRequest,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: None,
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
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // SET with two varbinds: first succeeds test_set, second fails.
        // free_set should be called once (for the first varbind).
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
        // free_set should have been called once for the first varbind
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

    /// Handler that always accepts test_set and counts commit_set invocations,
    /// used to prove the SET size check terminates before the commit phase.
    struct CommitTracker {
        commit_count: Arc<AtomicU32>,
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
        ) -> BoxFuture<'a, SetResult> {
            Box::pin(async { SetResult::Ok })
        }

        fn commit_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetResult> {
            self.commit_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { SetResult::Ok })
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
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // SET where the first varbind fails test_set. No free_set calls since
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
        fail_commit_oid: Oid,
        fail_undo_oid: Option<Oid>,
        calls: Arc<Mutex<SetLifecycleCalls>>,
    }

    #[derive(Clone, Debug, Default)]
    struct SetLifecycleCalls {
        commit: Vec<Oid>,
        undo: Vec<Oid>,
        free: Vec<Oid>,
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
            _oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetResult> {
            Box::pin(async { SetResult::Ok })
        }

        fn commit_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetResult> {
            self.calls.lock().unwrap().commit.push(oid.clone());
            let result = if oid == &self.fail_commit_oid {
                SetResult::CommitFailed
            } else {
                SetResult::Ok
            };
            Box::pin(async move { result })
        }

        fn undo_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, SetResult> {
            self.calls.lock().unwrap().undo.push(oid.clone());
            let result = if self.fail_undo_oid.as_ref() == Some(oid) {
                SetResult::UndoFailed
            } else {
                SetResult::Ok
            };
            Box::pin(async move { result })
        }

        fn free_set<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            oid: &'a Oid,
            _value: &'a Value,
        ) -> BoxFuture<'a, ()> {
            self.calls.lock().unwrap().free.push(oid.clone());
            Box::pin(async {})
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
        fail_commit: u32,
        fail_undo: Option<u32>,
    ) -> (Pdu, SetLifecycleCalls) {
        let calls = Arc::new(Mutex::new(SetLifecycleCalls::default()));
        let handler = Arc::new(CommitFailHandler {
            fail_commit_oid: set_oid(fail_commit),
            fail_undo_oid: fail_undo.map(set_oid),
            calls: calls.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
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
        (response, calls)
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
        assert_eq!(calls.commit, set_oids(expected_commits));
        assert_eq!(calls.undo, set_oids(expected_undos));
        assert_eq!(calls.free, set_oids(expected_frees));

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
        let (response, calls) = run_commit_scenario(1, None).await;
        assert_commit_failure_lifecycle(&response, &calls, 1, &[1], &[1], &[3, 2]);
    }

    #[tokio::test]
    async fn test_commit_failure_in_middle_undoes_attempted_and_frees_trailing() {
        let (response, calls) = run_commit_scenario(2, None).await;
        assert_commit_failure_lifecycle(&response, &calls, 2, &[1, 2], &[2, 1], &[3]);
    }

    #[tokio::test]
    async fn test_commit_failure_at_end_undoes_all_attempted() {
        let (response, calls) = run_commit_scenario(3, None).await;
        assert_commit_failure_lifecycle(&response, &calls, 3, &[1, 2, 3], &[3, 2, 1], &[]);
    }

    #[tokio::test]
    async fn test_undo_failure_during_rollback_reports_undo_failed() {
        // The failing binding's undo fails first. Cleanup must still undo the
        // earlier binding and free the trailing, never-attempted binding.
        let (response, calls) = run_commit_scenario(2, Some(2)).await;

        assert_eq!(response.error_status(), ErrorStatus::UndoFailed.as_i32());
        assert_eq!(response.error_index(), 0);
        assert_eq!(calls.commit, set_oids(&[1, 2]));
        assert_eq!(calls.undo, set_oids(&[2, 1]));
        assert_eq!(calls.free, set_oids(&[3]));
        assert_eq!(calls.undo.len() + calls.free.len(), 3);
        assert!(calls.undo.iter().all(|oid| !calls.free.contains(oid)));
    }

    #[tokio::test]
    async fn test_all_commits_succeed_no_undo_or_free() {
        let (response, calls) = run_commit_scenario(99, None).await;

        assert_eq!(response.error_status(), 0);
        assert_eq!(calls.commit, set_oids(&[1, 2, 3]));
        assert!(calls.undo.is_empty());
        assert!(calls.free.is_empty());
    }
}
