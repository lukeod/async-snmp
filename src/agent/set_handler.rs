//! Multi-phase SET protocol (RFC 3416).
//!
//! Implements the SET phases modeled after net-snmp's approach:
//!
//! - **Test**: Validate each varbind via `test_set`. If any fails, call `free_set`
//!   on all previously successful varbinds (in reverse order) to release resources,
//!   then return the error.
//! - **Commit**: Apply each varbind via `commit_set`. If any fails, call `undo_set`
//!   on all previously committed varbinds (in reverse order) to roll back.

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
    ///    call `undo_set` for all previously committed varbinds.
    ///
    /// Per RFC 3416 Section 4.2.5 step (1), the size of the Response (which
    /// echoes the request varbinds) is checked up front: if it would exceed the
    /// message-size limit the operation terminates immediately with a `tooBig`
    /// Response, before the test or commit phases run, so an oversized SET is
    /// never applied.
    pub(super) async fn handle_set(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
        // RFC 3416 Section 4.2.5 step (1): the SET Response echoes the request
        // varbinds. If that Response would not fit, return tooBig without running
        // the test or commit phases (prevents a retrying manager re-applying it).
        if !Self::response_fits(
            &pdu.varbinds,
            self.response_overhead(ctx),
            self.effective_max_size(ctx),
        ) {
            return Ok(Self::too_big_response(ctx.version, pdu));
        }

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
        let mut committed: Vec<&PendingSet> = Vec::with_capacity(pending.len());

        for (index, p) in pending.iter().enumerate() {
            let result = p.handler.commit_set(ctx, &p.oid, &p.value).await;

            if !result.is_ok() {
                // Commit failed - rollback all previously committed varbinds
                let mut undo_failed = false;
                for c in committed.iter().rev() {
                    let undo_result = c.handler.undo_set(ctx, &c.oid, &c.value).await;
                    if !undo_result.is_ok() {
                        undo_failed = true;
                        tracing::warn!(target: "async_snmp::agent", { oid = %c.oid }, "undo_set failed during rollback");
                    }
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

            committed.push(p);
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
        BoxFuture, GetNextResult, GetResult, MibHandler, RequestContext, SecurityModel, SetResult,
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
        fn get<'a>(&'a self, _ctx: &'a RequestContext, _oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async { GetResult::NoSuchObject })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, GetNextResult> {
            Box::pin(async { GetNextResult::EndOfMibView })
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
        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), Value::Integer(1)),
                VarBind::new(oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0), Value::Integer(2)),
            ],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // Should have error on varbind 2
        assert_eq!(response.error_index, 2);
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
        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Integer(1),
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status, 0);
        assert_eq!(free_count.load(Ordering::Relaxed), 0);
    }

    /// Handler that always accepts test_set and counts commit_set invocations,
    /// used to prove the SET size check terminates before the commit phase.
    struct CommitTracker {
        commit_count: Arc<AtomicU32>,
    }

    impl MibHandler for CommitTracker {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, _oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async { GetResult::NoSuchObject })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, GetNextResult> {
            Box::pin(async { GetNextResult::EndOfMibView })
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
            .max_message_size(150)
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .without_builtin_handlers()
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        // The echoed Response for five varbinds exceeds the 150-byte limit.
        // RFC 3416 Section 4.2.5 requires returning tooBig before any commit.
        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: five_set_varbinds(),
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, ErrorStatus::TooBig.as_i32());
        assert_eq!(response.error_index, 0);
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
        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
                Value::Integer(1),
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();
        assert_eq!(response.error_status, 0);
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
        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: vec![VarBind::new(
                oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
                Value::Integer(1),
            )],
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_index, 1);
        assert_eq!(free_count.load(Ordering::Relaxed), 0);
    }

    /// Handler for exercising the commit-phase rollback path (RFC 3416 §4.2.5):
    /// `test_set` always accepts, `commit_set` fails for a single designated OID,
    /// and `undo_set` records every OID it is called with, in call order, so
    /// tests can assert the rollback happens in reverse commit order. `undo_set`
    /// itself can also be configured to fail for a designated OID, to exercise
    /// the `UndoFailed` selection.
    struct CommitFailHandler {
        fail_commit_oid: Oid,
        fail_undo_oid: Option<Oid>,
        undo_calls: Arc<Mutex<Vec<Oid>>>,
    }

    impl MibHandler for CommitFailHandler {
        fn get<'a>(&'a self, _ctx: &'a RequestContext, _oid: &'a Oid) -> BoxFuture<'a, GetResult> {
            Box::pin(async { GetResult::NoSuchObject })
        }

        fn get_next<'a>(
            &'a self,
            _ctx: &'a RequestContext,
            _oid: &'a Oid,
        ) -> BoxFuture<'a, GetNextResult> {
            Box::pin(async { GetNextResult::EndOfMibView })
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
            self.undo_calls.lock().unwrap().push(oid.clone());
            let result = if self.fail_undo_oid.as_ref() == Some(oid) {
                SetResult::UndoFailed
            } else {
                SetResult::Ok
            };
            Box::pin(async move { result })
        }
    }

    /// Three-varbind SET where the first two `commit_set` calls succeed and the
    /// third fails: a commit failure with two previously-committed varbinds to
    /// roll back (in reverse order).
    fn three_set_varbinds() -> Vec<VarBind> {
        (1u32..=3)
            .map(|i| {
                VarBind::new(
                    oid!(1, 3, 6, 1, 4, 1, 99999, i, 0),
                    Value::Integer(i as i32),
                )
            })
            .collect()
    }

    #[tokio::test]
    async fn test_commit_failure_rolls_back_in_reverse_order() {
        let undo_calls: Arc<Mutex<Vec<Oid>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CommitFailHandler {
            fail_commit_oid: oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0),
            fail_undo_oid: None,
            undo_calls: undo_calls.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: three_set_varbinds(),
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // Third varbind's commit_set fails -> CommitFailed, error_index points
        // at the failing (1-based) varbind.
        assert_eq!(response.error_status, ErrorStatus::CommitFailed.as_i32());
        assert_eq!(response.error_index, 3);

        // The first two varbinds were committed; rollback must undo them in
        // reverse order (varbind 2 then varbind 1).
        let calls = undo_calls.lock().unwrap();
        assert_eq!(
            *calls,
            vec![
                oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            ]
        );
    }

    #[tokio::test]
    async fn test_undo_failure_during_rollback_reports_undo_failed() {
        let undo_calls: Arc<Mutex<Vec<Oid>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CommitFailHandler {
            fail_commit_oid: oid!(1, 3, 6, 1, 4, 1, 99999, 3, 0),
            fail_undo_oid: Some(oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0)),
            undo_calls: undo_calls.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: three_set_varbinds(),
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        // The undo for varbind 1 fails during rollback -> UndoFailed takes
        // precedence over CommitFailed.
        assert_eq!(response.error_status, ErrorStatus::UndoFailed.as_i32());
        // RFC 3416 4.2.5: undoFailed carries error-index zero (unlike
        // commitFailed, which carries the failed binding's index).
        assert_eq!(response.error_index, 0);

        // Both previously-committed varbinds are still attempted, in reverse
        // order, even though one of the undos fails.
        let calls = undo_calls.lock().unwrap();
        assert_eq!(
            *calls,
            vec![
                oid!(1, 3, 6, 1, 4, 1, 99999, 2, 0),
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0),
            ]
        );
    }

    #[tokio::test]
    async fn test_all_commits_succeed_no_undo() {
        let undo_calls: Arc<Mutex<Vec<Oid>>> = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(CommitFailHandler {
            // No OID in the request matches this, so every commit_set succeeds.
            fail_commit_oid: oid!(1, 3, 6, 1, 4, 1, 99999, 99, 0),
            fail_undo_oid: None,
            undo_calls: undo_calls.clone(),
        });

        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
            .build()
            .await
            .unwrap();

        let ctx = test_ctx();

        let pdu = Pdu {
            pdu_type: PduType::SetRequest,
            request_id: 1,
            error_status: 0,
            error_index: 0,
            varbinds: three_set_varbinds(),
        };

        let response = agent.dispatch_request(&ctx, &pdu).await.unwrap();

        assert_eq!(response.error_status, 0);
        assert!(undo_calls.lock().unwrap().is_empty());
    }
}
