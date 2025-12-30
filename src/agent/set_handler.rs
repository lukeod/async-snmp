//! Two-phase SET commit protocol (RFC 3416).

use std::sync::Arc;

use crate::error::{ErrorStatus, Result};
use crate::handler::{MibHandler, RequestContext};
use crate::oid::Oid;
use crate::pdu::{Pdu, PduType};
use crate::value::Value;
use crate::version::Version;

use super::Agent;

impl Agent {
    /// Handle SET request with two-phase commit protocol.
    ///
    /// Per RFC 3416, SET operations should be atomic. We implement this via:
    /// 1. **Test phase**: Call `test_set` for ALL varbinds. If any fails, abort.
    /// 2. **Commit phase**: Call `commit_set` for each varbind. If any fails,
    ///    call `undo_set` for all previously committed varbinds.
    pub(super) async fn handle_set(&self, ctx: &RequestContext, pdu: &Pdu) -> Result<Pdu> {
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
                if ctx.version == Version::V1 {
                    return Ok(Pdu {
                        pdu_type: PduType::Response,
                        request_id: pdu.request_id,
                        error_status: ErrorStatus::NoSuchName.as_i32(),
                        error_index: (index + 1) as i32,
                        varbinds: pdu.varbinds.clone(),
                    });
                } else {
                    return Ok(Pdu {
                        pdu_type: PduType::Response,
                        request_id: pdu.request_id,
                        error_status: ErrorStatus::NoAccess.as_i32(),
                        error_index: (index + 1) as i32,
                        varbinds: pdu.varbinds.clone(),
                    });
                }
            }

            let handler = self.find_handler(&vb.oid);

            if handler.is_none() {
                // No handler for this OID
                if ctx.version == Version::V1 {
                    return Ok(Pdu {
                        pdu_type: PduType::Response,
                        request_id: pdu.request_id,
                        error_status: ErrorStatus::NoSuchName.as_i32(),
                        error_index: (index + 1) as i32,
                        varbinds: pdu.varbinds.clone(),
                    });
                } else {
                    return Ok(Pdu {
                        pdu_type: PduType::Response,
                        request_id: pdu.request_id,
                        error_status: ErrorStatus::NotWritable.as_i32(),
                        error_index: (index + 1) as i32,
                        varbinds: pdu.varbinds.clone(),
                    });
                }
            }

            let handler = handler.unwrap();
            let result = handler.handler.test_set(ctx, &vb.oid, &vb.value).await;

            if !result.is_ok() {
                return Ok(Pdu {
                    pdu_type: PduType::Response,
                    request_id: pdu.request_id,
                    error_status: result.to_error_status().as_i32(),
                    error_index: (index + 1) as i32,
                    varbinds: pdu.varbinds.clone(),
                });
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
                for c in committed.iter().rev() {
                    c.handler.undo_set(ctx, &c.oid, &c.value).await;
                }

                return Ok(Pdu {
                    pdu_type: PduType::Response,
                    request_id: pdu.request_id,
                    error_status: ErrorStatus::CommitFailed.as_i32(),
                    error_index: (index + 1) as i32,
                    varbinds: pdu.varbinds.clone(),
                });
            }

            committed.push(p);
        }

        // All commits succeeded
        Ok(Pdu {
            pdu_type: PduType::Response,
            request_id: pdu.request_id,
            error_status: 0,
            error_index: 0,
            varbinds: pdu.varbinds.clone(),
        })
    }
}
