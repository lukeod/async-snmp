//! Two-phase SET commit protocol (RFC 3416).

use std::sync::Arc;

use crate::error::{ErrorStatus, Result};
use crate::handler::{MibHandler, RequestContext};
use crate::oid::Oid;
use crate::pdu::Pdu;
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
                let status = if ctx.version == Version::V1 {
                    ErrorStatus::NoSuchName
                } else {
                    ErrorStatus::NoAccess
                };
                return Ok(pdu.to_error_response(status, (index + 1) as i32));
            }

            let handler = self.find_handler(&vb.oid);

            if handler.is_none() {
                // No handler for this OID
                let status = if ctx.version == Version::V1 {
                    ErrorStatus::NoSuchName
                } else {
                    ErrorStatus::NotWritable
                };
                return Ok(pdu.to_error_response(status, (index + 1) as i32));
            }

            let handler = handler.unwrap();
            let result = handler.handler.test_set(ctx, &vb.oid, &vb.value).await;

            if !result.is_ok() {
                return Ok(pdu.to_error_response(result.to_error_status(), (index + 1) as i32));
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
                return Ok(pdu.to_error_response(status, (index + 1) as i32));
            }

            committed.push(p);
        }

        // All commits succeeded
        Ok(pdu.to_response())
    }
}
