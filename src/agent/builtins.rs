//! Built-in MIB handlers for SNMP engine, USM, and MPD statistics.
//!
//! These handlers provide read-only access to agent engine state and
//! RFC-defined statistics counters. They are registered automatically
//! during agent construction.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
};
use crate::oid;
use crate::oid::Oid;
use crate::value::Value;
use crate::varbind::VarBind;

use super::AgentState;

/// Number of arcs in the snmpEngine prefix (1.3.6.1.6.3.10.2.1).
const SNMP_ENGINE_PREFIX_LEN: usize = 9;
/// Number of arcs in the usmStats prefix (1.3.6.1.6.3.15.1.1).
const USM_STATS_PREFIX_LEN: usize = 9;
/// Number of arcs in the mpdStats prefix (1.3.6.1.6.3.11.2.1).
const MPD_STATS_PREFIX_LEN: usize = 9;

// ---------------------------------------------------------------------------
// SnmpEngineHandler
// ---------------------------------------------------------------------------

/// Handler for the snmpEngine group (1.3.6.1.6.3.10.2.1).
///
/// Exposes four read-only scalars:
/// - snmpEngineID (.1.0)
/// - snmpEngineBoots (.2.0)
/// - snmpEngineTime (.3.0)
/// - snmpEngineMaxMessageSize (.4.0)
pub(crate) struct SnmpEngineHandler {
    pub(crate) state: Arc<AgentState>,
}

impl SnmpEngineHandler {
    fn prefix() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 10, 2, 1)
    }

    fn get_column_value(&self, col: u32) -> Option<Value> {
        match col {
            1 => Some(Value::OctetString(self.state.engine_id.clone())),
            2 => Some(Value::Integer(
                self.state.engine_boots.load(Ordering::Relaxed) as i32,
            )),
            3 => Some(Value::Integer(
                self.state.engine_time.load(Ordering::Relaxed) as i32,
            )),
            4 => Some(Value::Integer(self.state.max_message_size as i32)),
            _ => None,
        }
    }
}

impl MibHandler for SnmpEngineHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move {
            let arcs = oid.arcs();
            if arcs.len() != SNMP_ENGINE_PREFIX_LEN + 2 {
                return Ok(GetResult::NoSuchObject);
            }
            let col = arcs[SNMP_ENGINE_PREFIX_LEN];
            let instance = arcs[SNMP_ENGINE_PREFIX_LEN + 1];
            if instance != 0 {
                return Ok(GetResult::NoSuchInstance);
            }
            match self.get_column_value(col) {
                Some(v) => Ok(GetResult::Value(v)),
                None => Ok(GetResult::NoSuchObject),
            }
        })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            let prefix = Self::prefix();
            for col in 1..=4u32 {
                let scalar_oid = prefix.child(col).child(0);
                if oid < &scalar_oid {
                    let value = self.get_column_value(col).unwrap();
                    return Ok(GetNextResult::Value(VarBind::new(scalar_oid, value)));
                }
            }
            Ok(GetNextResult::EndOfMibView)
        })
    }
}

// ---------------------------------------------------------------------------
// UsmStatsHandler
// ---------------------------------------------------------------------------

/// Handler for the usmStats group (1.3.6.1.6.3.15.1.1).
///
/// Exposes six read-only Counter32 scalars:
/// - usmStatsUnsupportedSecLevels (.1.0)
/// - usmStatsNotInTimeWindows (.2.0)
/// - usmStatsUnknownUserNames (.3.0)
/// - usmStatsUnknownEngineIDs (.4.0)
/// - usmStatsWrongDigests (.5.0)
/// - usmStatsDecryptionErrors (.6.0)
pub(crate) struct UsmStatsHandler {
    pub(crate) state: Arc<AgentState>,
}

impl UsmStatsHandler {
    fn prefix() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 15, 1, 1)
    }

    fn get_column_value(&self, col: u32) -> Option<Value> {
        match col {
            1 => Some(Value::Counter32(
                self.state
                    .usm_stats
                    .unsupported_sec_levels
                    .load(Ordering::Relaxed),
            )),
            2 => Some(Value::Counter32(
                self.state
                    .usm_stats
                    .not_in_time_windows
                    .load(Ordering::Relaxed),
            )),
            3 => Some(Value::Counter32(
                self.state
                    .usm_stats
                    .unknown_usernames
                    .load(Ordering::Relaxed),
            )),
            4 => Some(Value::Counter32(
                self.state
                    .usm_stats
                    .unknown_engine_ids
                    .load(Ordering::Relaxed),
            )),
            5 => Some(Value::Counter32(
                self.state.usm_stats.wrong_digests.load(Ordering::Relaxed),
            )),
            6 => Some(Value::Counter32(
                self.state
                    .usm_stats
                    .decryption_errors
                    .load(Ordering::Relaxed),
            )),
            _ => None,
        }
    }
}

impl MibHandler for UsmStatsHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move {
            let arcs = oid.arcs();
            if arcs.len() != USM_STATS_PREFIX_LEN + 2 {
                return Ok(GetResult::NoSuchObject);
            }
            let col = arcs[USM_STATS_PREFIX_LEN];
            let instance = arcs[USM_STATS_PREFIX_LEN + 1];
            if instance != 0 {
                return Ok(GetResult::NoSuchInstance);
            }
            match self.get_column_value(col) {
                Some(v) => Ok(GetResult::Value(v)),
                None => Ok(GetResult::NoSuchObject),
            }
        })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            let prefix = Self::prefix();
            for col in 1..=6u32 {
                let scalar_oid = prefix.child(col).child(0);
                if oid < &scalar_oid {
                    let value = self.get_column_value(col).unwrap();
                    return Ok(GetNextResult::Value(VarBind::new(scalar_oid, value)));
                }
            }
            Ok(GetNextResult::EndOfMibView)
        })
    }
}

// ---------------------------------------------------------------------------
// MpdStatsHandler
// ---------------------------------------------------------------------------

/// Handler for the snmpMPDStats group (1.3.6.1.6.3.11.2.1).
///
/// Exposes two read-only Counter32 scalars:
/// - snmpUnknownSecurityModels (.1.0)
/// - snmpInvalidMsgs (.2.0)
///
/// Note: snmpUnknownPDUHandlers (.3.0) is not tracked by the agent.
/// snmpSilentDrops lives in SNMPv2-MIB (1.3.6.1.2.1.11.30), not here.
pub(crate) struct MpdStatsHandler {
    pub(crate) state: Arc<AgentState>,
}

impl MpdStatsHandler {
    fn prefix() -> Oid {
        oid!(1, 3, 6, 1, 6, 3, 11, 2, 1)
    }

    fn get_column_value(&self, col: u32) -> Option<Value> {
        match col {
            1 => Some(Value::Counter32(
                self.state
                    .snmp_unknown_security_models
                    .load(Ordering::Relaxed),
            )),
            2 => Some(Value::Counter32(
                self.state.snmp_invalid_msgs.load(Ordering::Relaxed),
            )),
            _ => None,
        }
    }
}

impl MibHandler for MpdStatsHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move {
            let arcs = oid.arcs();
            if arcs.len() != MPD_STATS_PREFIX_LEN + 2 {
                return Ok(GetResult::NoSuchObject);
            }
            let col = arcs[MPD_STATS_PREFIX_LEN];
            let instance = arcs[MPD_STATS_PREFIX_LEN + 1];
            if instance != 0 {
                return Ok(GetResult::NoSuchInstance);
            }
            match self.get_column_value(col) {
                Some(v) => Ok(GetResult::Value(v)),
                None => Ok(GetResult::NoSuchObject),
            }
        })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            let prefix = Self::prefix();
            for col in 1..=2u32 {
                let scalar_oid = prefix.child(col).child(0);
                if oid < &scalar_oid {
                    let value = self.get_column_value(col).unwrap();
                    return Ok(GetNextResult::Value(VarBind::new(scalar_oid, value)));
                }
            }
            Ok(GetNextResult::EndOfMibView)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Instant;

    use bytes::Bytes;

    use crate::handler::{RequestContext, SecurityModel};
    use crate::message::SecurityLevel;
    use crate::pdu::PduType;
    use crate::version::Version;

    fn test_state() -> Arc<AgentState> {
        Arc::new(AgentState {
            engine_id: Bytes::from_static(&[0x80, 0x00, 0x01, 0x02, 0x03]),
            engine_boots: AtomicU32::new(5),
            engine_time: AtomicU32::new(12345),
            engine_start: Instant::now(),
            engine_boots_base: 5,
            max_message_size: 1472,
            snmp_invalid_msgs: AtomicU32::new(10),
            snmp_unknown_security_models: AtomicU32::new(20),
            snmp_silent_drops: AtomicU32::new(30),
            snmp_unknown_contexts: AtomicU32::new(0),
            usm_stats: {
                let stats = crate::v3::process::UsmStats::default();
                stats.unknown_engine_ids.store(40, Ordering::Relaxed);
                stats.unknown_usernames.store(50, Ordering::Relaxed);
                stats.wrong_digests.store(60, Ordering::Relaxed);
                stats.not_in_time_windows.store(70, Ordering::Relaxed);
                stats.unsupported_sec_levels.store(80, Ordering::Relaxed);
                stats.decryption_errors.store(90, Ordering::Relaxed);
                stats
            },
        })
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
            pdu_type: PduType::GetRequest,
            group_name: None,
            read_view: None,
            write_view: None,
            msg_max_size: None,
        }
    }

    // -----------------------------------------------------------------------
    // SnmpEngineHandler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_snmp_engine_get_engine_id() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0))
            .await
            .unwrap();
        match result {
            GetResult::Value(Value::OctetString(v)) => {
                assert_eq!(v.as_ref(), &[0x80, 0x00, 0x01, 0x02, 0x03]);
            }
            other => panic!("expected OctetString, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_snmp_engine_get_boots() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 2, 0))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::Value(Value::Integer(5))));
    }

    #[tokio::test]
    async fn test_snmp_engine_get_time() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 3, 0))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::Value(Value::Integer(12345))));
    }

    #[tokio::test]
    async fn test_snmp_engine_get_max_msg_size() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 4, 0))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::Value(Value::Integer(1472))));
    }

    #[tokio::test]
    async fn test_snmp_engine_get_unknown_column() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 5, 0))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::NoSuchObject));
    }

    #[tokio::test]
    async fn test_snmp_engine_get_non_zero_instance() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 1))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::NoSuchInstance));
    }

    #[tokio::test]
    async fn test_snmp_engine_get_next_walks_all() {
        let handler = SnmpEngineHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let prefix = oid!(1, 3, 6, 1, 6, 3, 10, 2, 1);

        let mut current = prefix.clone();
        let mut count = 0;
        while let GetNextResult::Value(vb) = handler.get_next(&ctx, &current).await.unwrap() {
            count += 1;
            current = vb.oid;
        }
        assert_eq!(count, 4, "should walk through all 4 snmpEngine scalars");
    }

    // -----------------------------------------------------------------------
    // UsmStatsHandler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_usm_stats_get_all_counters() {
        let handler = UsmStatsHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let prefix = oid!(1, 3, 6, 1, 6, 3, 15, 1, 1);

        let expected: [(u32, u32); 6] = [
            (1, 80), // unsupportedSecLevels
            (2, 70), // notInTimeWindows
            (3, 50), // unknownUserNames
            (4, 40), // unknownEngineIDs
            (5, 60), // wrongDigests
            (6, 90), // decryptionErrors
        ];

        for (col, expected_val) in &expected {
            let oid = prefix.child(*col).child(0);
            let result = handler.get(&ctx, &oid).await.unwrap();
            match result {
                GetResult::Value(Value::Counter32(v)) => {
                    assert_eq!(
                        v, *expected_val,
                        "column {col} expected {expected_val}, got {v}"
                    );
                }
                other => panic!("column {col}: expected Counter32, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_usm_stats_get_next_walks_all_six() {
        let handler = UsmStatsHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let prefix = oid!(1, 3, 6, 1, 6, 3, 15, 1, 1);

        let mut current = prefix.clone();
        let mut count = 0;
        while let GetNextResult::Value(vb) = handler.get_next(&ctx, &current).await.unwrap() {
            count += 1;
            current = vb.oid;
        }
        assert_eq!(count, 6, "should walk through all 6 usmStats counters");
    }

    // -----------------------------------------------------------------------
    // MpdStatsHandler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_mpd_stats_get_all_counters() {
        let handler = MpdStatsHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let prefix = oid!(1, 3, 6, 1, 6, 3, 11, 2, 1);

        let expected: [(u32, u32); 2] = [
            (1, 20), // unknownSecurityModels
            (2, 10), // invalidMsgs
        ];

        for (col, expected_val) in &expected {
            let oid = prefix.child(*col).child(0);
            let result = handler.get(&ctx, &oid).await.unwrap();
            match result {
                GetResult::Value(Value::Counter32(v)) => {
                    assert_eq!(
                        v, *expected_val,
                        "column {col} expected {expected_val}, got {v}"
                    );
                }
                other => panic!("column {col}: expected Counter32, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn test_mpd_stats_get_unknown_column() {
        let handler = MpdStatsHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        // Column 3 (snmpUnknownPDUHandlers) is not tracked
        let result = handler
            .get(&ctx, &oid!(1, 3, 6, 1, 6, 3, 11, 2, 1, 3, 0))
            .await
            .unwrap();
        assert!(matches!(result, GetResult::NoSuchObject));
    }

    #[tokio::test]
    async fn test_mpd_stats_get_next_walks_all() {
        let handler = MpdStatsHandler {
            state: test_state(),
        };
        let ctx = test_ctx();
        let prefix = oid!(1, 3, 6, 1, 6, 3, 11, 2, 1);

        let mut current = prefix.clone();
        let mut count = 0;
        while let GetNextResult::Value(vb) = handler.get_next(&ctx, &current).await.unwrap() {
            count += 1;
            current = vb.oid;
        }
        assert_eq!(count, 2, "should walk through all 2 mpdStats counters");
    }
}
