//! SNMP Agent with Writable Objects
//!
//! Demonstrates a MibHandler that supports SET operations using the
//! library's two-phase SET protocol (RFC 3416):
//!
//! 1. **test_set** - Validate and optionally reserve resources
//! 2. **commit_set** - Apply the change
//!
//! After validation, both commits in this example are infallible and reserve no
//! resources, so the default `undo_set` and `free_set` implementations are
//! sufficient. A handler whose commit can fail must retain the previous value
//! and restore it from `undo_set`.
//!
//! The example exposes a small configuration subtree under a private
//! enterprise OID with two writable scalars (a string and an integer)
//! and one read-only counter.
//!
//! Run with: cargo run --example agent_with_set --features agent

use async_snmp::agent::Agent;
use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext, SetResult,
};
use async_snmp::value::Value;
use async_snmp::varbind::VarBind;
use async_snmp::{Oid, oid};
use bytes::Bytes;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

// Private enterprise OID: 1.3.6.1.4.1.99999
// .1.0 = configName (read-write, OctetString, max 64 bytes)
// .2.0 = configInterval (read-write, Integer, 1..3600)
// .3.0 = configChangeCount (read-only, Counter32)

const OID_CONFIG_NAME: [u32; 9] = [1, 3, 6, 1, 4, 1, 99999, 1, 0];
const OID_CONFIG_INTERVAL: [u32; 9] = [1, 3, 6, 1, 4, 1, 99999, 2, 0];
const OID_CONFIG_CHANGES: [u32; 9] = [1, 3, 6, 1, 4, 1, 99999, 3, 0];

struct ConfigHandler {
    name: RwLock<Bytes>,
    interval: RwLock<i32>,
    change_count: AtomicU32,
}

impl ConfigHandler {
    fn new() -> Self {
        Self {
            name: RwLock::new(Bytes::from_static(b"default")),
            interval: RwLock::new(60),
            change_count: AtomicU32::new(0),
        }
    }

    fn oid_config_name() -> Oid {
        Oid::from(OID_CONFIG_NAME.as_slice())
    }
    fn oid_config_interval() -> Oid {
        Oid::from(OID_CONFIG_INTERVAL.as_slice())
    }
    fn oid_config_changes() -> Oid {
        Oid::from(OID_CONFIG_CHANGES.as_slice())
    }

    /// Return OIDs in lexicographic order for GETNEXT.
    fn all_oids() -> [Oid; 3] {
        [
            Self::oid_config_name(),
            Self::oid_config_interval(),
            Self::oid_config_changes(),
        ]
    }

    fn get_value(&self, oid: &Oid) -> GetResult {
        if oid.as_ref() == OID_CONFIG_NAME {
            let name = self.name.read().unwrap();
            GetResult::Value(Value::OctetString(name.clone()))
        } else if oid.as_ref() == OID_CONFIG_INTERVAL {
            let interval = *self.interval.read().unwrap();
            GetResult::Value(Value::Integer(interval))
        } else if oid.as_ref() == OID_CONFIG_CHANGES {
            GetResult::Value(Value::Counter32(self.change_count.load(Ordering::Relaxed)))
        } else if oid.as_ref().starts_with(&OID_CONFIG_NAME[..8])
            || oid.as_ref().starts_with(&OID_CONFIG_INTERVAL[..8])
            || oid.as_ref().starts_with(&OID_CONFIG_CHANGES[..8])
        {
            // The scalar object exists, but only its .0 instance is valid.
            GetResult::NoSuchInstance
        } else {
            GetResult::NoSuchObject
        }
    }
}

impl MibHandler for ConfigHandler {
    fn get<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move { Ok(self.get_value(oid)) })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            // Find the first OID strictly greater than the requested one.
            for candidate in Self::all_oids() {
                if &candidate > oid
                    && let GetResult::Value(v) = self.get_value(&candidate)
                {
                    return Ok(GetNextResult::Value(VarBind::new(candidate, v)));
                }
            }
            Ok(GetNextResult::EndOfMibView)
        })
    }

    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async move {
            if oid.as_ref() == OID_CONFIG_NAME {
                match value {
                    Value::OctetString(bytes) if bytes.len() <= 64 => SetResult::Ok,
                    Value::OctetString(_) => SetResult::WrongLength,
                    _ => SetResult::WrongType,
                }
            } else if oid.as_ref() == OID_CONFIG_INTERVAL {
                match value {
                    Value::Integer(v) if (1..=3600).contains(v) => SetResult::Ok,
                    Value::Integer(_) => SetResult::WrongValue,
                    _ => SetResult::WrongType,
                }
            } else if oid.as_ref() == OID_CONFIG_CHANGES {
                // Read-only counter
                SetResult::NotWritable
            } else {
                SetResult::NoAccess
            }
        })
    }

    fn commit_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async move {
            if oid.as_ref() == OID_CONFIG_NAME
                && let Value::OctetString(bytes) = value
            {
                *self.name.write().unwrap() = bytes.clone();
                self.change_count.fetch_add(1, Ordering::Relaxed);
                return SetResult::Ok;
            } else if oid.as_ref() == OID_CONFIG_INTERVAL
                && let Value::Integer(v) = value
            {
                *self.interval.write().unwrap() = *v;
                self.change_count.fetch_add(1, Ordering::Relaxed);
                return SetResult::Ok;
            }
            SetResult::CommitFailed
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=info".parse()?),
        )
        .init();

    let handler = Arc::new(ConfigHandler::new());

    let agent = Agent::builder()
        .bind("0.0.0.0:10161")
        .community(b"private")
        .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
        .build()
        .await?;

    println!("Agent listening on {}", agent.local_addr());
    println!();
    println!("Try these commands:");
    println!("  snmpget -v2c -c private localhost:10161 1.3.6.1.4.1.99999.1.0");
    println!("  snmpset -v2c -c private localhost:10161 1.3.6.1.4.1.99999.1.0 s 'new name'");
    println!("  snmpset -v2c -c private localhost:10161 1.3.6.1.4.1.99999.2.0 i 120");
    println!("  snmpget -v2c -c private localhost:10161 1.3.6.1.4.1.99999.3.0");
    println!("  snmpwalk -v2c -c private localhost:10161 1.3.6.1.4.1.99999");

    agent.run().await?;
    Ok(())
}
