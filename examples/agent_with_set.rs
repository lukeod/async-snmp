//! SNMP Agent with Writable Objects
//!
//! Demonstrates a MibHandler that supports SET operations using the
//! library's two-phase SET protocol (RFC 3416):
//!
//! 1. **test_set** - Validate and return request-owned prepared state
//! 2. **PreparedSet::commit** - Apply the change
//! 3. **PreparedSet::finalize** - Release successful transaction state
//!
//! Each prepared change retains the previous value so `undo` can restore it if
//! a later binding's commit fails.
//!
//! The example exposes a small configuration subtree under a private
//! enterprise OID with two writable scalars (a string and an integer)
//! and one read-only counter.
//!
//! Run with: cargo run --example agent_with_set --features agent

use async_snmp::agent::Agent;
use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, PreparedSet, RequestContext,
    SetCommitResult, SetTestError, SetTestResult, SetUndoResult,
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
    name: Arc<RwLock<Bytes>>,
    interval: Arc<RwLock<i32>>,
    change_count: Arc<AtomicU32>,
}

enum ConfigChange {
    Name {
        target: Arc<RwLock<Bytes>>,
        value: Bytes,
        previous: Option<Bytes>,
    },
    Interval {
        target: Arc<RwLock<i32>>,
        value: i32,
        previous: Option<i32>,
    },
}

struct PreparedConfigSet {
    change: ConfigChange,
    change_count: Arc<AtomicU32>,
}

impl PreparedSet for PreparedConfigSet {
    fn commit<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetCommitResult> {
        Box::pin(async move {
            match &mut self.change {
                ConfigChange::Name {
                    target,
                    value,
                    previous,
                } => {
                    *previous = Some(std::mem::replace(
                        &mut *target.write().unwrap(),
                        value.clone(),
                    ));
                }
                ConfigChange::Interval {
                    target,
                    value,
                    previous,
                } => {
                    *previous = Some(std::mem::replace(&mut *target.write().unwrap(), *value));
                }
            }
            self.change_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    }

    fn undo<'a>(
        &'a mut self,
        _ctx: &'a RequestContext,
        _oid: &'a Oid,
        _value: &'a Value,
    ) -> BoxFuture<'a, SetUndoResult> {
        Box::pin(async move {
            let mut restored = false;
            match &mut self.change {
                ConfigChange::Name {
                    target, previous, ..
                } => {
                    if let Some(previous) = previous.take() {
                        *target.write().unwrap() = previous;
                        restored = true;
                    }
                }
                ConfigChange::Interval {
                    target, previous, ..
                } => {
                    if let Some(previous) = previous.take() {
                        *target.write().unwrap() = previous;
                        restored = true;
                    }
                }
            }
            if restored {
                self.change_count.fetch_sub(1, Ordering::Relaxed);
            }
            Ok(())
        })
    }
}

impl ConfigHandler {
    fn new() -> Self {
        Self {
            name: Arc::new(RwLock::new(Bytes::from_static(b"default"))),
            interval: Arc::new(RwLock::new(60)),
            change_count: Arc::new(AtomicU32::new(0)),
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
    ) -> BoxFuture<'a, SetTestResult> {
        Box::pin(async move {
            if oid.as_ref() == OID_CONFIG_NAME {
                match value {
                    Value::OctetString(bytes) if bytes.len() <= 64 => {
                        Ok(Box::new(PreparedConfigSet {
                            change: ConfigChange::Name {
                                target: self.name.clone(),
                                value: bytes.clone(),
                                previous: None,
                            },
                            change_count: self.change_count.clone(),
                        }) as Box<dyn PreparedSet>)
                    }
                    Value::OctetString(_) => Err(SetTestError::WrongLength),
                    _ => Err(SetTestError::WrongType),
                }
            } else if oid.as_ref() == OID_CONFIG_INTERVAL {
                match value {
                    Value::Integer(v) if (1..=3600).contains(v) => Ok(Box::new(PreparedConfigSet {
                        change: ConfigChange::Interval {
                            target: self.interval.clone(),
                            value: *v,
                            previous: None,
                        },
                        change_count: self.change_count.clone(),
                    })
                        as Box<dyn PreparedSet>),
                    Value::Integer(_) => Err(SetTestError::WrongValue),
                    _ => Err(SetTestError::WrongType),
                }
            } else if oid.as_ref() == OID_CONFIG_CHANGES {
                // Read-only counter
                Err(SetTestError::NotWritable)
            } else {
                Err(SetTestError::NoAccess)
            }
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
        .allow_all_access()
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
