//! Simple SNMP Agent Example
//!
//! This example shows how to create a minimal SNMP agent that responds to
//! GET, GETNEXT, GETBULK, and SET requests.
//!
//! Run with: cargo run --example simple_agent
//!
//! Test with:
//!   snmpget -v2c -c public localhost:11161 sysDescr.0
//!   snmpwalk -v2c -c public localhost:11161 system
//!   snmpbulkwalk -v2c -c public localhost:11161 system

use async_snmp::{
    Agent, BoxFuture, GetNextResult, GetResult, MibHandler, Oid, RequestContext, SetResult, Value,
    VarBind, oid,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

/// Handler for the system MIB subtree (1.3.6.1.2.1.1)
struct SystemHandler {
    /// A settable counter for demonstration
    counter: AtomicI32,
}

impl SystemHandler {
    fn new() -> Self {
        Self {
            counter: AtomicI32::new(0),
        }
    }

    /// Get all OIDs this handler provides, in lexicographic order
    fn all_oids(&self) -> Vec<(Oid, Value)> {
        vec![
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0), // sysDescr.0
                Value::OctetString("async-snmp Example Agent v0.1".into()),
            ),
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 2, 0), // sysObjectID.0
                Value::ObjectIdentifier(oid!(1, 3, 6, 1, 4, 1, 99999)),
            ),
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime.0
                Value::TimeTicks(12345),
            ),
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 4, 0), // sysContact.0
                Value::OctetString("admin@example.com".into()),
            ),
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName.0
                Value::OctetString("example-host".into()),
            ),
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 6, 0), // sysLocation.0
                Value::OctetString("Server Room".into()),
            ),
            (
                oid!(1, 3, 6, 1, 2, 1, 1, 7, 0), // sysServices.0
                Value::Integer(72),
            ),
            (
                oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0), // Custom counter
                Value::Integer(self.counter.load(Ordering::Relaxed)),
            ),
        ]
    }
}

impl MibHandler for SystemHandler {
    fn get<'a>(&'a self, _ctx: &'a RequestContext, oid: &'a Oid) -> BoxFuture<'a, GetResult> {
        Box::pin(async move {
            self.all_oids()
                .into_iter()
                .find(|(o, _)| o == oid)
                .map(|(_, v)| GetResult::Value(v))
                .unwrap_or(GetResult::NoSuchObject)
        })
    }

    fn get_next<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
    ) -> BoxFuture<'a, GetNextResult> {
        Box::pin(async move {
            self.all_oids()
                .into_iter()
                .find(|(o, _)| o > oid)
                .map(|(o, v)| GetNextResult::Value(VarBind::new(o, v)))
                .unwrap_or(GetNextResult::EndOfMibView)
        })
    }

    fn test_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async move {
            // Only allow setting the custom counter with an integer value
            if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                if matches!(value, Value::Integer(_)) {
                    return SetResult::Ok;
                }
                return SetResult::WrongType;
            }
            SetResult::NotWritable
        })
    }

    fn commit_set<'a>(
        &'a self,
        _ctx: &'a RequestContext,
        oid: &'a Oid,
        value: &'a Value,
    ) -> BoxFuture<'a, SetResult> {
        Box::pin(async move {
            if oid == &oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0) {
                if let Value::Integer(v) = value {
                    self.counter.store(*v, Ordering::Relaxed);
                    println!("Counter set to: {}", v);
                    return SetResult::Ok;
                }
            }
            SetResult::CommitFailed
        })
    }
}

#[tokio::main]
async fn main() -> async_snmp::Result<()> {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("async_snmp=debug".parse().unwrap()),
        )
        .init();

    let handler = Arc::new(SystemHandler::new());

    let agent = Agent::builder()
        .bind("127.0.0.1:11161")
        .community(b"public")
        .community(b"private")
        // Register handler for system MIB and custom enterprise OID
        .handler(oid!(1, 3, 6, 1, 2, 1, 1), handler.clone())
        .handler(oid!(1, 3, 6, 1, 4, 1, 99999), handler)
        .build()
        .await?;

    println!("SNMP Agent listening on {}", agent.local_addr());
    println!();
    println!("Test with:");
    println!("  snmpget -v2c -c public localhost:11161 sysDescr.0");
    println!("  snmpwalk -v2c -c public localhost:11161 system");
    println!("  snmpset -v2c -c public localhost:11161 1.3.6.1.4.1.99999.1.0 i 42");
    println!();

    agent.run().await
}
