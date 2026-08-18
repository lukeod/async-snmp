//! Use async-snmp from synchronous code
//!
//! async-snmp is asynchronous, but a synchronous application can call it with
//! Tokio's `Runtime::block_on`.
//!
//! The code uses two patterns:
//!
//! - For a one-shot call, create a runtime, complete the SNMP operation, and
//!   drop the runtime.
//! - For repeated calls, keep a runtime and client alive.
//!
//! Run `cargo run --example sync_wrapper`.

use async_snmp::{
    Auth, Client, Error, FixedCardinalityResponse, ResponseShapePolicy, Retry, Value, VarBind, oid,
};
use bytes::Bytes;
use std::net::SocketAddr;
use std::time::Duration;

/// Creates a runtime for one SNMP operation.
///
/// This pattern suits CLI tools, scripts, and infrequent SNMP calls.
fn oneshot_get(
    target: (&str, u16),
    community: &str,
) -> Result<FixedCardinalityResponse, Box<Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let client = Client::builder(
            target,
            Auth::v2c(Bytes::copy_from_slice(community.as_bytes())),
        )
        .response_shape_policy(ResponseShapePolicy::Strict)
        .request_timeout(Duration::from_secs(5))
        .retry(Retry::fixed(2, Duration::ZERO).expect("valid retry count"))
        .connect()
        .await?;

        client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await
    })
}

/// Keeps a runtime and client alive for repeated calls.
///
/// This wrapper exposes synchronous methods for an asynchronous client.
struct SyncSnmpClient {
    rt: tokio::runtime::Runtime,
    client: Client,
}

impl SyncSnmpClient {
    fn connect(target: (&str, u16), community: &str) -> Result<Self, Box<Error>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");

        let client = rt.block_on(async {
            Client::builder(
                target,
                Auth::v2c(Bytes::copy_from_slice(community.as_bytes())),
            )
            .response_shape_policy(ResponseShapePolicy::Strict)
            .request_timeout(Duration::from_secs(5))
            .retry(Retry::fixed(2, Duration::ZERO).expect("valid retry count"))
            .connect()
            .await
        })?;

        Ok(Self { rt, client })
    }

    fn get(&self, oid: &async_snmp::Oid) -> Result<FixedCardinalityResponse, Box<Error>> {
        self.rt.block_on(self.client.get(oid))
    }

    fn get_many(&self, oids: &[async_snmp::Oid]) -> Result<FixedCardinalityResponse, Box<Error>> {
        self.rt.block_on(self.client.get_many(oids))
    }

    #[allow(dead_code)]
    fn set(
        &self,
        oid: &async_snmp::Oid,
        value: Value,
    ) -> Result<FixedCardinalityResponse, Box<Error>> {
        self.rt.block_on(self.client.set(oid, value))
    }

    fn walk(&self, oid: async_snmp::Oid) -> Result<Vec<VarBind>, Box<Error>> {
        self.rt.block_on(async {
            let walk = self.client.walk(oid)?;
            walk.collect().await
        })
    }

    fn peer_addr(&self) -> SocketAddr {
        self.client.peer_addr()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = ("127.0.0.1", 11161);

    // =========================================================================
    // Make one call without retaining a runtime.
    // =========================================================================
    println!("--- One-shot GET ---\n");

    match oneshot_get(target, "public") {
        Ok(response) => println!(
            "sysDescr: {:?}",
            response
                .single()
                .expect("strict response policy returns a singleton")
                .value
        ),
        Err(e) => println!("Error: {e}"),
    }

    // =========================================================================
    // Reuse a runtime and client across calls.
    // =========================================================================
    println!("\n--- Persistent client ---\n");

    let client = SyncSnmpClient::connect(target, "public")?;
    println!("UDP client configured for {}", client.peer_addr());

    // Retrieve sysDescr.0.
    let response = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0))?;
    println!(
        "sysDescr: {:?}",
        response
            .single()
            .expect("strict response policy returns a singleton")
            .value
    );

    // Retrieve sysUpTime.0 and sysName.0 in one request.
    let vbs = client.get_many(&[
        oid!(1, 3, 6, 1, 2, 1, 1, 3, 0), // sysUpTime
        oid!(1, 3, 6, 1, 2, 1, 1, 5, 0), // sysName
    ])?;
    for vb in &vbs.varbinds {
        println!("  {}: {:?}", vb.oid, vb.value);
    }

    // Walk the system subtree.
    let results = client.walk(oid!(1, 3, 6, 1, 2, 1, 1))?;
    println!("System subtree: {} OIDs", results.len());

    println!("\nExample complete!");
    Ok(())
}
