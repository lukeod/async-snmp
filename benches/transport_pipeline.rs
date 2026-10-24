//! Docker-free loopback request pipeline, including dispatch and framing.
//!
//! Run with `cargo bench --bench transport_pipeline --features agent`.
//! Setup and discovery are excluded. Each iteration is a batch of concurrent
//! GETs; throughput counts requests, while reported time is per batch. A
//! current-thread runtime keeps scheduling reproducible; these timings are not
//! estimates of remote-device latency or multi-core throughput.
//! Supplied TCP streams use TCP_NODELAY so delayed ACKs do not dominate batches.

use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
};
use async_snmp::{
    Agent, Auth, AuthProtocol, AuthoritativeEngine, Client, ClientBuilder, Oid, PrivProtocol,
    RequestTransport, Retry, TcpTransport, UsmConfig, Value, oid,
};
use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::{hint::black_box, sync::Arc, time::Duration};
use tokio::runtime::{Builder, Runtime};

const AUTH_PASSWORD: &[u8] = b"benchmark-auth";
const PRIV_PASSWORD: &[u8] = b"benchmark-priv";

struct ValueHandler(Bytes);

impl MibHandler for ValueHandler {
    fn get<'a>(
        &'a self,
        _: &'a RequestContext,
        _: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetResult>> {
        Box::pin(async move { Ok(GetResult::Value(Value::OctetString(self.0.clone()))) })
    }

    fn get_next<'a>(
        &'a self,
        _: &'a RequestContext,
        _: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async { Ok(GetNextResult::EndOfMibView) })
    }
}

fn secure_builder(engine_id: &[u8]) -> async_snmp::agent::AgentBuilder {
    Agent::builder()
        .bind("127.0.0.1:0")
        .authoritative_engine(
            AuthoritativeEngine::install(engine_id.to_vec(), |_| {
                Ok::<_, std::convert::Infallible>(())
            })
            .unwrap(),
        )
        .usm_user("benchmark", |user| {
            user.auth_priv(
                AuthProtocol::Sha256,
                AUTH_PASSWORD,
                PrivProtocol::Aes128,
                PRIV_PASSWORD,
            )
        })
        .unwrap()
        .allow_all_access()
}

fn benchmark_client<T: RequestTransport>(
    criterion: &mut Criterion,
    runtime: &Runtime,
    name: &str,
    client: &Client<T>,
    value_len: usize,
) {
    let oid = oid!(1, 3, 6, 1, 4, 1, 99999, 1, 0);
    // Complete discovery and warm every concurrent request path before timing.
    runtime.block_on(async {
        for _ in 0..16 {
            let response = client.get(&oid).await.unwrap();
            assert_eq!(
                response.varbinds[0].value.as_bytes().unwrap().len(),
                value_len
            );
        }
    });
    let mut group = criterion.benchmark_group(name);
    for concurrency in [1_u64, 16] {
        group.throughput(Throughput::Elements(concurrency));
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |benchmark, &concurrency| {
                benchmark.to_async(runtime).iter(|| async {
                    let responses =
                        futures::future::try_join_all((0..concurrency).map(|_| client.get(&oid)))
                            .await
                            .unwrap();
                    black_box(responses);
                });
            },
        );
    }
    group.finish();
}

fn transport_pipeline(criterion: &mut Criterion) {
    let runtime = Builder::new_current_thread().enable_all().build().unwrap();
    let prefix = oid!(1, 3, 6, 1, 4, 1, 99999);

    let (agent, client) = runtime.block_on(async {
        let agent = Agent::builder()
            .bind("127.0.0.1:0")
            .community(b"public")
            .allow_all_access()
            .handler(prefix.clone(), Arc::new(ValueHandler(vec![42; 32].into())))
            .spawn()
            .await
            .unwrap();
        let client = Client::builder(
            agent.bound_addresses()[0].local_addr.to_string(),
            Auth::v2c("public"),
        )
        .retry(Retry::none())
        .connect()
        .await
        .unwrap();
        (agent, client)
    });
    benchmark_client(criterion, &runtime, "pipeline/udp_v2c", &client, 32);
    drop(client);
    runtime.block_on(agent.shutdown()).unwrap();

    for privacy in [false, true] {
        let (agent, manager, client) = runtime.block_on(async {
            let agent = secure_builder(b"benchmark-device")
                .handler(prefix.clone(), Arc::new(ValueHandler(vec![42; 512].into())))
                .spawn()
                .await
                .unwrap();
            let manager = secure_builder(b"benchmark-manager")
                .client_exchanges(true)
                .spawn()
                .await
                .unwrap();
            let bound = manager.bound_addresses()[0];
            let endpoint = manager.udp_endpoint(bound.endpoint_id).unwrap();
            let auth = if privacy {
                UsmConfig::new("benchmark")
                    .auth_priv(
                        AuthProtocol::Sha256,
                        AUTH_PASSWORD,
                        PrivProtocol::Aes128,
                        PRIV_PASSWORD,
                    )
                    .unwrap()
            } else {
                UsmConfig::new("benchmark")
                    .auth(AuthProtocol::Sha256, AUTH_PASSWORD)
                    .unwrap()
            };
            let client = ClientBuilder::new(Auth::from(auth))
                .retry(Retry::none())
                .build_with_transport(
                    endpoint
                        .handle(agent.bound_addresses()[0].local_addr)
                        .unwrap(),
                )
                .unwrap();
            (agent, manager, client)
        });
        benchmark_client(
            criterion,
            &runtime,
            if privacy {
                "pipeline/udp_authpriv_shared"
            } else {
                "pipeline/udp_authnopriv_shared"
            },
            &client,
            512,
        );
        drop(client);
        runtime.block_on(manager.shutdown()).unwrap();
        runtime.block_on(agent.shutdown()).unwrap();
    }

    for value_len in [32, 32 * 1024] {
        let (agent, session, client) = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let connected = tokio::net::TcpStream::connect(listener.local_addr().unwrap());
            let (connected, accepted) = tokio::join!(connected, listener.accept());
            let connected = connected.unwrap();
            let (accepted, _) = accepted.unwrap();
            connected.set_nodelay(true).unwrap();
            accepted.set_nodelay(true).unwrap();
            let agent = Agent::builder()
                .session(TcpTransport::builder().from_stream(accepted))
                .community(b"public")
                .max_message_size(65_507)
                .allow_all_access()
                .handler(
                    prefix.clone(),
                    Arc::new(ValueHandler(vec![42; value_len].into())),
                )
                .spawn()
                .await
                .unwrap();
            let session = TcpTransport::builder()
                .from_stream(connected)
                .spawn()
                .await
                .unwrap();
            let client = ClientBuilder::new(Auth::v2c("public"))
                .retry(Retry::none())
                .build_with_transport(session.transport())
                .unwrap();
            (agent, session, client)
        });
        benchmark_client(
            criterion,
            &runtime,
            &format!("pipeline/tcp_v2c_{value_len}"),
            &client,
            value_len,
        );
        drop(client);
        runtime.block_on(session.shutdown()).unwrap();
        runtime.block_on(agent.shutdown()).unwrap();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(2));
    targets = transport_pipeline
}
criterion_main!(benches);
