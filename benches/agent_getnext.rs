//! End-to-end GETNEXT latency with independent I/O-backed handlers.

use async_snmp::agent::Agent;
use async_snmp::handler::{
    BoxFuture, GetNextResult, GetResult, HandlerResult, MibHandler, RequestContext,
};
use async_snmp::{Auth, Client, Oid, Value, VarBind, oid};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

struct DelayedHandler {
    candidate: Oid,
    delay: Duration,
}

impl MibHandler for DelayedHandler {
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
        oid: &'a Oid,
    ) -> BoxFuture<'a, HandlerResult<GetNextResult>> {
        Box::pin(async move {
            tokio::time::sleep(self.delay).await;
            Ok(if self.candidate > *oid {
                GetNextResult::Value(VarBind::new(self.candidate.clone(), Value::Integer(1)))
            } else {
                GetNextResult::EndOfMibView
            })
        })
    }
}

fn bench_io_backed_handlers(c: &mut Criterion) {
    let runtime = Runtime::new().unwrap();
    let cursor = oid!(1, 3, 6, 1, 4, 1, 50000);

    for handler_count in [4_u32, 8, 17] {
        let (agent, client, run) = runtime.block_on(async {
            let mut builder = Agent::builder()
                .bind("127.0.0.1:0")
                .community(b"public")
                .without_builtin_handlers();
            for index in 1..=handler_count {
                let prefix = cursor.child(index);
                builder = builder.handler(
                    prefix.clone(),
                    Arc::new(DelayedHandler {
                        candidate: prefix.child(0),
                        delay: if handler_count > 16 && (index == 1 || index == handler_count) {
                            Duration::from_millis(2)
                        } else if handler_count > 16 {
                            Duration::ZERO
                        } else {
                            Duration::from_millis(2)
                        },
                    }),
                );
            }
            let agent = builder.allow_all_access().build().await.unwrap();
            let client = Client::builder(agent.local_addr().to_string(), Auth::v2c("public"))
                .request_timeout(Duration::from_secs(1))
                .connect()
                .await
                .unwrap();
            let run_agent = agent.clone();
            let run = tokio::spawn(async move { run_agent.run().await });
            (agent, client, run)
        });

        c.bench_with_input(
            BenchmarkId::new("agent_getnext_io_handlers", handler_count),
            &handler_count,
            |benchmark, _| {
                benchmark
                    .to_async(&runtime)
                    .iter(|| async { black_box(client.get_next(&cursor).await.unwrap()) });
            },
        );

        agent.cancel().cancel();
        runtime.block_on(run).unwrap().unwrap();
    }
}

criterion_group!(benches, bench_io_backed_handlers);
criterion_main!(benches);
