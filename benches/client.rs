//! Client benchmarks against a real SNMP agent.
//!
//! These benchmarks test actual network performance against a running snmpd
//! container. They measure end-to-end latency and throughput for common
//! SNMP operations.
//!
//! Prerequisites:
//!   docker run -d --name async-snmp-test-manual -p 11161:161/udp async-snmp-test:latest
//!
//! Or use the test container from tests/containers/snmpd/:
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!   docker run -d --name async-snmp-test-manual -p 11161:161/udp async-snmp-test:latest
//!
//! Run with:
//!   cargo bench --bench client

use async_snmp::{Auth, Client, Retry, oid};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;

const TARGET: &str = "127.0.0.1:11161";
const COMMUNITY: &str = "public";

/// Check if the test container is available
fn is_container_available(rt: &Runtime) -> bool {
    rt.block_on(async {
        match Client::builder(TARGET, Auth::v2c(COMMUNITY))
            .timeout(Duration::from_millis(500))
            .retry(Retry::none())
            .connect()
            .await
        {
            Ok(client) => client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)).await.is_ok(),
            Err(_) => false,
        }
    })
}

/// Benchmark single GET operations
fn bench_get_single(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        eprintln!(
            "Skipping client benchmarks: test container not available at {TARGET}"
        );
        eprintln!(
            "Start with: docker run -d --name async-snmp-test-manual -p 11161:161/udp async-snmp-test:latest"
        );
        return;
    }

    let client = rt.block_on(async {
        Client::builder(TARGET, Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .retry(Retry::fixed(1, Duration::ZERO))
            .connect()
            .await
            .expect("Failed to connect to test container")
    });

    let mut group = c.benchmark_group("client_get");
    group.sample_size(100);

    // Common OIDs
    let oids = [
        ("sysDescr", oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)),
        ("sysUpTime", oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)),
        ("sysName", oid!(1, 3, 6, 1, 2, 1, 1, 5, 0)),
    ];

    for (name, oid) in oids {
        group.bench_with_input(BenchmarkId::new("single", name), &oid, |b, oid| {
            b.to_async(&rt)
                .iter(|| async { black_box(client.get(oid).await.unwrap()) });
        });
    }

    group.finish();
}

/// Benchmark GET with multiple OIDs
fn bench_get_many(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        return;
    }

    let client = rt.block_on(async {
        Client::builder(TARGET, Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .max_oids_per_request(10)
            .connect()
            .await
            .expect("Failed to connect")
    });

    let mut group = c.benchmark_group("client_get_many");
    group.sample_size(50);

    // Test different batch sizes
    let oid_sets: Vec<(usize, Vec<_>)> = vec![
        (
            3,
            vec![
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
                oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
            ],
        ),
        (
            5,
            vec![
                oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
                oid!(1, 3, 6, 1, 2, 1, 1, 2, 0),
                oid!(1, 3, 6, 1, 2, 1, 1, 3, 0),
                oid!(1, 3, 6, 1, 2, 1, 1, 5, 0),
                oid!(1, 3, 6, 1, 2, 1, 1, 6, 0),
            ],
        ),
    ];

    for (count, oids) in &oid_sets {
        group.throughput(Throughput::Elements(*count as u64));
        group.bench_with_input(BenchmarkId::new("batch", count), oids, |b, oids| {
            b.to_async(&rt)
                .iter(|| async { black_box(client.get_many(oids).await.unwrap()) });
        });
    }

    group.finish();
}

/// Benchmark GETNEXT operations
fn bench_get_next(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        return;
    }

    let client = rt.block_on(async {
        Client::builder(TARGET, Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect("Failed to connect")
    });

    let mut group = c.benchmark_group("client_getnext");
    group.sample_size(100);

    let oid = oid!(1, 3, 6, 1, 2, 1, 1);

    group.bench_function("single", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(client.get_next(&oid).await.unwrap()) });
    });

    group.finish();
}

/// Benchmark GETBULK operations
fn bench_get_bulk(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        return;
    }

    let client = rt.block_on(async {
        Client::builder(TARGET, Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect("Failed to connect")
    });

    let mut group = c.benchmark_group("client_getbulk");
    group.sample_size(50);

    let system_oid = oid!(1, 3, 6, 1, 2, 1, 1);

    for max_reps in [5u16, 10, 25] {
        group.throughput(Throughput::Elements(max_reps.into()));
        group.bench_with_input(
            BenchmarkId::new("max_repetitions", max_reps),
            &max_reps,
            |b, &max_reps| {
                b.to_async(&rt).iter(|| async {
                    black_box(
                        client
                            .get_bulk(std::slice::from_ref(&system_oid), 0, max_reps.into())
                            .await
                            .unwrap(),
                    )
                });
            },
        );
    }

    group.finish();
}

/// Benchmark walk operations
fn bench_walk(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        return;
    }

    let client = rt.block_on(async {
        Client::builder(TARGET, Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .connect()
            .await
            .expect("Failed to connect")
    });

    let mut group = c.benchmark_group("client_walk");
    group.sample_size(20);

    // Walk the system subtree
    let system_oid = oid!(1, 3, 6, 1, 2, 1, 1);

    group.bench_function("system_getnext", |b| {
        b.to_async(&rt).iter(|| async {
            let results = client
                .walk_getnext(system_oid.clone())
                .collect()
                .await
                .unwrap();
            black_box(results)
        });
    });

    group.bench_function("system_bulk", |b| {
        b.to_async(&rt).iter(|| async {
            let results = client
                .bulk_walk(system_oid.clone(), 10)
                .collect()
                .await
                .unwrap();
            black_box(results)
        });
    });

    group.bench_function("system_auto", |b| {
        b.to_async(&rt).iter(|| async {
            let results = client
                .walk(system_oid.clone())
                .unwrap()
                .collect()
                .await
                .unwrap();
            black_box(results)
        });
    });

    group.finish();
}

/// Benchmark client construction overhead
fn bench_client_construction(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        return;
    }

    let mut group = c.benchmark_group("client_construction");
    group.sample_size(50);

    group.bench_function("connect_v2c", |b| {
        b.to_async(&rt).iter(|| async {
            let client = Client::builder(TARGET, Auth::v2c(COMMUNITY))
                .timeout(Duration::from_secs(5))
                .connect()
                .await
                .unwrap();
            black_box(client)
        });
    });

    group.finish();
}

/// Benchmark request ID generation and message encoding overhead
fn bench_request_overhead(c: &mut Criterion) {
    use async_snmp::message::CommunityMessage;
    use async_snmp::pdu::Pdu;
    use async_snmp::version::Version;
    use bytes::Bytes;

    let mut group = c.benchmark_group("request_overhead");

    // Measure message encoding (no network)
    let oids = vec![oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)];

    group.bench_function("encode_get_request", |b| {
        b.iter(|| {
            let pdu = Pdu::get_request(12345, &oids);
            let msg = CommunityMessage::new(Version::V2c, Bytes::from_static(b"public"), pdu);
            black_box(msg.encode())
        });
    });

    // Measure response decoding (no network)
    let request = Pdu::get_request(12345, &[oid!(1, 3, 6, 1, 2, 1, 1, 1, 0)]);
    let mut response_pdu = request.to_response();
    response_pdu.varbinds = vec![async_snmp::varbind::VarBind::new(
        oid!(1, 3, 6, 1, 2, 1, 1, 1, 0),
        async_snmp::value::Value::OctetString(Bytes::from_static(
            b"Linux test-host 5.15.0-generic",
        )),
    )];
    let msg = CommunityMessage::new(Version::V2c, Bytes::from_static(b"public"), response_pdu);
    let encoded = msg.encode();

    group.bench_function("decode_get_response", |b| {
        b.iter(|| {
            let data = encoded.clone();
            black_box(CommunityMessage::decode(data).unwrap())
        });
    });

    group.finish();
}

/// Benchmark concurrent operations (simulating real polling scenarios)
fn bench_concurrent(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    if !is_container_available(&rt) {
        return;
    }

    let mut group = c.benchmark_group("client_concurrent");
    group.sample_size(20);

    // Create multiple clients
    let clients: Vec<_> = rt.block_on(async {
        let mut clients = Vec::new();
        for _ in 0..10 {
            let client = Client::builder(TARGET, Auth::v2c(COMMUNITY))
                .timeout(Duration::from_secs(5))
                .connect()
                .await
                .expect("Failed to connect");
            clients.push(client);
        }
        clients
    });

    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0); // sysUpTime

    // Benchmark sequential requests
    group.bench_function("sequential_10_gets", |b| {
        b.to_async(&rt).iter(|| async {
            for client in &clients {
                black_box(client.get(&oid).await.unwrap());
            }
        });
    });

    // Benchmark concurrent requests
    group.bench_function("concurrent_10_gets", |b| {
        b.to_async(&rt).iter(|| async {
            let futures: Vec<_> = clients.iter().map(|client| client.get(&oid)).collect();
            let results: Vec<async_snmp::Result<async_snmp::varbind::VarBind>> =
                futures::future::join_all(futures).await;
            for result in results {
                black_box(result.unwrap());
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_get_single,
    bench_get_many,
    bench_get_next,
    bench_get_bulk,
    bench_walk,
    bench_client_construction,
    bench_request_overhead,
    bench_concurrent,
);

criterion_main!(benches);
