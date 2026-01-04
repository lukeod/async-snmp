//! Transport comparison benchmark: per-client vs shared UdpTransport
//!
//! This benchmark compares performance characteristics between two usage patterns:
//! - Per-client: Each client creates its own UdpTransport via `.connect()`
//! - Shared: Multiple clients share a single UdpTransport via handles
//!
//! Metrics measured:
//! - Throughput (requests/sec)
//! - Latency distribution (p50, p95, p99)
//! - File descriptor usage
//! - Memory overhead (RSS delta)
//!
//! Prerequisites:
//!   docker build -t async-snmp-test:latest tests/containers/snmpd/
//!
//! Run with:
//!   cargo bench --bench transport_comparison

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_snmp::{Auth, Client, Retry, UdpHandle, UdpTransport, oid};
use futures::future::join_all;
use hdrhistogram::Histogram;
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};
use tokio::runtime::Runtime;
use tokio::sync::Barrier;

const COMMUNITY: &str = "public";
const WARMUP_REQUESTS: usize = 10;

fn benchmark_duration_secs() -> u64 {
    std::env::var("BENCH_DURATION")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

fn main() {
    let rt = Runtime::new().expect("Failed to create runtime");

    println!("Transport Comparison Benchmark");
    println!("==============================\n");

    // Check Docker availability
    if !is_docker_available() {
        eprintln!("Docker not available. Skipping benchmark.");
        return;
    }

    // Check image exists
    if !image_exists("async-snmp-test:latest") {
        eprintln!("Container image 'async-snmp-test:latest' not found.");
        eprintln!("Build with: docker build -t async-snmp-test:latest tests/containers/snmpd/");
        return;
    }

    // Test configurations: (num_containers, concurrent_requests_per_container)
    let configs = [
        (1, 1),  // Baseline: single target, single request
        (1, 10), // Single target, concurrent requests
        (5, 1),  // Multiple targets, sequential per target
        (5, 5),  // Multiple targets, concurrent per target
        (10, 1), // Scale test: 10 targets
        (10, 5), // Scale test: 10 targets, concurrent
        (20, 1), // Scale test: 20 targets
        (20, 5), // Scale test: 20 targets, concurrent
    ];

    for (num_containers, concurrency) in configs {
        println!(
            "\n--- {} containers, {} concurrent requests each ---\n",
            num_containers, concurrency
        );

        rt.block_on(async {
            run_comparison(num_containers, concurrency).await;
        });
    }

    println!("\nBenchmark complete.");
}

async fn run_comparison(num_containers: usize, concurrency_per_target: usize) {
    // Spawn containers
    println!("Spawning {} containers...", num_containers);
    let containers = spawn_containers(num_containers).await;
    let targets: Vec<SocketAddr> = containers.iter().map(|(_, addr)| *addr).collect();

    println!("Containers ready. Targets: {:?}", targets);

    // Get baseline FD count
    let baseline_fds = count_fds();

    // Warmup and benchmark per-client transport
    println!("\n[Per-Client Transport (implicit UdpTransport per client)]");
    let non_shared_result = benchmark_non_shared(&targets, concurrency_per_target).await;

    let non_shared_fds = count_fds();
    println!(
        "  FDs during test: {} (baseline: {})",
        non_shared_fds, baseline_fds
    );

    // Drop clients, wait a moment for cleanup
    drop(non_shared_result.clients);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let after_non_shared_fds = count_fds();
    println!("  FDs after cleanup: {}", after_non_shared_fds);

    // Warmup and benchmark shared transport
    println!("\n[Shared Transport (explicit UdpTransport with handles)]");
    let shared_result = benchmark_shared(&targets, concurrency_per_target).await;

    let shared_fds = count_fds();
    println!(
        "  FDs during test: {} (baseline: {})",
        shared_fds, baseline_fds
    );

    // Print comparison
    println!("\n[Comparison]");
    print_comparison(&non_shared_result.stats, &shared_result.stats);

    println!("\n  FD Usage:");
    println!(
        "    Per-client: {} FDs ({} per target)",
        non_shared_fds - baseline_fds,
        (non_shared_fds - baseline_fds) / targets.len().max(1)
    );
    println!(
        "    Shared:     {} FDs (1 socket for all targets)",
        shared_fds - baseline_fds
    );

    // Keep containers alive until end of comparison
    drop(containers);
}

struct BenchmarkResult<C> {
    stats: BenchmarkStats,
    #[allow(dead_code)]
    clients: Vec<C>,
}

#[derive(Clone)]
struct BenchmarkStats {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    duration_secs: f64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    min_us: u64,
    max_us: u64,
}

impl BenchmarkStats {
    fn requests_per_sec(&self) -> f64 {
        self.successful_requests as f64 / self.duration_secs
    }
}

async fn benchmark_non_shared(
    targets: &[SocketAddr],
    concurrency: usize,
) -> BenchmarkResult<Client> {
    // Create one client per target (each creates its own UdpTransport via .connect())
    let mut clients = Vec::with_capacity(targets.len());
    for target in targets {
        let client = Client::builder(target.to_string(), Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .retry(Retry::fixed(1, Duration::ZERO))
            .connect()
            .await
            .expect("Failed to connect");
        clients.push(client);
    }

    // Warmup
    for client in &clients {
        for _ in 0..WARMUP_REQUESTS {
            let _ = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await;
        }
    }

    let stats = run_benchmark(&clients, concurrency).await;

    print_stats(&stats);

    BenchmarkResult { stats, clients }
}

async fn benchmark_shared(
    targets: &[SocketAddr],
    concurrency: usize,
) -> BenchmarkResult<Client<UdpHandle>> {
    // Create shared transport
    let shared = UdpTransport::builder()
        .bind("0.0.0.0:0")
        .build()
        .await
        .expect("Failed to bind shared transport");

    // Create clients using shared transport
    let mut clients = Vec::with_capacity(targets.len());
    for target in targets {
        let client = Client::builder(target.to_string(), Auth::v2c(COMMUNITY))
            .timeout(Duration::from_secs(5))
            .retry(Retry::fixed(1, Duration::ZERO))
            .build_with(&shared)
            .expect("Failed to build client");
        clients.push(client);
    }

    // Warmup
    for client in &clients {
        for _ in 0..WARMUP_REQUESTS {
            let _ = client.get(&oid!(1, 3, 6, 1, 2, 1, 1, 3, 0)).await;
        }
    }

    let stats = run_benchmark(&clients, concurrency).await;

    print_stats(&stats);

    BenchmarkResult { stats, clients }
}

fn print_stats(stats: &BenchmarkStats) {
    println!("  Throughput: {:.0} req/s", stats.requests_per_sec());
    println!(
        "  Latency: p50={:.2}ms p95={:.2}ms p99={:.2}ms min={:.2}ms max={:.2}ms",
        stats.p50_us as f64 / 1000.0,
        stats.p95_us as f64 / 1000.0,
        stats.p99_us as f64 / 1000.0,
        stats.min_us as f64 / 1000.0,
        stats.max_us as f64 / 1000.0
    );
    println!(
        "  Requests: {} total, {} ok, {} failed ({:.1}% success)",
        stats.total_requests,
        stats.successful_requests,
        stats.failed_requests,
        100.0 * stats.successful_requests as f64 / stats.total_requests.max(1) as f64
    );
}

async fn run_benchmark<T: async_snmp::Transport + 'static>(
    clients: &[Client<T>],
    concurrency_per_client: usize,
) -> BenchmarkStats {
    let histogram = Arc::new(tokio::sync::Mutex::new(
        Histogram::<u64>::new(3).expect("Failed to create histogram"),
    ));
    let success_count = Arc::new(AtomicU64::new(0));
    let fail_count = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(AtomicBool::new(false));

    let total_workers = clients.len() * concurrency_per_client;
    let barrier = Arc::new(Barrier::new(total_workers));

    let oid = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0); // sysUpTime

    let start = Instant::now();

    // Spawn worker tasks
    let mut handles = Vec::with_capacity(total_workers);

    for client in clients {
        for _ in 0..concurrency_per_client {
            let client = client.clone();
            let oid = oid.clone();
            let histogram = Arc::clone(&histogram);
            let success_count = Arc::clone(&success_count);
            let fail_count = Arc::clone(&fail_count);
            let stop_flag = Arc::clone(&stop_flag);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                // Sync all workers to start together
                barrier.wait().await;

                loop {
                    // Check if we should stop
                    if stop_flag.load(Ordering::Relaxed) {
                        break;
                    }

                    let req_start = Instant::now();
                    let result = client.get(&oid).await;
                    let elapsed = req_start.elapsed();

                    match result {
                        Ok(_) => {
                            success_count.fetch_add(1, Ordering::Relaxed);
                            let us = elapsed.as_micros() as u64;
                            // Clamp to histogram range
                            let us = us.min(60_000_000); // 60 seconds max
                            histogram.lock().await.record(us).ok();
                        }
                        Err(_) => {
                            fail_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    // Small yield to prevent tight loop
                    tokio::task::yield_now().await;
                }
            }));
        }
    }

    // Run for specified duration
    tokio::time::sleep(Duration::from_secs(benchmark_duration_secs())).await;
    stop_flag.store(true, Ordering::Relaxed);

    // Wait for all workers to finish
    for handle in handles {
        let _ = handle.await;
    }

    let duration = start.elapsed();
    let hist = histogram.lock().await;

    BenchmarkStats {
        total_requests: success_count.load(Ordering::Relaxed) + fail_count.load(Ordering::Relaxed),
        successful_requests: success_count.load(Ordering::Relaxed),
        failed_requests: fail_count.load(Ordering::Relaxed),
        duration_secs: duration.as_secs_f64(),
        p50_us: hist.value_at_percentile(50.0),
        p95_us: hist.value_at_percentile(95.0),
        p99_us: hist.value_at_percentile(99.0),
        min_us: hist.min(),
        max_us: hist.max(),
    }
}

fn print_comparison(per_client: &BenchmarkStats, shared: &BenchmarkStats) {
    let throughput_ratio = shared.requests_per_sec() / per_client.requests_per_sec().max(0.001);
    let p50_ratio = per_client.p50_us as f64 / shared.p50_us.max(1) as f64;
    let p99_ratio = per_client.p99_us as f64 / shared.p99_us.max(1) as f64;

    println!(
        "  Throughput: shared is {:.2}x vs per-client",
        throughput_ratio
    );
    println!(
        "  p50 Latency: shared is {:.2}x {} than per-client",
        if p50_ratio > 1.0 {
            p50_ratio
        } else {
            1.0 / p50_ratio
        },
        if p50_ratio > 1.0 { "faster" } else { "slower" }
    );
    println!(
        "  p99 Latency: shared is {:.2}x {} than per-client",
        if p99_ratio > 1.0 {
            p99_ratio
        } else {
            1.0 / p99_ratio
        },
        if p99_ratio > 1.0 { "faster" } else { "slower" }
    );
}

async fn spawn_containers(count: usize) -> Vec<(ContainerAsync<GenericImage>, SocketAddr)> {
    let futures: Vec<_> = (0..count).map(|_| spawn_container()).collect();
    join_all(futures).await
}

async fn spawn_container() -> (ContainerAsync<GenericImage>, SocketAddr) {
    let container = GenericImage::new("async-snmp-test", "latest")
        .with_exposed_port(161.udp())
        .with_wait_for(WaitFor::seconds(1))
        .start()
        .await
        .expect("Failed to start container");

    let port = container
        .get_host_port_ipv4(161.udp())
        .await
        .expect("Failed to get port");

    // Use 127.0.0.1 directly since testcontainers maps to localhost
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .expect("Failed to parse address");

    (container, addr)
}

fn is_docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn image_exists(image: &str) -> bool {
    std::process::Command::new("docker")
        .args(["image", "inspect", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn count_fds() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.count())
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0 // FD counting not supported on this platform
    }
}
