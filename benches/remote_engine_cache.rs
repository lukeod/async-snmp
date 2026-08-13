//! Remote authoritative-engine cache-operation benchmarks.
//!
//! These measurements are a lower bound on cache service time, not a model of
//! full notification receive throughput. They include the synchronous mutex,
//! lookup, authenticated-update timestamp maintenance, and eviction, but omit
//! socket I/O, BER/USM decoding, user/key lookup, HMAC verification, tracing,
//! and notification construction. Consequently no payload size or security
//! level is assumed. The 17-octet engine IDs are representative wire values;
//! excluding the rest of the receive path deliberately isolates the data
//! structure decision and must not be extrapolated as end-to-end throughput.
//!
//! Two independently evaluated acceptance criteria apply at the supported
//! 8,192-entry bound:
//!
//! - adversarial all-miss churn: indexed median service time at most 80% of
//!   the scan median (at least a 20% reduction);
//! - normal known-engine traffic: indexed median service time at most 110% of
//!   the scan median in the weighted profile below (at most a 10% regression).
//!
//! The normal profile represents one remote engine sending 1,000 authenticated
//! notifications per second while its integer `snmpEngineTime` advances once
//! per second: 999 non-advancing hits followed by one advancing hit. Production
//! eviction recency changes only on that authenticated high-water update, not
//! on every accepted packet. Steady-hit results are also reported separately
//! so that the common no-index-rewrite operation remains visible.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Mutex;
use std::time::Instant;

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

#[allow(dead_code, unused_imports)]
#[path = "../src/v3/recency_map.rs"]
mod recency_map;
use recency_map::RecencyMap;

const CAPACITIES: [usize; 3] = [256, 2_048, 8_192];
const NOTIFICATIONS_PER_ENGINE_TICK: u64 = 1_000;
const INITIAL_ENGINE_TIME: u64 = 10_000;

#[derive(Clone, Copy)]
struct BenchEngineState {
    engine_time: u64,
    updated_at: Instant,
}

impl BenchEngineState {
    fn new(engine_time: u64, updated_at: Instant) -> Self {
        Self {
            engine_time,
            updated_at,
        }
    }

    /// Mirror `EngineState`'s forward-only authenticated high-water update.
    fn observe(&mut self, engine_time: u64, observed_at: Instant) -> Instant {
        if engine_time > self.engine_time {
            self.engine_time = engine_time;
            self.updated_at = observed_at;
        }
        self.updated_at
    }
}

struct ScanTable {
    entries: Mutex<HashMap<Bytes, BenchEngineState>>,
    capacity: usize,
}

struct IndexedTable {
    entries: Mutex<RecencyMap<Bytes, BenchEngineState>>,
}

impl ScanTable {
    fn full(capacity: usize) -> Self {
        let now = Instant::now();
        let entries = (0..capacity)
            .map(|index| {
                (
                    engine_id(index),
                    BenchEngineState::new(INITIAL_ENGINE_TIME, now),
                )
            })
            .collect();
        Self {
            entries: Mutex::new(entries),
            capacity,
        }
    }

    fn accept(&self, engine_id: Bytes, engine_time: u64) {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        if let Some(state) = entries.get_mut(&engine_id) {
            state.observe(engine_time, now);
            return;
        }
        if entries.len() >= self.capacity
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, state)| state.updated_at)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(engine_id, BenchEngineState::new(engine_time, now));
    }
}

impl IndexedTable {
    fn full(capacity: usize) -> Self {
        let now = Instant::now();
        let mut entries = RecencyMap::new(capacity);
        for index in 0..capacity {
            entries.insert(
                engine_id(index),
                BenchEngineState::new(INITIAL_ENGINE_TIME, now),
                now,
            );
        }
        Self {
            entries: Mutex::new(entries),
        }
    }

    fn accept(&self, engine_id: Bytes, engine_time: u64) {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        if entries
            .update(&engine_id, |state| {
                let updated_at = state.observe(engine_time, now);
                ((), updated_at)
            })
            .is_none()
        {
            entries.insert(engine_id, BenchEngineState::new(engine_time, now), now);
        }
    }
}

fn engine_id(index: usize) -> Bytes {
    let mut id = [0_u8; 17];
    id[0] = 0x80;
    id[9..].copy_from_slice(&(index as u64).to_be_bytes());
    Bytes::copy_from_slice(&id)
}

fn bench_remote_engine_cache(c: &mut Criterion) {
    let mut group = c.benchmark_group("remote_engine_cache_operations");
    group.throughput(Throughput::Elements(1));

    for capacity in CAPACITIES {
        let known = engine_id(capacity / 2);
        let scan = ScanTable::full(capacity);
        group.bench_with_input(
            BenchmarkId::new("scan_steady_hit", capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    scan.accept(black_box(known.clone()), black_box(INITIAL_ENGINE_TIME));
                });
            },
        );

        let indexed = IndexedTable::full(capacity);
        group.bench_with_input(
            BenchmarkId::new("indexed_steady_hit", capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    indexed.accept(black_box(known.clone()), black_box(INITIAL_ENGINE_TIME));
                });
            },
        );

        let scan = ScanTable::full(capacity);
        let mut sequence = 0_u64;
        group.bench_with_input(
            BenchmarkId::new("scan_hit_1_in_1000_advance", capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    let engine_time =
                        INITIAL_ENGINE_TIME + sequence / NOTIFICATIONS_PER_ENGINE_TICK;
                    scan.accept(black_box(known.clone()), black_box(engine_time));
                    sequence = sequence.wrapping_add(1);
                });
            },
        );

        let indexed = IndexedTable::full(capacity);
        let mut sequence = 0_u64;
        group.bench_with_input(
            BenchmarkId::new("indexed_hit_1_in_1000_advance", capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    let engine_time =
                        INITIAL_ENGINE_TIME + sequence / NOTIFICATIONS_PER_ENGINE_TICK;
                    indexed.accept(black_box(known.clone()), black_box(engine_time));
                    sequence = sequence.wrapping_add(1);
                });
            },
        );

        let scan = ScanTable::full(capacity);
        let mut next = capacity;
        group.bench_with_input(
            BenchmarkId::new("scan_churn", capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    scan.accept(black_box(engine_id(next)), black_box(INITIAL_ENGINE_TIME));
                    next = next.wrapping_add(1);
                });
            },
        );

        let indexed = IndexedTable::full(capacity);
        let mut next = capacity;
        group.bench_with_input(
            BenchmarkId::new("indexed_churn", capacity),
            &capacity,
            |b, _| {
                b.iter(|| {
                    indexed.accept(black_box(engine_id(next)), black_box(INITIAL_ENGINE_TIME));
                    next = next.wrapping_add(1);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_remote_engine_cache);
criterion_main!(benches);
