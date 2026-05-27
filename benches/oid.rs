//! OID benchmarks focused on `SmallVec` optimization evaluation.
//!
//! The Oid type uses `SmallVec<[u32; 16]>` to avoid heap allocation for
//! OIDs with 16 or fewer arcs. This benchmark suite evaluates whether
//! this optimization provides meaningful value.

use async_snmp::oid::Oid;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// Generate OIDs of various lengths for benchmarking
fn generate_oid(len: usize) -> Oid {
    // Start with a valid prefix and extend
    let mut arcs = vec![1u32, 3, 6, 1, 4, 1];
    for i in 0..(len.saturating_sub(6)) {
        arcs.push((i & 0xFF) as u32);
    }
    Oid::new(arcs)
}

/// Benchmark OID creation from slice (`SmallVec` allocation test)
fn bench_oid_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_creation");

    // Test lengths below, at, and above the SmallVec threshold of 16
    let lengths = [4u16, 8, 12, 16, 20, 24, 32, 64];

    for len in lengths {
        let arcs: Vec<u32> = (0..len)
            .map(|i| if i == 0 { 1 } else { i.into() })
            .collect();

        group.bench_with_input(BenchmarkId::new("from_slice", len), &arcs, |b, arcs| {
            b.iter(|| black_box(Oid::from_slice(arcs)));
        });
    }

    group.finish();
}

/// Benchmark OID cloning (measures `SmallVec` clone cost)
fn bench_oid_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_clone");

    // Test lengths below, at, and above the SmallVec threshold
    for len in [4, 8, 12, 16, 20, 24, 32] {
        let oid = generate_oid(len);

        group.bench_with_input(BenchmarkId::new("clone", len), &oid, |b, oid| {
            b.iter(|| black_box(oid.clone()));
        });
    }

    group.finish();
}

/// Benchmark OID child creation (appending an arc)
fn bench_oid_child(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_child");

    // Test child creation at different base lengths
    for len in [4, 8, 15, 16, 20, 31, 32] {
        let oid = generate_oid(len);

        group.bench_with_input(BenchmarkId::new("child", len), &oid, |b, oid| {
            b.iter(|| black_box(oid.child(42)));
        });
    }

    group.finish();
}

/// Benchmark OID parent creation
fn bench_oid_parent(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_parent");

    for len in [4, 8, 16, 17, 24, 32] {
        let oid = generate_oid(len);

        group.bench_with_input(BenchmarkId::new("parent", len), &oid, |b, oid| {
            b.iter(|| black_box(oid.parent()));
        });
    }

    group.finish();
}

/// Benchmark OID comparison operations
fn bench_oid_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_comparison");

    // Test starts_with which is common in walk operations
    for len in [8, 16, 24, 32] {
        let oid = generate_oid(len);
        let prefix = generate_oid(6); // Common prefix length

        group.bench_with_input(
            BenchmarkId::new("starts_with", len),
            &(oid.clone(), prefix.clone()),
            |b, (oid, prefix)| b.iter(|| black_box(oid.starts_with(prefix))),
        );
    }

    // Test equality comparison
    for len in [8, 16, 24, 32] {
        let oid1 = generate_oid(len);
        let oid2 = oid1.clone();

        group.bench_with_input(
            BenchmarkId::new("eq", len),
            &(oid1, oid2),
            |b, (oid1, oid2)| b.iter(|| black_box(oid1 == oid2)),
        );
    }

    // Test ordering comparison
    for len in [8, 16, 24, 32] {
        let oid1 = generate_oid(len);
        let mut oid2 = oid1.clone();
        // Make oid2 slightly different for ordering test
        if let Some(last) = oid2.arcs().last().copied() {
            let arcs: Vec<u32> = oid2
                .arcs()
                .iter()
                .take(len - 1)
                .copied()
                .chain(std::iter::once(last + 1))
                .collect();
            oid2 = Oid::new(arcs);
        }

        group.bench_with_input(
            BenchmarkId::new("cmp", len),
            &(oid1, oid2),
            |b, (oid1, oid2)| b.iter(|| black_box(oid1.cmp(oid2))),
        );
    }

    group.finish();
}

/// Benchmark OID BER encoding at different lengths
fn bench_oid_ber_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_ber_encode");

    for len in [4, 8, 16, 24, 32, 64] {
        let oid = generate_oid(len);

        group.bench_with_input(BenchmarkId::new("to_ber", len), &oid, |b, oid| {
            b.iter(|| black_box(oid.to_ber()));
        });
    }

    group.finish();
}

/// Benchmark OID BER decoding at different lengths
fn bench_oid_ber_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_ber_decode");

    for len in [4, 8, 16, 24, 32, 64] {
        let oid = generate_oid(len);
        let encoded = oid.to_ber();

        group.bench_with_input(BenchmarkId::new("from_ber", len), &encoded, |b, data| {
            b.iter(|| black_box(Oid::from_ber(data).unwrap()));
        });
    }

    group.finish();
}

/// Benchmark OID string parsing at different lengths
fn bench_oid_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_string_parse");

    for len in [4, 8, 16, 24, 32] {
        let oid = generate_oid(len);
        let oid_str = oid.to_string();

        group.bench_with_input(BenchmarkId::new("parse", len), &oid_str, |b, s| {
            b.iter(|| black_box(Oid::parse(s).unwrap()));
        });
    }

    group.finish();
}

/// Benchmark OID Display formatting
fn bench_oid_display(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_display");

    for len in [4, 8, 16, 24, 32] {
        let oid = generate_oid(len);

        group.bench_with_input(BenchmarkId::new("to_string", len), &oid, |b, oid| {
            b.iter(|| black_box(oid.to_string()));
        });
    }

    group.finish();
}

/// Benchmark common SNMP OID operations (real-world patterns)
fn bench_real_world_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_real_world");

    // Common SNMP OIDs
    let _sys_descr = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    let if_table = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1]);
    let if_index = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1]);

    // Walk iteration pattern: check if OID is within subtree
    group.bench_function("walk_check_subtree", |b| {
        let current = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 42]);
        b.iter(|| black_box(current.starts_with(&if_table)));
    });

    // GETBULK response processing: decode multiple OIDs
    let encoded_oids: Vec<Vec<u8>> = (0..25)
        .map(|i| Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, i]).to_ber())
        .collect();

    group.bench_function("bulk_decode_25_oids", |b| {
        b.iter(|| {
            for encoded in &encoded_oids {
                black_box(Oid::from_ber(encoded).unwrap());
            }
        });
    });

    // Table index extraction pattern
    group.bench_function("extract_table_index", |b| {
        let entry = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 42]);
        b.iter(|| {
            // Check if in table, then extract index
            if entry.starts_with(&if_index) {
                black_box(entry.arcs().last())
            } else {
                None
            }
        });
    });

    // Hash map lookup simulation (common for caching)
    use std::collections::HashMap;
    let mut oid_map: HashMap<Oid, i32> = HashMap::new();
    for i in 0u16..100 {
        let oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, i.into()]);
        oid_map.insert(oid, i.into());
    }
    let lookup_oid = Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 50]);

    group.bench_function("hashmap_lookup", |b| {
        b.iter(|| black_box(oid_map.get(&lookup_oid)));
    });

    // OID sorting (used in walk result ordering)
    let oids: Vec<Oid> = (0..100)
        .map(|i| Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, (i % 10) + 1, i]))
        .collect();

    group.bench_function("sort_100_oids", |b| {
        b.iter_batched(
            || oids.clone(),
            |mut oids| {
                oids.sort();
                black_box(oids)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Specific test for `SmallVec` threshold behavior
fn bench_smallvec_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("smallvec_threshold");

    // Test exactly at threshold boundaries
    let oid_15 = generate_oid(15); // Below threshold
    let oid_16 = generate_oid(16); // At threshold
    let oid_17 = generate_oid(17); // Above threshold (spills to heap)

    // Clone at boundaries
    group.bench_function("clone_15_arcs", |b| b.iter(|| black_box(oid_15.clone())));

    group.bench_function("clone_16_arcs", |b| b.iter(|| black_box(oid_16.clone())));

    group.bench_function("clone_17_arcs", |b| b.iter(|| black_box(oid_17.clone())));

    // Child at boundaries (tests grow behavior)
    let oid_15_base = generate_oid(15);
    let oid_16_base = generate_oid(16);

    group.bench_function("child_15_to_16_arcs", |b| {
        b.iter(|| black_box(oid_15_base.child(42)));
    });

    group.bench_function("child_16_to_17_arcs", |b| {
        b.iter(|| black_box(oid_16_base.child(42)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_oid_creation,
    bench_oid_clone,
    bench_oid_child,
    bench_oid_parent,
    bench_oid_comparison,
    bench_oid_ber_encode,
    bench_oid_ber_decode,
    bench_oid_parse,
    bench_oid_display,
    bench_real_world_patterns,
    bench_smallvec_threshold,
);

criterion_main!(benches);
