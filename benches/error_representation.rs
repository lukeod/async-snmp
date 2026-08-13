//! Size and construction-cost comparison for boxed and inline public errors.

use async_snmp::Error;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::mem::{size_of, size_of_val};
use std::net::{Ipv4Addr, SocketAddr};

type BoxedResult<T> = std::result::Result<T, Box<Error>>;
type InlineResult<T> = std::result::Result<T, Error>;

fn auth_error() -> Error {
    Error::Auth {
        target: SocketAddr::from((Ipv4Addr::LOCALHOST, 161)),
    }
}

async fn hold_boxed_error() -> BoxedResult<()> {
    let error = auth_error().boxed();
    tokio::task::yield_now().await;
    Err(error)
}

async fn hold_inline_error() -> InlineResult<()> {
    let error = auth_error();
    tokio::task::yield_now().await;
    Err(error)
}

fn bench_error_representation(c: &mut Criterion) {
    let boxed_future = hold_boxed_error();
    let inline_future = hold_inline_error();

    println!(
        "representation sizes (bytes): Error={}, BoxedResult<()>={}, InlineResult<()>={}, boxed future={}, inline future={}",
        size_of::<Error>(),
        size_of::<BoxedResult<()>>(),
        size_of::<InlineResult<()>>(),
        size_of_val(&boxed_future),
        size_of_val(&inline_future),
    );

    let mut group = c.benchmark_group("error_representation");
    group.bench_function("boxed_error_construction", |b| {
        b.iter(|| {
            let result: BoxedResult<()> = Err(black_box(auth_error()).boxed());
            black_box(result)
        });
    });
    group.bench_function("inline_error_construction", |b| {
        b.iter(|| {
            let result: InlineResult<()> = Err(black_box(auth_error()));
            black_box(result)
        });
    });
    group.bench_function("boxed_success_construction", |b| {
        b.iter(|| {
            let result: BoxedResult<()> = Ok(());
            black_box(result)
        });
    });
    group.bench_function("inline_success_construction", |b| {
        b.iter(|| {
            let result: InlineResult<()> = Ok(());
            black_box(result)
        });
    });
    group.finish();
}

criterion_group!(benches, bench_error_representation);
criterion_main!(benches);
