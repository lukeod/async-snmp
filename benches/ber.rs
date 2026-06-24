//! BER encoding/decoding benchmarks.
//!
//! Tests the performance of the core BER codec which is on the hot path
//! for all SNMP operations.

use async_snmp::ber::{Decoder, EncodeBuf};
use async_snmp::oid::Oid;
use async_snmp::value::Value;
use async_snmp::varbind::VarBind;
use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// Common OIDs used in benchmarks
fn common_oids() -> Vec<(&'static str, Oid)> {
    vec![
        ("sysDescr", Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0])),
        ("sysUpTime", Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0])),
        (
            "ifIndex",
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1]),
        ),
        (
            "long_oid",
            Oid::from_slice(&[1, 3, 6, 1, 4, 1, 9, 9, 42, 1, 2, 3, 4, 5, 6, 7]),
        ),
    ]
}

/// Benchmark OID BER encoding
fn bench_oid_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_encode");

    for (name, oid) in common_oids() {
        group.bench_with_input(BenchmarkId::new("to_ber", name), &oid, |b, oid| {
            b.iter(|| black_box(oid.to_ber()));
        });
    }

    group.finish();
}

/// Benchmark OID BER decoding
fn bench_oid_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_decode");

    for (name, oid) in common_oids() {
        let encoded = oid.to_ber();
        group.bench_with_input(BenchmarkId::new("from_ber", name), &encoded, |b, data| {
            b.iter(|| black_box(Oid::from_ber(data).unwrap()));
        });
    }

    group.finish();
}

/// Benchmark OID parsing from string
fn bench_oid_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("oid_parse");

    let oid_strings = [
        ("short", "1.3.6.1"),
        ("medium", "1.3.6.1.2.1.1.1.0"),
        ("long", "1.3.6.1.4.1.9.9.42.1.2.3.4.5.6.7.8.9.10"),
    ];

    for (name, s) in oid_strings {
        group.bench_with_input(BenchmarkId::new("parse", name), s, |b, s| {
            b.iter(|| black_box(Oid::parse(s).unwrap()));
        });
    }

    group.finish();
}

/// Benchmark Value encoding
fn bench_value_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_encode");

    let values: Vec<(&str, Value)> = vec![
        ("integer", Value::Integer(42)),
        ("integer_neg", Value::Integer(-12345)),
        ("counter32", Value::Counter32(1_000_000)),
        ("counter64", Value::Counter64(1_000_000_000_000)),
        ("gauge32", Value::Gauge32(999_999)),
        ("timeticks", Value::TimeTicks(123_456_789)),
        (
            "octet_string_short",
            Value::OctetString(Bytes::from_static(b"hello")),
        ),
        (
            "octet_string_medium",
            Value::OctetString(Bytes::from_static(
                b"Linux router 5.15.0-generic #123-Ubuntu SMP",
            )),
        ),
        (
            "octet_string_long",
            Value::OctetString(Bytes::from(vec![0u8; 256])),
        ),
        ("null", Value::Null),
        ("ip_address", Value::IpAddress([192, 168, 1, 1])),
        (
            "oid",
            Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0])),
        ),
        ("no_such_object", Value::NoSuchObject),
        ("end_of_mib_view", Value::EndOfMibView),
    ];

    for (name, value) in &values {
        group.bench_with_input(BenchmarkId::new("encode", name), value, |b, value| {
            b.iter(|| {
                let mut buf = EncodeBuf::new();
                value.encode(&mut buf);
                black_box(buf.finish())
            });
        });
    }

    group.finish();
}

/// Benchmark Value decoding
fn bench_value_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("value_decode");

    let values: Vec<(&str, Value)> = vec![
        ("integer", Value::Integer(42)),
        ("counter32", Value::Counter32(1_000_000)),
        ("counter64", Value::Counter64(1_000_000_000_000)),
        (
            "octet_string_short",
            Value::OctetString(Bytes::from_static(b"hello")),
        ),
        (
            "octet_string_medium",
            Value::OctetString(Bytes::from_static(
                b"Linux router 5.15.0-generic #123-Ubuntu SMP",
            )),
        ),
        ("null", Value::Null),
        ("ip_address", Value::IpAddress([192, 168, 1, 1])),
        (
            "oid",
            Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0])),
        ),
    ];

    for (name, value) in &values {
        let mut buf = EncodeBuf::new();
        value.encode(&mut buf);
        let encoded = buf.finish();

        group.bench_with_input(BenchmarkId::new("decode", name), &encoded, |b, data| {
            b.iter(|| {
                let mut decoder = Decoder::new(data.clone());
                black_box(Value::decode(&mut decoder).unwrap())
            });
        });
    }

    group.finish();
}

/// Benchmark `VarBind` encoding
fn bench_varbind_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("varbind_encode");

    let varbinds: Vec<(&str, VarBind)> = vec![
        (
            "integer",
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                Value::Integer(42),
            ),
        ),
        (
            "string",
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                Value::OctetString(Bytes::from_static(
                    b"Linux router 5.15.0-generic #123-Ubuntu SMP",
                )),
            ),
        ),
        (
            "counter64",
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1]),
                Value::Counter64(1_000_000_000_000),
            ),
        ),
    ];

    for (name, vb) in &varbinds {
        group.bench_with_input(BenchmarkId::new("encode", name), vb, |b, vb| {
            b.iter(|| {
                let mut buf = EncodeBuf::new();
                vb.encode(&mut buf);
                black_box(buf.finish())
            });
        });
    }

    group.finish();
}

/// Benchmark `VarBind` decoding
fn bench_varbind_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("varbind_decode");

    let varbinds: Vec<(&str, VarBind)> = vec![
        (
            "integer",
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
                Value::Integer(42),
            ),
        ),
        (
            "string",
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
                Value::OctetString(Bytes::from_static(
                    b"Linux router 5.15.0-generic #123-Ubuntu SMP",
                )),
            ),
        ),
        (
            "counter64",
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1]),
                Value::Counter64(1_000_000_000_000),
            ),
        ),
    ];

    for (name, vb) in &varbinds {
        let mut buf = EncodeBuf::new();
        vb.encode(&mut buf);
        let encoded = buf.finish();

        group.bench_with_input(BenchmarkId::new("decode", name), &encoded, |b, data| {
            b.iter(|| {
                let mut decoder = Decoder::new(data.clone());
                black_box(VarBind::decode(&mut decoder).unwrap())
            });
        });
    }

    group.finish();
}

/// Benchmark `EncodeBuf` operations
fn bench_encode_buf(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_buf");

    // Measure the overhead of buffer operations
    group.bench_function("new_default", |b| b.iter(|| black_box(EncodeBuf::new())));

    group.bench_function("new_with_capacity_512", |b| {
        b.iter(|| black_box(EncodeBuf::with_capacity(512)));
    });

    group.bench_function("new_with_capacity_1024", |b| {
        b.iter(|| black_box(EncodeBuf::with_capacity(1024)));
    });

    // Measure encoding a typical SNMP response (multiple varbinds)
    let varbinds: Vec<VarBind> = vec![
        VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            Value::OctetString(Bytes::from_static(b"Linux router")),
        ),
        VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            Value::TimeTicks(123_456_789),
        ),
        VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
            Value::OctetString(Bytes::from_static(b"router.example.com")),
        ),
    ];

    group.bench_function("encode_3_varbinds", |b| {
        b.iter(|| {
            let mut buf = EncodeBuf::new();
            for vb in &varbinds {
                vb.encode(&mut buf);
            }
            black_box(buf.finish())
        });
    });

    // Measure encoding 10 varbinds (typical GETBULK response)
    let many_varbinds: Vec<VarBind> = (0..10)
        .map(|i| {
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, i]),
                Value::OctetString(Bytes::from(format!("eth{i}"))),
            )
        })
        .collect();

    group.bench_function("encode_10_varbinds", |b| {
        b.iter(|| {
            let mut buf = EncodeBuf::new();
            for vb in &many_varbinds {
                vb.encode(&mut buf);
            }
            black_box(buf.finish())
        });
    });

    group.finish();
}

/// Benchmark integer encoding edge cases
fn bench_integer_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("integer_encode");

    let values = [
        ("zero", 0i32),
        ("small_pos", 42),
        ("small_neg", -42),
        ("boundary_127", 127),
        ("boundary_128", 128),
        ("boundary_neg128", -128),
        ("boundary_neg129", -129),
        ("max_i32", i32::MAX),
        ("min_i32", i32::MIN),
    ];

    for (name, value) in values {
        group.bench_with_input(BenchmarkId::new("encode", name), &value, |b, &v| {
            b.iter(|| {
                let mut buf = EncodeBuf::new();
                buf.push_integer(v);
                black_box(buf.finish())
            });
        });
    }

    group.finish();
}

/// Benchmark full message decode throughput
fn bench_message_decode_throughput(c: &mut Criterion) {
    use async_snmp::message::CommunityMessage;
    use async_snmp::pdu::Pdu;
    use async_snmp::version::Version;

    let mut group = c.benchmark_group("message_decode");

    // Create a typical GET response message
    let varbinds = vec![
        VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0]),
            Value::OctetString(Bytes::from_static(
                b"Linux router 5.15.0-generic #123-Ubuntu SMP",
            )),
        ),
        VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 3, 0]),
            Value::TimeTicks(123_456_789),
        ),
        VarBind::new(
            Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 5, 0]),
            Value::OctetString(Bytes::from_static(b"router.example.com")),
        ),
    ];

    // Create a GET request and convert to response
    let request = Pdu::get_request(12345, &[Oid::from_slice(&[1, 3, 6, 1, 2, 1, 1, 1, 0])]);
    let mut pdu = request.to_response();
    pdu.varbinds = varbinds;

    let msg = CommunityMessage::new(Version::V2c, Bytes::from_static(b"public"), pdu);
    let encoded = msg.encode();

    group.throughput(Throughput::Bytes(encoded.len() as u64));
    group.bench_function("v2c_response_3_varbinds", |b| {
        b.iter(|| {
            let data = encoded.clone();
            black_box(CommunityMessage::decode(data).unwrap())
        });
    });

    // Larger message (10 varbinds, simulating GETBULK)
    let many_varbinds: Vec<VarBind> = (0..10)
        .map(|i| {
            VarBind::new(
                Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2, i]),
                Value::OctetString(Bytes::from(format!("GigabitEthernet0/{i}"))),
            )
        })
        .collect();

    let request = Pdu::get_request(12346, &[Oid::from_slice(&[1, 3, 6, 1, 2, 1, 2, 2, 1, 2])]);
    let mut pdu = request.to_response();
    pdu.varbinds = many_varbinds;

    let msg = CommunityMessage::new(Version::V2c, Bytes::from_static(b"public"), pdu);
    let encoded_large = msg.encode();

    group.throughput(Throughput::Bytes(encoded_large.len() as u64));
    group.bench_function("v2c_response_10_varbinds", |b| {
        b.iter(|| {
            let data = encoded_large.clone();
            black_box(CommunityMessage::decode(data).unwrap())
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_oid_encode,
    bench_oid_decode,
    bench_oid_parse,
    bench_value_encode,
    bench_value_decode,
    bench_varbind_encode,
    bench_varbind_decode,
    bench_encode_buf,
    bench_integer_encode,
    bench_message_decode_throughput,
);

criterion_main!(benches);
