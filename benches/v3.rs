//! SNMPv3 security benchmarks.
//!
//! Tests the performance of V3 crypto operations which are on the hot path
//! for all SNMPv3 communications.

use async_snmp::v3::{AuthProtocol, LocalizedKey, PrivKey, PrivProtocol};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const ENGINE_ID: &[u8] = b"\x80\x00\x1f\x88\x80\xe9\xb1\x04\x61\x73\x61\x00\x00\x00";
const PASSWORD: &[u8] = b"maplesyrup";

/// Benchmark key derivation (password to localized key).
///
/// This is the slow path - 1MB expansion + hash + localization.
/// Only done once per engine, cached thereafter.
fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_key_derivation");
    // Key derivation is slow, reduce sample size
    group.sample_size(10);

    let mut protocols: Vec<(&str, AuthProtocol)> = Vec::new();
    #[cfg(feature = "crypto-rustcrypto")]
    protocols.push(("MD5", AuthProtocol::Md5));
    protocols.push(("SHA-1", AuthProtocol::Sha1));
    protocols.push(("SHA-256", AuthProtocol::Sha256));

    for (name, protocol) in protocols {
        group.bench_function(BenchmarkId::new("from_password", name), |b| {
            b.iter(|| black_box(LocalizedKey::from_password(protocol, PASSWORD, ENGINE_ID)))
        });
    }

    group.finish();
}

/// Benchmark HMAC computation for authentication.
///
/// This is on the hot path for every authenticated message.
fn bench_hmac(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_hmac");

    // Typical SNMP message sizes
    let message_sizes = [64, 128, 256, 512, 1024];

    let mut protocols: Vec<(&str, AuthProtocol)> = Vec::new();
    #[cfg(feature = "crypto-rustcrypto")]
    protocols.push(("MD5", AuthProtocol::Md5));
    protocols.push(("SHA-1", AuthProtocol::Sha1));
    protocols.push(("SHA-256", AuthProtocol::Sha256));
    protocols.push(("SHA-512", AuthProtocol::Sha512));

    // Pre-derive keys (don't include derivation in HMAC benchmark)
    let keys: Vec<_> = protocols
        .iter()
        .map(|(_, p)| LocalizedKey::from_password(*p, PASSWORD, ENGINE_ID))
        .collect();

    for (i, (name, _)) in protocols.iter().enumerate() {
        let key = &keys[i];

        for size in message_sizes {
            let data = vec![0xABu8; size];

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(
                BenchmarkId::new(format!("compute_{}", name), size),
                &data,
                |b, data| b.iter(|| black_box(key.compute_hmac(data))),
            );
        }
    }

    // Benchmark verify (compute + compare)
    let key_sha256 = LocalizedKey::from_password(AuthProtocol::Sha256, PASSWORD, ENGINE_ID);
    let data = vec![0xABu8; 256];
    let mac = key_sha256.compute_hmac(&data);

    group.bench_function("verify_SHA-256_256bytes", |b| {
        b.iter(|| black_box(key_sha256.verify_hmac(&data, &mac)))
    });

    group.finish();
}

/// Benchmark encryption operations.
fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_encrypt");

    // Typical ScopedPDU sizes
    let data_sizes = [64, 128, 256, 512];

    // Create keys for each privacy protocol
    #[cfg(feature = "crypto-rustcrypto")]
    let des_key = PrivKey::from_bytes(
        PrivProtocol::Des,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ],
    );

    let aes128_key = PrivKey::from_bytes(
        PrivProtocol::Aes128,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
    );

    let aes256_key = PrivKey::from_bytes(
        PrivProtocol::Aes256,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ],
    );

    let engine_boots = 100u32;
    let engine_time = 12345u32;

    for size in data_sizes {
        let data = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64));

        // DES
        #[cfg(feature = "crypto-rustcrypto")]
        {
            let key = des_key.clone();
            group.bench_with_input(BenchmarkId::new("DES", size), &data, |b, data| {
                b.iter(|| black_box(key.encrypt(data, engine_boots, engine_time, None).unwrap()))
            });
        }

        // AES-128
        let key = aes128_key.clone();
        group.bench_with_input(BenchmarkId::new("AES-128", size), &data, |b, data| {
            b.iter(|| black_box(key.encrypt(data, engine_boots, engine_time, None).unwrap()))
        });

        // AES-256
        let key = aes256_key.clone();
        group.bench_with_input(BenchmarkId::new("AES-256", size), &data, |b, data| {
            b.iter(|| black_box(key.encrypt(data, engine_boots, engine_time, None).unwrap()))
        });
    }

    group.finish();
}

/// Benchmark decryption operations.
fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_decrypt");

    let data_sizes = [64, 128, 256, 512];

    #[cfg(feature = "crypto-rustcrypto")]
    let des_key = PrivKey::from_bytes(
        PrivProtocol::Des,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18,
        ],
    );

    let aes128_key = PrivKey::from_bytes(
        PrivProtocol::Aes128,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
    );

    let aes256_key = PrivKey::from_bytes(
        PrivProtocol::Aes256,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ],
    );

    let engine_boots = 100u32;
    let engine_time = 12345u32;

    for size in data_sizes {
        let plaintext = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64));

        // DES
        #[cfg(feature = "crypto-rustcrypto")]
        {
            let (ciphertext, priv_params) = des_key
                .encrypt(&plaintext, engine_boots, engine_time, None)
                .unwrap();
            group.bench_with_input(
                BenchmarkId::new("DES", size),
                &(&ciphertext, &priv_params),
                |b, (ct, pp)| {
                    b.iter(|| {
                        black_box(des_key.decrypt(ct, engine_boots, engine_time, pp).unwrap())
                    })
                },
            );
        }

        // AES-128
        let (ciphertext, priv_params) = aes128_key
            .encrypt(&plaintext, engine_boots, engine_time, None)
            .unwrap();
        group.bench_with_input(
            BenchmarkId::new("AES-128", size),
            &(&ciphertext, &priv_params),
            |b, (ct, pp)| {
                b.iter(|| {
                    black_box(
                        aes128_key
                            .decrypt(ct, engine_boots, engine_time, pp)
                            .unwrap(),
                    )
                })
            },
        );

        // AES-256
        let (ciphertext, priv_params) = aes256_key
            .encrypt(&plaintext, engine_boots, engine_time, None)
            .unwrap();
        group.bench_with_input(
            BenchmarkId::new("AES-256", size),
            &(&ciphertext, &priv_params),
            |b, (ct, pp)| {
                b.iter(|| {
                    black_box(
                        aes256_key
                            .decrypt(ct, engine_boots, engine_time, pp)
                            .unwrap(),
                    )
                })
            },
        );
    }

    group.finish();
}

/// Benchmark combined auth+priv overhead (typical authPriv message processing).
fn bench_authpriv_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("v3_authpriv");

    // Pre-derive keys
    let auth_key = LocalizedKey::from_password(AuthProtocol::Sha256, PASSWORD, ENGINE_ID);
    let priv_key = PrivKey::from_bytes(
        PrivProtocol::Aes128,
        vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ],
    );

    let engine_boots = 100u32;
    let engine_time = 12345u32;

    // Typical SNMP message (256 bytes total, ~200 bytes ScopedPDU)
    let scoped_pdu = vec![0xABu8; 200];
    let full_message = vec![0xCDu8; 256];

    group.throughput(Throughput::Bytes(256));

    // Outgoing: encrypt ScopedPDU, then HMAC entire message
    group.bench_function("outgoing_encrypt_then_auth", |b| {
        b.iter(|| {
            let (encrypted, _priv_params) = priv_key
                .encrypt(&scoped_pdu, engine_boots, engine_time, None)
                .unwrap();
            let _hmac = auth_key.compute_hmac(&full_message);
            black_box(encrypted)
        })
    });

    // Incoming: verify HMAC, then decrypt
    let (ciphertext, priv_params) = priv_key
        .encrypt(&scoped_pdu, engine_boots, engine_time, None)
        .unwrap();
    let hmac = auth_key.compute_hmac(&full_message);

    group.bench_function("incoming_verify_then_decrypt", |b| {
        b.iter(|| {
            let valid = auth_key.verify_hmac(&full_message, &hmac);
            assert!(valid);
            let decrypted = priv_key
                .decrypt(&ciphertext, engine_boots, engine_time, &priv_params)
                .unwrap();
            black_box(decrypted)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_hmac,
    bench_encrypt,
    bench_decrypt,
    bench_authpriv_overhead,
);

criterion_main!(benches);
