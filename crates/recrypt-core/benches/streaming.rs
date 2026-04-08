//! Streaming encrypt/decrypt benchmarks for `HybridEncryptor`.
//!
//! # Design targets (from design doc §6.3)
//!
//! | Scenario                                      | Target                          |
//! |-----------------------------------------------|---------------------------------|
//! | `encrypt_streaming` of 1 GiB plaintext        | ≤ 2× XChaCha20-only baseline    |
//! | `decrypt_streaming` of 1 GiB                  | ≤ 2× XChaCha20-only baseline    |
//! | `decrypt_range` 100 MiB window / 10 GiB file  | DEFERRED — see below            |
//! | Outboard fetch for 10 GiB file                | DEFERRED — storage-layer bench  |
//! | Proxy CPU + bandwidth flat across file size    | DEFERRED — server-side bench    |
//!
//! # CI-friendly substitutes
//!
//! 1 GiB workloads make CI multi-minute (especially under `spawn_blocking`
//! for bao-tree). This file uses **1 MiB** and **16 MiB** payloads, which
//! are enough to detect regressions without blowing CI budgets.
//! The 1 GiB target remains a documented goal; run it manually with
//! `cargo bench -p recrypt-core --bench streaming`.
//!
//! # Deferred items
//!
//! - **`decrypt_range` 100 MiB / 10 GiB**: impractical for CI; becomes
//!   meaningful only after chunked-streaming optimization (Group B follow-up)
//!   that avoids buffering the full ciphertext.
//! - **Outboard fetch latency** (`< 2 MiB transferred` for 10 GiB file):
//!   storage-layer concern; requires real or mock S3, not a crypto bench.
//! - **Proxy CPU flat across file size**: server-side bench, depends on real
//!   S3 integration; tracked as a separate deliverable.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use recrypt_core::pre::backends::MockBackend;
use recrypt_core::{HybridEncryptor, PreBackend};
use std::io::Cursor;
use tokio::runtime::Runtime;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build an `n`-byte pseudo-random buffer (xorshift64 — fast, non-zero output).
fn make_buf(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut state: u64 = 0xdeadbeef_cafebabe;
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        buf.push(state as u8);
    }
    buf
}

fn make_rt() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

// ---------------------------------------------------------------------------
// encrypt_streaming benchmarks
// ---------------------------------------------------------------------------

fn bench_encrypt_streaming_1mib(c: &mut Criterion) {
    let rt = make_rt();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let plaintext = make_buf(1024 * 1024); // 1 MiB

    c.bench_function("encrypt_streaming_1mib", |b| {
        b.to_async(&rt).iter(|| async {
            let mut sink: Vec<u8> = Vec::with_capacity(plaintext.len());
            let result = encryptor
                .encrypt_streaming(
                    black_box(&kp.public),
                    Cursor::new(black_box(&plaintext)),
                    &mut sink,
                )
                .await
                .expect("encrypt_streaming_1mib failed");
            black_box(result.bao_hash);
        });
    });
}

fn bench_encrypt_streaming_16mib(c: &mut Criterion) {
    let rt = make_rt();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let plaintext = make_buf(16 * 1024 * 1024); // 16 MiB

    c.bench_function("encrypt_streaming_16mib", |b| {
        b.to_async(&rt).iter(|| async {
            let mut sink: Vec<u8> = Vec::with_capacity(plaintext.len());
            let result = encryptor
                .encrypt_streaming(
                    black_box(&kp.public),
                    Cursor::new(black_box(&plaintext)),
                    &mut sink,
                )
                .await
                .expect("encrypt_streaming_16mib failed");
            black_box(result.bao_hash);
        });
    });
}

// ---------------------------------------------------------------------------
// decrypt_streaming benchmarks
// ---------------------------------------------------------------------------

fn bench_decrypt_streaming_1mib(c: &mut Criterion) {
    let rt = make_rt();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let plaintext = make_buf(1024 * 1024);

    // Pre-encrypt once; bench only the decrypt path.
    let (ciphertext, wrapped_key, bao_hash, outboard) = rt.block_on(async {
        let mut ct = Vec::new();
        let r = encryptor
            .encrypt_streaming(&kp.public, Cursor::new(&plaintext), &mut ct)
            .await
            .expect("setup encrypt failed");
        (ct, r.wrapped_key, r.bao_hash, r.outboard)
    });

    c.bench_function("decrypt_streaming_1mib", |b| {
        b.to_async(&rt).iter(|| async {
            let mut out: Vec<u8> = Vec::with_capacity(ciphertext.len());
            encryptor
                .decrypt_streaming(
                    black_box(&kp.secret),
                    black_box(&wrapped_key),
                    black_box(&bao_hash),
                    Cursor::new(black_box(&ciphertext)),
                    Cursor::new(black_box(&outboard)),
                    &mut out,
                )
                .await
                .expect("decrypt_streaming_1mib failed");
            black_box(out.len());
        });
    });
}

fn bench_decrypt_streaming_16mib(c: &mut Criterion) {
    let rt = make_rt();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let kp = encryptor.backend().generate_keypair().unwrap();
    let plaintext = make_buf(16 * 1024 * 1024);

    let (ciphertext, wrapped_key, bao_hash, outboard) = rt.block_on(async {
        let mut ct = Vec::new();
        let r = encryptor
            .encrypt_streaming(&kp.public, Cursor::new(&plaintext), &mut ct)
            .await
            .expect("setup encrypt failed");
        (ct, r.wrapped_key, r.bao_hash, r.outboard)
    });

    c.bench_function("decrypt_streaming_16mib", |b| {
        b.to_async(&rt).iter(|| async {
            let mut out: Vec<u8> = Vec::with_capacity(ciphertext.len());
            encryptor
                .decrypt_streaming(
                    black_box(&kp.secret),
                    black_box(&wrapped_key),
                    black_box(&bao_hash),
                    Cursor::new(black_box(&ciphertext)),
                    Cursor::new(black_box(&outboard)),
                    &mut out,
                )
                .await
                .expect("decrypt_streaming_16mib failed");
            black_box(out.len());
        });
    });
}

// ---------------------------------------------------------------------------
// XChaCha20-only baselines (no bao-tree, no PRE wrapping)
//
// These establish the theoretical floor: what would throughput look like if
// we only ran the stream cipher? The ratio (streaming bench / baseline) is
// the overhead target — design goal ≤ 2×.
// ---------------------------------------------------------------------------

fn bench_xchacha20_only_1mib(c: &mut Criterion) {
    use chacha20::XChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let mut data = make_buf(1024 * 1024);

    c.bench_function("xchacha20_only_1mib", |b| {
        b.iter(|| {
            let mut cipher = XChaCha20::new(
                black_box(&key).into(),
                black_box(&nonce).into(),
            );
            cipher.apply_keystream(black_box(&mut data));
            black_box(data[0]);
        });
    });
}

fn bench_xchacha20_only_16mib(c: &mut Criterion) {
    use chacha20::XChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    let key = [0u8; 32];
    let nonce = [0u8; 24];
    let mut data = make_buf(16 * 1024 * 1024);

    c.bench_function("xchacha20_only_16mib", |b| {
        b.iter(|| {
            let mut cipher = XChaCha20::new(
                black_box(&key).into(),
                black_box(&nonce).into(),
            );
            cipher.apply_keystream(black_box(&mut data));
            black_box(data[0]);
        });
    });
}

// ---------------------------------------------------------------------------

criterion_group!(
    streaming_benches,
    bench_encrypt_streaming_1mib,
    bench_encrypt_streaming_16mib,
    bench_decrypt_streaming_1mib,
    bench_decrypt_streaming_16mib,
    bench_xchacha20_only_1mib,
    bench_xchacha20_only_16mib,
);
criterion_main!(streaming_benches);
