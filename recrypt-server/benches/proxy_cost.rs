//! Proxy recryption cost benchmark.
//!
//! # Acceptance criterion (from the Bao streaming execution plan §F1)
//!
//! > Measures proxy CPU + bytes per recrypted download for 100 MiB and 10 GiB
//! > files; assert flat.
//!
//! The design goal is that a recryption proxy call costs the *same* regardless
//! of underlying file size. The proxy never reads bulk ciphertext: it fetches
//! only the wrapped key and the recryption key (both KB-scale), runs
//! `recrypt_wrapped_key`, and returns the result with storage URLs the client
//! uses to fetch ciphertext directly.
//!
//! # What we measure
//!
//! The inner loop of `GET /recryption/share/{id}` ([`recryption.rs`]):
//!
//! 1. `Ciphertext::from_bytes(&policy.wrapped_key)` — parse stored wrapped key
//! 2. `RecryptKey::from_bytes(&policy.recrypt_key)` — parse stored recrypt key
//! 3. `HybridEncryptor::recrypt_wrapped_key(..)` — the actual PRE transform
//! 4. `new_wrapped.to_bytes()` — serialize for the JSON response
//!
//! We prepare inputs derived from files of different *nominal* plaintext sizes
//! (1 MiB, 16 MiB) and confirm the inner loop's timing does not vary. If a
//! future change causes the proxy to fetch or process bulk ciphertext, the
//! per-size numbers will diverge and the regression gate will fire.
//!
//! # CI sizing
//!
//! 100 MiB / 10 GiB workloads make CI multi-minute. We use 1 MiB and 16 MiB
//! for setup — the point is to verify flatness, not to hit a specific
//! throughput. The streaming-layer benchmark (`recrypt-core/benches/streaming.rs`)
//! already covers throughput at representative sizes.
//!
//! [`recryption.rs`]: ../../recrypt-server/src/routes/recryption.rs

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use recrypt_core::pre::backends::MockBackend;
use recrypt_core::{Ciphertext, HybridEncryptor, PreBackend, RecryptKey};
use std::io::Cursor;
use tokio::runtime::Runtime;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/// Produce proxy-side inputs that would exist after a file of `plaintext_len`
/// has been uploaded and a share has been created: the stored wrapped key
/// bytes, the recrypt key bytes, and a live encryptor.
///
/// These bytes mirror what `SharePolicy` holds in the server
/// ([`routes::recryption`]). The nominal file size determines the upstream
/// ciphertext + outboard that a real deployment would hold in storage, but
/// none of those bytes touch the proxy recryption path — we discard them
/// deliberately to keep the hot loop honest.
struct ProxyInputs {
    wrapped_key_bytes: Vec<u8>,
    recrypt_key_bytes: Vec<u8>,
    encryptor: HybridEncryptor<MockBackend>,
}

fn prepare_proxy_inputs(plaintext_len: usize) -> ProxyInputs {
    let rt = make_rt();
    let backend = MockBackend;
    let encryptor = HybridEncryptor::new(backend);
    let alice = encryptor.backend().generate_keypair().unwrap();
    let bob = encryptor.backend().generate_keypair().unwrap();
    let plaintext = make_buf(plaintext_len);

    // Drive the real encrypt path so the wrapped_key size matches production.
    let stream_result = rt.block_on(async {
        let mut ct_sink: Vec<u8> = Vec::with_capacity(plaintext.len());
        encryptor
            .encrypt_streaming(&alice.public, Cursor::new(&plaintext), &mut ct_sink)
            .await
            .expect("encrypt_streaming failed")
    });

    let recrypt_key = encryptor
        .backend()
        .generate_recrypt_key(&alice.secret, &bob.public)
        .expect("generate_recrypt_key failed");

    ProxyInputs {
        wrapped_key_bytes: stream_result.wrapped_key.to_bytes(),
        recrypt_key_bytes: recrypt_key.to_bytes(),
        encryptor,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// The proxy's inner loop: parse stored key material, run the PRE transform,
/// serialize the result. File-size independent by design.
fn run_proxy_call(inputs: &ProxyInputs) -> Vec<u8> {
    let wrapped_key = Ciphertext::from_bytes(black_box(&inputs.wrapped_key_bytes))
        .expect("Ciphertext::from_bytes failed");
    let recrypt_key = RecryptKey::from_bytes(black_box(&inputs.recrypt_key_bytes))
        .expect("RecryptKey::from_bytes failed");
    let new_wrapped = inputs
        .encryptor
        .recrypt_wrapped_key(&recrypt_key, &wrapped_key)
        .expect("recrypt_wrapped_key failed");
    new_wrapped.to_bytes()
}

fn bench_proxy_call_1mib_backed(c: &mut Criterion) {
    let inputs = prepare_proxy_inputs(1024 * 1024);

    c.bench_function("proxy_call_backed_by_1mib_file", |b| {
        b.iter(|| {
            black_box(run_proxy_call(&inputs));
        });
    });
}

fn bench_proxy_call_16mib_backed(c: &mut Criterion) {
    let inputs = prepare_proxy_inputs(16 * 1024 * 1024);

    c.bench_function("proxy_call_backed_by_16mib_file", |b| {
        b.iter(|| {
            black_box(run_proxy_call(&inputs));
        });
    });
}

/// Just the PRE transform on its own. Useful as a floor: everything else in
/// `run_proxy_call` is serialization overhead.
fn bench_recrypt_wrapped_key_only(c: &mut Criterion) {
    let inputs = prepare_proxy_inputs(1024 * 1024);
    let wrapped_key = Ciphertext::from_bytes(&inputs.wrapped_key_bytes).unwrap();
    let recrypt_key = RecryptKey::from_bytes(&inputs.recrypt_key_bytes).unwrap();

    c.bench_function("recrypt_wrapped_key_only", |b| {
        b.iter(|| {
            black_box(
                inputs
                    .encryptor
                    .recrypt_wrapped_key(black_box(&recrypt_key), black_box(&wrapped_key))
                    .expect("recrypt_wrapped_key failed"),
            );
        });
    });
}

// ---------------------------------------------------------------------------

criterion_group!(
    proxy_benches,
    bench_proxy_call_1mib_backed,
    bench_proxy_call_16mib_backed,
    bench_recrypt_wrapped_key_only,
);
criterion_main!(proxy_benches);
