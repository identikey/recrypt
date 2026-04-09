//! NFR measurement tests — Gate 5 of the migration plan.
//! These tests measure and assert the non-functional requirements
//! from docs/plans/2026-04-08-gordian-envelope-migration.md.

use recrypt_core::hybrid::EncryptedFile;
use recrypt_core::pre::{BackendId, Ciphertext};
use recrypt_wire::format::MultiFormat;

// ── NFR-2: Storage overhead stays small ──────────────────────────────────────

#[test]
fn nfr2_metadata_only_envelope_under_2kb() {
    // Server mode: no inline ciphertext or wrapped-key
    let meta_only = EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Lattice, 0, Vec::new()),
        bao_hash: [0x42u8; 32],
        ciphertext: Vec::new(),
        signature: None,
    };
    let env = meta_only.to_envelope().unwrap();
    println!("NFR-2: metadata-only envelope = {} bytes", env.len());
    assert!(
        env.len() < 2048,
        "NFR-2 FAIL: metadata-only envelope {} bytes exceeds 2048",
        env.len()
    );
}

#[test]
fn nfr2_overhead_under_5pct_for_1mb_file() {
    // 1 MB ciphertext + 4 KB wrapped key (realistic lattice PRE)
    let file = EncryptedFile {
        wrapped_key: Ciphertext::new(BackendId::Lattice, 0, vec![0xBB; 4096]),
        bao_hash: [0x42u8; 32],
        ciphertext: vec![0u8; 1_000_000],
        signature: None,
    };
    let env = file.to_envelope().unwrap();
    let payload_size = 1_000_000 + 4096;
    let overhead = env.len() - payload_size;
    let overhead_pct = overhead as f64 / 1_000_000.0 * 100.0;

    println!(
        "NFR-2: 1 MB file envelope = {} bytes, overhead = {} bytes ({:.2}%)",
        env.len(),
        overhead,
        overhead_pct
    );
    assert!(
        overhead_pct < 5.0,
        "NFR-2 FAIL: overhead {:.2}% exceeds 5%",
        overhead_pct
    );
}

// ── NFR-2 size report (informational) ────────────────────────────────────────

#[test]
fn nfr2_size_report() {
    let sizes = [
        ("empty ct, no wk", 0usize, 0usize),
        ("1 KB ct, 128 B wk", 1024, 128),
        ("64 KB ct, 4 KB wk", 65536, 4096),
        ("1 MB ct, 4 KB wk", 1_000_000, 4096),
    ];

    println!("\n=== Envelope size report ===");
    println!(
        "{:<25} {:>10} {:>10} {:>10} {:>8}",
        "Scenario", "Payload", "Envelope", "Overhead", "Ovh %"
    );
    println!("{}", "-".repeat(73));

    for (label, ct_size, wk_size) in sizes {
        let file = EncryptedFile {
            wrapped_key: Ciphertext::new(BackendId::Lattice, 0, vec![0u8; wk_size]),
            bao_hash: [0x42u8; 32],
            ciphertext: vec![0u8; ct_size],
            signature: None,
        };
        let env = file.to_envelope().unwrap();
        let payload = ct_size + wk_size;
        let overhead = if env.len() > payload {
            env.len() - payload
        } else {
            env.len()
        };
        let pct = if payload > 0 {
            overhead as f64 / payload as f64 * 100.0
        } else {
            100.0
        };
        println!(
            "{:<25} {:>10} {:>10} {:>10} {:>7.1}%",
            label, payload, env.len(), overhead, pct
        );
    }
}
