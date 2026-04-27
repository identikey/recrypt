//! Time all components of identity creation

use std::time::Instant;

fn main() {
    println!("=== Identity Creation Component Timing ===\n");

    // ED25519
    println!("--- ED25519 ---");
    let start = Instant::now();
    let _kp = recrypt_ffi::ed25519::ed25519_keygen();
    println!("✓ KeyGen: {:.0}ms\n", start.elapsed().as_millis());

    // ML-DSA-87
    println!("--- ML-DSA-87 (Post-Quantum Signature) ---");
    let start = Instant::now();
    let _kp = recrypt_ffi::liboqs::pq_keygen(recrypt_ffi::liboqs::PqAlgorithm::MlDsa87)
        .expect("ML-DSA keygen failed");
    println!("✓ KeyGen: {:.0}ms\n", start.elapsed().as_millis());

    // OpenFHE PRE
    #[cfg(feature = "openfhe")]
    {
        println!("--- OpenFHE BFV PRE ---");
        use recrypt_core::pre::PreBackend;
        use recrypt_core::pre::backends::LatticeBackend;

        let backend = LatticeBackend::new().expect("Failed to init backend");
        let start = Instant::now();
        let _kp = backend.generate_keypair().expect("PRE keygen failed");
        println!("✓ KeyGen: {:.0}ms\n", start.elapsed().as_millis());
    }

    println!("Done!");
}
