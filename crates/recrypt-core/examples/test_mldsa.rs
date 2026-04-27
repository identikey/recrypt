//! Test just ML-DSA keygen

use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};
use std::time::Instant;

fn main() {
    println!("Testing ML-DSA-87 keygen...");

    for i in 1..=5 {
        let start = Instant::now();
        let _kp = pq_keygen(PqAlgorithm::MlDsa87).expect("Failed");
        println!("  Iteration {}: {:.0}ms", i, start.elapsed().as_millis());
    }
}
