//! Compare key generation times for different PRE backends

use recrypt_core::pre::PreBackend;
use recrypt_core::pre::backends::LatticeBackend;
use std::time::Instant;

fn main() {
    println!("=== PRE Backend Key Generation Timing ===\n");

    // Test OpenFHE BFV (Lattice)
    if LatticeBackend::is_available() {
        println!("--- OpenFHE BFV (Lattice) ---");
        match LatticeBackend::new() {
            Ok(backend) => {
                println!("Backend: {}", backend.name());

                let start = Instant::now();
                match backend.generate_keypair() {
                    Ok(_kp) => {
                        let elapsed = start.elapsed();
                        println!(
                            "KeyGen: {:.2}s ({:.0}ms)",
                            elapsed.as_secs_f64(),
                            elapsed.as_millis()
                        );
                    }
                    Err(e) => println!("KeyGen failed: {e}"),
                }
            }
            Err(e) => println!("Init failed: {e}"),
        }
        println!();
    } else {
        println!("--- OpenFHE BFV: NOT AVAILABLE ---\n");
    }
}
