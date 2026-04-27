//! Check PRE key sizes

use recrypt_core::pre::PreBackend;
use recrypt_core::pre::backends::LatticeBackend;

fn main() {
    let backend = LatticeBackend::new().expect("Backend init failed");
    let kp = backend.generate_keypair().expect("Keygen failed");

    println!("OpenFHE BFV Key Sizes:");
    println!("  Public key:  {} bytes", kp.public.as_bytes().len());
    println!("  Secret key:  {} bytes", kp.secret.as_bytes().len());
}
