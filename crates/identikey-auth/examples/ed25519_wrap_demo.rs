//! Demo of an **Ed25519** identity wrapped under a macOS Secure Enclave P-256 key (§8).
//!
//! The Ed25519 seed is ECIES-encrypted under a Touch-ID-gated Secure Enclave key; signing
//! unwraps it (Touch ID prompt) into memory, signs, and zeroizes. Run on a code-signed
//! build:
//!
//! ```sh
//! cargo build -p identikey-auth --example ed25519_wrap_demo
//! codesign --force --sign "Developer ID Application: …" target/debug/examples/ed25519_wrap_demo
//! ./target/debug/examples/ed25519_wrap_demo
//! ```
//!
//! Expected: a Touch ID prompt at signing, then `VERIFIED (ed25519)`. macOS-only.

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use identikey_auth::{
        verify_response, ChallengeIssuer, ClassicalAlg, InMemoryNonceStore,
        SecureEnclaveEd25519Signer, Signer, VerifyPolicy,
    };

    let now = 1_000_000u64;
    let mut nonces = InMemoryNonceStore::new();
    let challenge = ChallengeIssuer::new("papyrus", 120).issue(&mut nonces, now);
    println!("issued challenge for audience 'papyrus'");

    // Ephemeral: a session-only SE wrapping key + a fresh wrapped Ed25519 seed.
    let signer = SecureEnclaveEd25519Signer::create_ephemeral("io.identikey.papyrus.ed25519")?;
    let pubkey = signer.classical_public_key();
    assert_eq!(pubkey.alg, ClassicalAlg::Ed25519);
    println!("ed25519 device fingerprint: {}", pubkey.fingerprint());

    let response = signer.respond(&challenge)?; // unwraps under Touch ID, signs
    println!("signed challenge with Secure-Enclave-wrapped Ed25519 key");

    let verified = verify_response(
        &response,
        "papyrus",
        now,
        30,
        VerifyPolicy::PqOptional,
        &mut nonces,
    )?;
    assert_eq!(verified.public_key.alg, ClassicalAlg::Ed25519);
    println!("VERIFIED (ed25519) identity: {}", verified.fingerprint);
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("ed25519_wrap_demo is macOS-only");
}
