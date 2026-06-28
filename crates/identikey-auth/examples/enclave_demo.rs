//! End-to-end demo of the Secure Enclave + Touch ID auth path.
//!
//! Run on a **code-signed** macOS build (the Secure Enclave needs the
//! `keychain-access-groups` entitlement; unsigned binaries cannot create SEP keys):
//!
//! ```sh
//! cargo build --example enclave_demo
//! codesign --force --sign "Developer ID Application: Identikey Inc (3GZ9RHNYZM)" \
//!   --entitlements ../../Papyrus/src-tauri/entitlements.plist --options runtime \
//!   target/debug/examples/enclave_demo
//! ./target/debug/examples/enclave_demo
//! ```
//!
//! Expected: a Touch ID prompt appears at signing time; the response then verifies.
//! On non-macOS this example is a no-op.

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use identikey_auth::{
        verify_response, ChallengeIssuer, InMemoryNonceStore, SecureEnclaveSigner, Signer,
        VerifyPolicy,
    };

    // A real verifier would supply `now` from the system clock.
    let now = 1_000_000u64;

    // 1. Verifier issues a challenge.
    let mut nonces = InMemoryNonceStore::new();
    let challenge = ChallengeIssuer::new("papyrus", 120).issue(&mut nonces, now);
    println!("issued challenge for audience 'papyrus'");

    // 2. Claimant creates a Secure Enclave identity and responds. We use an EPHEMERAL
    //    (session-only) key here so the demo needs no keychain entitlement; the real app
    //    uses `load_or_create` for a persistent device key. Signing presents Touch ID.
    let signer = SecureEnclaveSigner::create_ephemeral("io.identikey.papyrus.device")?;
    println!("device fingerprint: {}", signer.classical_public_key().fingerprint());
    let response = signer.respond(&challenge)?;
    println!("signed challenge with Secure Enclave P-256 key");

    // 3. Verifier checks the response.
    let verified = verify_response(
        &response,
        "papyrus",
        now,
        30,
        VerifyPolicy::PqOptional,
        &mut nonces,
    )?;
    println!("VERIFIED identity: {}", verified.fingerprint);
    assert_eq!(verified.public_key, signer.classical_public_key());
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("enclave_demo is macOS-only");
}
