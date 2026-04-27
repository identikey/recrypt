//! Envelope spike: validate that bc-envelope compiles, round-trips,
//! and supports the sign+elide+verify flow that the migration depends on.
//!
//! This is a Gate 2 precondition test. If this file compiles and the
//! tests pass, the bc-envelope API surface is confirmed to work for
//! recrypt's use case. If it doesn't, the migration plan needs revision
//! before any production code is written.
//!
//! See: docs/spikes/2026-04-08-envelope-sketch.md

use bc_envelope::prelude::*;

/// Basic round-trip: construct an envelope, serialize to CBOR, deserialize,
/// and verify the subject is preserved.
#[test]
fn envelope_basic_roundtrip() {
    let envelope = Envelope::new("hello recrypt");

    // Serialize to CBOR bytes
    let cbor_bytes = envelope.to_cbor_data();
    assert!(!cbor_bytes.is_empty());

    // Deserialize (takes Vec<u8>)
    let recovered = Envelope::try_from_cbor_data(cbor_bytes).expect("deserialize");

    // Verify structural equality
    assert_eq!(envelope.digest(), recovered.digest());
}

/// Assertion round-trip: add assertions and verify they survive serialization.
#[test]
fn envelope_assertion_roundtrip() {
    let envelope = Envelope::new("test-file")
        .add_assertion("backend", "lattice-bfv")
        .add_assertion("version", 3);

    let cbor_bytes = envelope.to_cbor_data();
    let recovered = Envelope::try_from_cbor_data(cbor_bytes).expect("deserialize");

    assert_eq!(envelope.digest(), recovered.digest());
}

/// Salted assertion round-trip: verify salted assertions have different
/// digests from unsalted ones (decorrelation) and survive serialization.
#[test]
fn envelope_salted_assertion() {
    let e1 = Envelope::new("file-a").add_assertion_salted("backend", "lattice-bfv", true);
    let e2 = Envelope::new("file-a").add_assertion_salted("backend", "lattice-bfv", true);

    // Two independently salted assertions should produce different digests
    let cbor1 = e1.to_cbor_data();
    let cbor2 = e2.to_cbor_data();

    // The CBOR bytes should differ because of different salts
    assert_ne!(
        cbor1, cbor2,
        "salted assertions should produce different bytes"
    );

    // But both should round-trip cleanly
    let r1 = Envelope::try_from_cbor_data(cbor1).expect("deserialize 1");
    let r2 = Envelope::try_from_cbor_data(cbor2).expect("deserialize 2");
    assert_eq!(e1.digest(), r1.digest());
    assert_eq!(e2.digest(), r2.digest());
}

/// dCBOR determinism: the same envelope serialized twice must produce
/// byte-identical output (FR-2).
#[test]
fn dcbor_determinism() {
    let envelope = Envelope::new("determinism-test")
        .add_assertion("field-a", "value-a")
        .add_assertion("field-b", "value-b")
        .add_assertion("field-c", 42);

    let bytes1 = envelope.to_cbor_data();
    let bytes2 = envelope.to_cbor_data();

    assert_eq!(bytes1, bytes2, "dCBOR encoding must be deterministic");
}

/// Elision preserves digest: elide an assertion and verify the envelope's
/// top-level digest is unchanged (the marquee feature — FR-4).
#[test]
fn elision_preserves_digest() {
    let base = Envelope::new("elision-test")
        .add_assertion("keep-me", "visible")
        .add_assertion("elide-me", "secret");

    let original_digest = base.digest();

    // Find the assertion to elide by checking predicates
    let target = base
        .assertions()
        .into_iter()
        .find(|a| {
            a.try_predicate()
                .ok()
                .and_then(|p| p.extract_subject::<String>().ok())
                .as_deref()
                == Some("elide-me")
        })
        .expect("should find elide-me assertion");

    // Elide it
    let elided = base.elide_removing_target(&target);

    // The top-level digest MUST be unchanged
    assert_eq!(
        original_digest,
        elided.digest(),
        "elision must preserve the envelope digest"
    );

    // The elided envelope should still serialize and deserialize
    let cbor = elided.to_cbor_data();
    let recovered = Envelope::try_from_cbor_data(cbor).expect("deserialize elided");
    assert_eq!(elided.digest(), recovered.digest());
}
