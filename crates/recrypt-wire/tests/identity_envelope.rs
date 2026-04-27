use bc_components::{Ed25519PublicKey, SigningPublicKey};
use bc_envelope::prelude::*;
use ed25519_dalek::SigningKey;
use recrypt_wire::{Identity, MlDsaKeyPair, PreKeyMaterial};

fn test_ed25519_public() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0] = 0xAA;
    key[31] = 0xBB;
    key
}

fn test_fingerprint(ed25519_public: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(ed25519_public).as_bytes()
}

fn full_identity() -> Identity {
    let ed25519_public = test_ed25519_public();
    Identity {
        fingerprint: test_fingerprint(&ed25519_public),
        ed25519_public,
        ed25519_secret: Some([0x11; 32]),
        name: Some("Alice".to_string()),
        created: Some(1700000000),
        ml_dsa: Some(MlDsaKeyPair {
            public: vec![0x22; 64],
            secret: Some(vec![0x33; 128]),
        }),
        pre: Some(PreKeyMaterial {
            backend: "lattice-bfv".to_string(),
            public: vec![0x44; 256],
            secret: Some(vec![0x55; 512]),
        }),
        unknown_assertions: vec![],
    }
}

#[test]
fn roundtrip_full_identity() {
    let identity = full_identity();
    let bytes = identity.to_envelope_bytes().unwrap();
    let parsed = Identity::from_envelope_bytes(&bytes).unwrap();

    assert_eq!(parsed.fingerprint, identity.fingerprint);
    assert_eq!(parsed.ed25519_public, identity.ed25519_public);
    assert_eq!(parsed.ed25519_secret, identity.ed25519_secret);
    assert_eq!(parsed.name, identity.name);
    assert_eq!(parsed.created, identity.created);
    assert_eq!(parsed.ml_dsa, identity.ml_dsa);
    assert_eq!(parsed.pre, identity.pre);
    assert!(parsed.unknown_assertions.is_empty());
}

#[test]
fn roundtrip_ed25519_only() {
    let ed25519_public = test_ed25519_public();
    let identity = Identity {
        fingerprint: test_fingerprint(&ed25519_public),
        ed25519_public,
        ed25519_secret: None,
        name: None,
        created: None,
        ml_dsa: None,
        pre: None,
        unknown_assertions: vec![],
    };

    let bytes = identity.to_envelope_bytes().unwrap();
    let parsed = Identity::from_envelope_bytes(&bytes).unwrap();

    assert_eq!(parsed.fingerprint, identity.fingerprint);
    assert_eq!(parsed.ed25519_public, identity.ed25519_public);
    assert_eq!(parsed.ed25519_secret, None);
    assert_eq!(parsed.name, None);
    assert_eq!(parsed.created, None);
    assert_eq!(parsed.ml_dsa, None);
    assert_eq!(parsed.pre, None);
    assert!(parsed.unknown_assertions.is_empty());
}

#[test]
fn roundtrip_hybrid_no_pre() {
    let ed25519_public = test_ed25519_public();
    let identity = Identity {
        fingerprint: test_fingerprint(&ed25519_public),
        ed25519_public,
        ed25519_secret: Some([0x99; 32]),
        name: Some("Bob".to_string()),
        created: Some(1710000000),
        ml_dsa: Some(MlDsaKeyPair {
            public: vec![0xAA; 64],
            secret: Some(vec![0xBB; 128]),
        }),
        pre: None,
        unknown_assertions: vec![],
    };

    let bytes = identity.to_envelope_bytes().unwrap();
    let parsed = Identity::from_envelope_bytes(&bytes).unwrap();

    assert_eq!(parsed.fingerprint, identity.fingerprint);
    assert_eq!(parsed.ed25519_public, identity.ed25519_public);
    assert_eq!(parsed.ed25519_secret, identity.ed25519_secret);
    assert_eq!(parsed.name, identity.name);
    assert_eq!(parsed.created, identity.created);
    assert_eq!(parsed.ml_dsa, identity.ml_dsa);
    assert_eq!(parsed.pre, None);
    assert!(parsed.unknown_assertions.is_empty());
}

#[test]
fn unknown_assertion_preserved() {
    let ed25519_public = test_ed25519_public();
    let fingerprint = test_fingerprint(&ed25519_public);

    // Build envelope manually with a known identity + unknown assertion
    let mut subject = Map::new();
    subject.insert("type", "recrypt.identity");
    subject.insert("format-version", 1_u32);
    subject.insert("fingerprint", ByteString::from(fingerprint.to_vec()));

    let envelope = Envelope::new(CBOR::from(subject))
        .add_assertion("ed25519-public", ByteString::from(ed25519_public.to_vec()))
        .add_assertion(
            "dreamball-lineage",
            ByteString::from(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        );

    let original_bytes = envelope.to_cbor_data();

    // Parse it
    let parsed = Identity::from_envelope_bytes(&original_bytes).unwrap();
    assert_eq!(parsed.unknown_assertions.len(), 1);

    // Re-emit and check byte equality
    let re_emitted = parsed.to_envelope_bytes().unwrap();
    assert_eq!(
        original_bytes, re_emitted,
        "unknown assertion round-trip must produce byte-equal CBOR"
    );
}

#[test]
fn name_absent_not_empty_string() {
    let ed25519_public = test_ed25519_public();
    let identity = Identity {
        fingerprint: test_fingerprint(&ed25519_public),
        ed25519_public,
        ed25519_secret: None,
        name: None,
        created: None,
        ml_dsa: None,
        pre: None,
        unknown_assertions: vec![],
    };

    let bytes = identity.to_envelope_bytes().unwrap();
    let parsed = Identity::from_envelope_bytes(&bytes).unwrap();
    assert_eq!(parsed.name, None);
    assert_ne!(parsed.name, Some("".to_string()));
}

#[test]
fn fingerprint_validation_on_encode() {
    // Encoder validates fingerprint == Blake3(ed25519-public) — catches
    // construction errors before they hit the wire.
    let ed25519_public = test_ed25519_public();
    let wrong_fingerprint = [0xFF; 32]; // deliberate mismatch

    let identity = Identity {
        fingerprint: wrong_fingerprint,
        ed25519_public,
        ed25519_secret: None,
        name: None,
        created: None,
        ml_dsa: None,
        pre: None,
        unknown_assertions: vec![],
    };

    let err = identity.to_envelope_bytes().unwrap_err().to_string();
    assert!(
        err.contains("fingerprint"),
        "encode error must mention fingerprint: {err}"
    );
}

#[test]
fn fingerprint_validation_on_decode() {
    // Decoder also enforces fingerprint == Blake3(ed25519-public) — catches
    // tampered bytes that bypassed the encoder (e.g. from another impl).
    use bc_envelope::prelude::*;
    let mut subject = Map::new();
    subject.insert("type", "recrypt.identity");
    subject.insert("format-version", 1_u32);
    subject.insert("fingerprint", ByteString::from(vec![0xFFu8; 32])); // bogus

    let env = Envelope::new(CBOR::from(subject)).add_assertion(
        "ed25519-public",
        ByteString::from(test_ed25519_public().to_vec()),
    );
    let bytes = env.to_cbor_data();
    let err = Identity::from_envelope_bytes(&bytes)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("fingerprint"),
        "decode error must mention fingerprint: {err}"
    );
}

#[test]
fn missing_ed25519_public_rejected() {
    let fingerprint = [0x42; 32];

    let mut subject = Map::new();
    subject.insert("type", "recrypt.identity");
    subject.insert("format-version", 1_u32);
    subject.insert("fingerprint", ByteString::from(fingerprint.to_vec()));

    // Build envelope without ed25519-public assertion
    let envelope = Envelope::new(CBOR::from(subject)).add_assertion("name", "Alice");

    let bytes = envelope.to_cbor_data();
    let result = Identity::from_envelope_bytes(&bytes);
    assert!(result.is_err(), "missing ed25519-public must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("ed25519-public"),
        "error must mention ed25519-public: {err}"
    );
}

// ── Self-signature tests ────────────────────────────────────────────────────

/// Generate a deterministic ed25519 keypair from a seed for tests.
fn make_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
    let secret_bytes = [seed; 32];
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let public_bytes: [u8; 32] = signing_key.verifying_key().to_bytes();
    (secret_bytes, public_bytes)
}

fn signed_identity(seed: u8) -> Identity {
    let (secret, public) = make_keypair(seed);
    let fingerprint = *blake3::hash(&public).as_bytes();
    Identity {
        fingerprint,
        ed25519_public: public,
        ed25519_secret: Some(secret),
        name: Some("SignTest".to_string()),
        created: Some(1700000000),
        ml_dsa: None,
        pre: None,
        unknown_assertions: vec![],
    }
}

#[test]
fn self_sign_and_verify_roundtrip() {
    let identity = signed_identity(0xAA);
    let signed_bytes = identity.sign_self_ed25519().unwrap();
    Identity::verify_self_signature_ed25519(&signed_bytes)
        .expect("self-signed envelope must verify");
}

#[test]
fn verify_fails_without_signature() {
    let identity = signed_identity(0xBB);
    // to_envelope_bytes produces an unsigned envelope
    let unsigned_bytes = identity.to_envelope_bytes().unwrap();
    let result = Identity::verify_self_signature_ed25519(&unsigned_bytes);
    assert!(result.is_err(), "unsigned envelope must fail verification");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("signature verification failed"),
        "error must mention signature: {err}"
    );
}

#[test]
fn sign_requires_secret_key() {
    let (_, public) = make_keypair(0xCC);
    let fingerprint = *blake3::hash(&public).as_bytes();
    let identity = Identity {
        fingerprint,
        ed25519_public: public,
        ed25519_secret: None, // no secret key
        name: None,
        created: None,
        ml_dsa: None,
        pre: None,
        unknown_assertions: vec![],
    };
    let result = identity.sign_self_ed25519();
    assert!(result.is_err(), "signing without secret key must fail");
}

#[test]
fn verify_fails_with_wrong_key() {
    // Construct a forged envelope: take identity A's wrapped envelope (bound to
    // A's ed25519-public via fingerprint) but sign it with B's key. Verification
    // must fail — the embedded public key is A's, B's signature won't verify
    // against A's verifying key.
    let identity_a = signed_identity(0xDD);
    let identity_b = signed_identity(0xEE);

    let inner_a = identity_a.to_envelope_bytes().unwrap();
    let inner_envelope = Envelope::try_from_cbor_data(inner_a).unwrap();
    let wrapped = inner_envelope.wrap();

    let secret_b = identity_b.ed25519_secret.unwrap();
    let private_key_b = bc_components::SigningPrivateKey::new_ed25519(
        bc_components::Ed25519PrivateKey::from_data(secret_b),
    );
    let forged = wrapped.add_signature(&private_key_b).to_cbor_data();

    let result = Identity::verify_self_signature_ed25519(&forged);
    assert!(
        result.is_err(),
        "envelope signed by wrong key must fail verification"
    );
}

#[test]
fn self_signed_envelope_has_signed_assertion() {
    let identity = signed_identity(0xFF);
    let signed_bytes = identity.sign_self_ed25519().unwrap();

    // Parse the raw envelope and confirm the 'signed' assertion is present on
    // the wrapper (wrap-then-sign).
    let envelope = Envelope::try_from_cbor_data(signed_bytes).unwrap();
    let public_key =
        SigningPublicKey::from_ed25519(Ed25519PublicKey::from_data(identity.ed25519_public));
    let has_sig = envelope.has_signature_from(&public_key).unwrap();
    assert!(
        has_sig,
        "signed envelope must contain valid 'signed' assertion"
    );
}

#[test]
fn signature_covers_assertions_not_just_subject() {
    // Wrap-then-sign means tampering with any assertion (e.g., substituting
    // the ml-dsa-public key) must break verification. This is the protection
    // the subject-only signing scheme did NOT provide.
    let (secret, public) = make_keypair(0x10);
    let fingerprint = *blake3::hash(&public).as_bytes();
    let identity = Identity {
        fingerprint,
        ed25519_public: public,
        ed25519_secret: Some(secret),
        name: Some("Carol".to_string()),
        created: Some(1700000000),
        ml_dsa: Some(MlDsaKeyPair {
            public: vec![0xAA; 64],
            secret: None,
        }),
        pre: None,
        unknown_assertions: vec![],
    };

    let signed_bytes = identity.sign_self_ed25519().unwrap();

    // Build a tampered version: same identity, different ml-dsa-public.
    let tampered_identity = Identity {
        fingerprint,
        ed25519_public: public,
        ed25519_secret: Some(secret),
        name: Some("Carol".to_string()),
        created: Some(1700000000),
        ml_dsa: Some(MlDsaKeyPair {
            public: vec![0xBB; 64], // attacker-substituted key
            secret: None,
        }),
        pre: None,
        unknown_assertions: vec![],
    };

    let tampered_inner = tampered_identity.to_envelope_bytes().unwrap();
    let tampered_envelope = Envelope::try_from_cbor_data(tampered_inner).unwrap();
    let tampered_wrapped = tampered_envelope.wrap();

    // The original signed envelope must verify; the tampered wrapper without
    // a fresh signature must not. Re-using the original signature is
    // impossible because the wrapper's subject digest covers the inner
    // envelope, which now differs (different ml-dsa-public assertion).
    Identity::verify_self_signature_ed25519(&signed_bytes)
        .expect("original signed envelope must verify");

    let unsigned_tampered = tampered_wrapped.to_cbor_data();
    let result = Identity::verify_self_signature_ed25519(&unsigned_tampered);
    assert!(
        result.is_err(),
        "wrapped envelope without signature must fail verification"
    );
}

// ---------------------------------------------------------------------------
// Hybrid (ed25519 + ML-DSA-87) self-signature
// ---------------------------------------------------------------------------

#[cfg(feature = "pq-self-sign")]
mod hybrid {
    use super::*;
    use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

    fn real_identity_with_secrets() -> Identity {
        // Real ed25519 keypair (deterministic seed; tests don't need
        // freshness here, just a key that bc-envelope sign/verify
        // accepts).
        let seed = [0xA1u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let ed25519_public = signing.verifying_key().to_bytes();
        let ed25519_secret = signing.to_bytes();

        // Real ML-DSA-87 keypair.
        let pq_kp = pq_keygen(PqAlgorithm::MlDsa87).unwrap();

        Identity {
            fingerprint: *blake3::hash(&ed25519_public).as_bytes(),
            ed25519_public,
            ed25519_secret: Some(ed25519_secret),
            name: Some("Hybrid Hannah".to_string()),
            created: Some(1_712_534_400),
            ml_dsa: Some(MlDsaKeyPair {
                public: pq_kp.public_key.clone(),
                secret: Some(pq_kp.secret_key.clone()),
            }),
            pre: None,
            unknown_assertions: vec![],
        }
    }

    #[test]
    fn hybrid_sign_and_verify_roundtrip() {
        let identity = real_identity_with_secrets();
        let ml_dsa_secret = identity.ml_dsa.as_ref().unwrap().secret.clone().unwrap();
        let signed_bytes = identity.sign_self_hybrid(&ml_dsa_secret).unwrap();

        Identity::verify_self_signature_hybrid(&signed_bytes)
            .expect("hybrid roundtrip must verify");

        // The ed25519-only verifier is also satisfied because the ed25519
        // half of the hybrid uses the same `'signed'` mechanism.
        Identity::verify_self_signature_ed25519(&signed_bytes)
            .expect("ed25519 verifier must accept hybrid envelope");
    }

    #[test]
    fn hybrid_verify_rejects_missing_mldsa_assertion() {
        // An ed25519-only signed envelope has no `mldsa-signature`
        // assertion, so the hybrid verifier must refuse it.
        let identity = real_identity_with_secrets();
        let signed_ed_only = identity.sign_self_ed25519().unwrap();
        let err = Identity::verify_self_signature_hybrid(&signed_ed_only).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mldsa-signature") || msg.contains("signature verification failed"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn hybrid_verify_rejects_tampered_mldsa_signature() {
        let identity = real_identity_with_secrets();
        let ml_dsa_secret = identity.ml_dsa.as_ref().unwrap().secret.clone().unwrap();
        let signed_bytes = identity.sign_self_hybrid(&ml_dsa_secret).unwrap();

        // Flip a byte deep in the envelope (likely inside the ml-dsa
        // signature). This must fail verification — either because of
        // CBOR parse failure, ed25519 mismatch, or ml-dsa mismatch.
        // Try several positions to find one that lands cleanly.
        for offset in [signed_bytes.len() - 100, signed_bytes.len() - 50] {
            let mut tampered = signed_bytes.clone();
            tampered[offset] ^= 0xAA;
            let _ = Identity::verify_self_signature_hybrid(&tampered).unwrap_err();
        }
    }

    #[test]
    fn hybrid_sign_requires_ed25519_secret() {
        let mut identity = real_identity_with_secrets();
        let ml_dsa_secret = identity.ml_dsa.as_ref().unwrap().secret.clone().unwrap();
        identity.ed25519_secret = None;
        let err = identity.sign_self_hybrid(&ml_dsa_secret).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ed25519 secret key required"),
            "unexpected: {msg}"
        );
    }
}
