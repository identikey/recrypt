//! Gordian Envelope encode/decode for wallet body.
//!
//! Spec: docs/standards/wallet-envelope-format.md (§3.1, §3.2).
//!
//! Wallet envelope shape:
//!   subject: leaf map {type: "recrypt.wallet", format-version: 2}
//!   assertions:
//!     "active-identity" -> string (when Some)
//!     "identity" -> nested identity envelope, repeated per identity
//!
//! Identity envelope shape:
//!   subject: leaf map {type: "recrypt.identity", format-version: 1, fingerprint: 32B}
//!   assertions: name, created (tag 1 epoch), ed25519-{public,secret},
//!               ml-dsa-{public,secret}, pre-backend, pre-{public,secret}

use anyhow::{anyhow, Result};
use bc_envelope::prelude::*;
use std::collections::HashMap;
use std::str::FromStr;

use recrypt_core::pre::BackendId;

use super::format::{Identity, KeyPair, WalletData};

const WALLET_TYPE: &str = "recrypt.wallet";
const WALLET_FORMAT_VERSION: u32 = 2;
const IDENTITY_TYPE: &str = "recrypt.identity";
const IDENTITY_FORMAT_VERSION: u32 = 1;

/// Encode a wallet to dCBOR envelope bytes.
pub fn to_envelope(wallet: &WalletData) -> Result<Vec<u8>> {
    let envelope = wallet_to_envelope(wallet)?;
    Ok(envelope.to_cbor_data())
}

/// Decode dCBOR envelope bytes into a WalletData.
pub fn from_envelope(bytes: &[u8]) -> Result<WalletData> {
    let envelope = Envelope::try_from_cbor_data(bytes.to_vec())
        .map_err(|e| anyhow!("Failed to parse wallet envelope: {e}"))?;
    wallet_from_envelope(&envelope)
}

fn wallet_to_envelope(wallet: &WalletData) -> Result<Envelope> {
    let mut subject = Map::new();
    subject.insert("type", WALLET_TYPE);
    subject.insert("format-version", WALLET_FORMAT_VERSION);

    let mut envelope = Envelope::new(CBOR::from(subject));

    if let Some(ref active) = wallet.active_identity {
        envelope = envelope.add_assertion("active-identity", active.as_str());
    }

    // Sort by name for stable encoding order across runs.
    let mut names: Vec<&String> = wallet.identities.keys().collect();
    names.sort();
    for name in names {
        let identity = &wallet.identities[name];
        let id_envelope = identity_to_envelope(name, identity)?;
        envelope = envelope.add_assertion("identity", id_envelope);
    }

    Ok(envelope)
}

fn wallet_from_envelope(envelope: &Envelope) -> Result<WalletData> {
    let subject_cbor = envelope
        .subject()
        .try_leaf()
        .map_err(|e| anyhow!("Wallet envelope subject not a leaf: {e}"))?;

    let subject = match subject_cbor.into_case() {
        CBORCase::Map(m) => m,
        _ => return Err(anyhow!("Wallet envelope subject is not a map")),
    };

    let ty: String = subject
        .get("type")
        .ok_or_else(|| anyhow!("Wallet envelope subject missing 'type'"))?;
    if ty != WALLET_TYPE {
        return Err(anyhow!(
            "Expected wallet type '{WALLET_TYPE}', got '{ty}'"
        ));
    }

    let version: u32 = subject
        .get("format-version")
        .ok_or_else(|| anyhow!("Wallet envelope subject missing 'format-version'"))?;
    if version != WALLET_FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported wallet envelope format-version: {version}"
        ));
    }

    let active_identity: Option<String> = envelope
        .extract_optional_object_for_predicate::<String>("active-identity")
        .unwrap_or(None);

    let mut identities: HashMap<String, Identity> = HashMap::new();
    for assertion in envelope.assertions() {
        let pred = match assertion.as_predicate() {
            Some(p) => p,
            None => continue,
        };
        let pred_str: String = match pred.try_leaf() {
            Ok(c) => match c.try_into_text() {
                Ok(s) => s,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        if pred_str != "identity" {
            continue;
        }
        let obj = assertion
            .as_object()
            .ok_or_else(|| anyhow!("'identity' assertion missing object"))?;
        let (name, identity) = identity_from_envelope(&obj)?;
        if identities.insert(name.clone(), identity).is_some() {
            return Err(anyhow!("Duplicate identity name: {name}"));
        }
    }

    Ok(WalletData {
        identities,
        active_identity,
    })
}

fn identity_to_envelope(name: &str, id: &Identity) -> Result<Envelope> {
    // Verify fingerprint == Blake3(ed25519-public) before emitting.
    let expected = blake3::hash(&id.ed25519.public);
    if id.fingerprint != *expected.as_bytes() {
        return Err(anyhow!(
            "Identity '{name}': fingerprint does not match Blake3(ed25519-public)"
        ));
    }

    let mut subject = Map::new();
    subject.insert("type", IDENTITY_TYPE);
    subject.insert("format-version", IDENTITY_FORMAT_VERSION);
    subject.insert("fingerprint", ByteString::from(id.fingerprint.to_vec()));

    let mut envelope = Envelope::new(CBOR::from(subject));

    envelope = envelope.add_assertion("name", name);

    let created_tagged = CBOR::to_tagged_value(Tag::with_value(1), id.created_at);
    envelope = envelope.add_assertion("created", created_tagged);

    envelope = envelope.add_assertion(
        "ed25519-public",
        ByteString::from(id.ed25519.public.clone()),
    );
    envelope = envelope.add_assertion(
        "ed25519-secret",
        ByteString::from(id.ed25519.secret.clone()),
    );
    envelope = envelope.add_assertion(
        "ml-dsa-public",
        ByteString::from(id.ml_dsa.public.clone()),
    );
    envelope = envelope.add_assertion(
        "ml-dsa-secret",
        ByteString::from(id.ml_dsa.secret.clone()),
    );
    envelope = envelope.add_assertion("pre-backend", id.pre_backend.to_string());
    envelope = envelope.add_assertion("pre-public", ByteString::from(id.pre.public.clone()));
    envelope = envelope.add_assertion("pre-secret", ByteString::from(id.pre.secret.clone()));

    Ok(envelope)
}

fn identity_from_envelope(envelope: &Envelope) -> Result<(String, Identity)> {
    let subject_cbor = envelope
        .subject()
        .try_leaf()
        .map_err(|e| anyhow!("Identity envelope subject not a leaf: {e}"))?;

    let subject = match subject_cbor.into_case() {
        CBORCase::Map(m) => m,
        _ => return Err(anyhow!("Identity envelope subject is not a map")),
    };

    let ty: String = subject
        .get("type")
        .ok_or_else(|| anyhow!("Identity envelope subject missing 'type'"))?;
    if ty != IDENTITY_TYPE {
        return Err(anyhow!(
            "Expected identity type '{IDENTITY_TYPE}', got '{ty}'"
        ));
    }

    let version: u32 = subject
        .get("format-version")
        .ok_or_else(|| anyhow!("Identity envelope subject missing 'format-version'"))?;
    if version != IDENTITY_FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported identity envelope format-version: {version}"
        ));
    }

    let fp_bs: ByteString = subject
        .get("fingerprint")
        .ok_or_else(|| anyhow!("Identity envelope subject missing 'fingerprint'"))?;
    let fingerprint: [u8; 32] = fp_bs
        .to_vec()
        .try_into()
        .map_err(|_| anyhow!("Identity fingerprint must be 32 bytes"))?;

    let name: String = envelope
        .extract_object_for_predicate("name")
        .map_err(|_| anyhow!("Identity envelope missing 'name' assertion"))?;

    let created_at = extract_created(envelope)?;

    let ed25519_public = extract_bytes(envelope, "ed25519-public")?;
    let ed25519_secret = extract_bytes(envelope, "ed25519-secret")?;
    let ml_dsa_public = extract_bytes(envelope, "ml-dsa-public")?;
    let ml_dsa_secret = extract_bytes(envelope, "ml-dsa-secret")?;

    let pre_backend_str: String = envelope
        .extract_object_for_predicate("pre-backend")
        .map_err(|_| anyhow!("Identity envelope missing 'pre-backend' assertion"))?;
    let pre_backend = BackendId::from_str(&pre_backend_str)
        .map_err(|e| anyhow!("Unknown pre-backend '{pre_backend_str}': {e}"))?;
    let pre_public = extract_bytes(envelope, "pre-public")?;
    let pre_secret = extract_bytes(envelope, "pre-secret")?;

    // Verify fingerprint == Blake3(ed25519-public).
    let expected = blake3::hash(&ed25519_public);
    if fingerprint != *expected.as_bytes() {
        return Err(anyhow!(
            "Identity fingerprint does not match Blake3(ed25519-public)"
        ));
    }

    let identity = Identity {
        created_at,
        fingerprint,
        ed25519: KeyPair {
            public: ed25519_public,
            secret: ed25519_secret,
        },
        ml_dsa: KeyPair {
            public: ml_dsa_public,
            secret: ml_dsa_secret,
        },
        pre: KeyPair {
            public: pre_public,
            secret: pre_secret,
        },
        pre_backend,
    };

    Ok((name, identity))
}

fn extract_bytes(envelope: &Envelope, predicate: &str) -> Result<Vec<u8>> {
    let bs: ByteString = envelope
        .extract_object_for_predicate(predicate)
        .map_err(|_| anyhow!("Identity envelope missing '{predicate}' assertion"))?;
    Ok(bs.to_vec())
}

fn extract_created(envelope: &Envelope) -> Result<u64> {
    let obj = envelope
        .object_for_predicate("created")
        .map_err(|_| anyhow!("Identity envelope missing 'created' assertion"))?;
    let cbor = obj
        .try_leaf()
        .map_err(|e| anyhow!("'created' object not a leaf: {e}"))?;
    match cbor.into_case() {
        CBORCase::Tagged(tag, inner) if tag.value() == 1 => match inner.into_case() {
            CBORCase::Unsigned(v) => Ok(v),
            other => Err(anyhow!(
                "'created' tag-1 inner must be unsigned, got {:?}",
                CBOR::from(other)
            )),
        },
        other => Err(anyhow!(
            "'created' must be CBOR tag 1 epoch time, got {:?}",
            CBOR::from(other)
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_identity(name: &str, ed_pub_seed: u8) -> (String, Identity) {
        let ed_public = vec![ed_pub_seed; 32];
        let fingerprint: [u8; 32] = *blake3::hash(&ed_public).as_bytes();
        let identity = Identity {
            created_at: 1_704_067_200 + ed_pub_seed as u64,
            fingerprint,
            ed25519: KeyPair {
                public: ed_public,
                secret: vec![0xAA; 32],
            },
            ml_dsa: KeyPair {
                public: vec![0xBB; 16],
                secret: vec![0xCC; 32],
            },
            pre: KeyPair {
                public: vec![0xDD; 8],
                secret: vec![0xEE; 16],
            },
            pre_backend: BackendId::Mock,
        };
        (name.to_string(), identity)
    }

    fn assert_wallet_eq(a: &WalletData, b: &WalletData) {
        assert_eq!(a.active_identity, b.active_identity, "active-identity");
        assert_eq!(
            a.identities.len(),
            b.identities.len(),
            "identity count mismatch"
        );
        for (name, id_a) in &a.identities {
            let id_b = b
                .identities
                .get(name)
                .unwrap_or_else(|| panic!("missing identity {name} after roundtrip"));
            assert_eq!(id_a.created_at, id_b.created_at, "{name}: created_at");
            assert_eq!(id_a.fingerprint, id_b.fingerprint, "{name}: fingerprint");
            assert_eq!(
                id_a.ed25519.public, id_b.ed25519.public,
                "{name}: ed25519 public"
            );
            assert_eq!(
                id_a.ed25519.secret, id_b.ed25519.secret,
                "{name}: ed25519 secret"
            );
            assert_eq!(id_a.ml_dsa.public, id_b.ml_dsa.public, "{name}: ml_dsa pub");
            assert_eq!(id_a.ml_dsa.secret, id_b.ml_dsa.secret, "{name}: ml_dsa sec");
            assert_eq!(id_a.pre.public, id_b.pre.public, "{name}: pre pub");
            assert_eq!(id_a.pre.secret, id_b.pre.secret, "{name}: pre sec");
            assert_eq!(id_a.pre_backend, id_b.pre_backend, "{name}: pre_backend");
        }
    }

    #[test]
    fn roundtrip_single_identity() {
        let (name, identity) = mock_identity("alice", 1);
        let mut wallet = WalletData {
            identities: HashMap::new(),
            active_identity: Some(name.clone()),
        };
        wallet.identities.insert(name, identity);

        let bytes = to_envelope(&wallet).unwrap();
        let decoded = from_envelope(&bytes).unwrap();
        assert_wallet_eq(&wallet, &decoded);
    }

    #[test]
    fn roundtrip_three_identities_active_preserved() {
        let mut wallet = WalletData {
            identities: HashMap::new(),
            active_identity: Some("bob".to_string()),
        };
        for (name, id) in [
            mock_identity("alice", 1),
            mock_identity("bob", 2),
            mock_identity("carol", 3),
        ] {
            wallet.identities.insert(name, id);
        }

        let bytes = to_envelope(&wallet).unwrap();
        let decoded = from_envelope(&bytes).unwrap();
        assert_wallet_eq(&wallet, &decoded);
        assert_eq!(decoded.active_identity, Some("bob".to_string()));
    }

    #[test]
    fn roundtrip_zero_identities_no_active() {
        let wallet = WalletData {
            identities: HashMap::new(),
            active_identity: None,
        };
        let bytes = to_envelope(&wallet).unwrap();
        let decoded = from_envelope(&bytes).unwrap();
        assert_wallet_eq(&wallet, &decoded);
        assert!(decoded.active_identity.is_none());
        assert!(decoded.identities.is_empty());
    }

    #[test]
    fn determinism_same_input_same_bytes() {
        let (name, identity) = mock_identity("alice", 7);
        let mut wallet = WalletData {
            identities: HashMap::new(),
            active_identity: Some(name.clone()),
        };
        wallet.identities.insert(name, identity);

        let a = to_envelope(&wallet).unwrap();
        let b = to_envelope(&wallet).unwrap();
        assert_eq!(a, b, "envelope encoding is non-deterministic");
    }

    #[test]
    fn encode_rejects_tampered_fingerprint() {
        let (name, mut identity) = mock_identity("alice", 1);
        identity.fingerprint = [0xFFu8; 32]; // bogus fingerprint
        let mut wallet = WalletData {
            identities: HashMap::new(),
            active_identity: None,
        };
        wallet.identities.insert(name, identity);

        let err = to_envelope(&wallet).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("fingerprint does not match"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn decode_rejects_tampered_fingerprint() {
        // Build an identity envelope by hand with a wrong fingerprint.
        let bogus_fp = [0xFFu8; 32];
        let ed_public = vec![1u8; 32];

        let mut id_subject = Map::new();
        id_subject.insert("type", IDENTITY_TYPE);
        id_subject.insert("format-version", IDENTITY_FORMAT_VERSION);
        id_subject.insert("fingerprint", ByteString::from(bogus_fp.to_vec()));
        let id_env = Envelope::new(CBOR::from(id_subject))
            .add_assertion("name", "alice")
            .add_assertion("created", CBOR::to_tagged_value(Tag::with_value(1), 1u64))
            .add_assertion("ed25519-public", ByteString::from(ed_public.clone()))
            .add_assertion("ed25519-secret", ByteString::from(vec![0xAA; 32]))
            .add_assertion("ml-dsa-public", ByteString::from(vec![0xBB; 16]))
            .add_assertion("ml-dsa-secret", ByteString::from(vec![0xCC; 32]))
            .add_assertion("pre-backend", "mock")
            .add_assertion("pre-public", ByteString::from(vec![0xDD; 8]))
            .add_assertion("pre-secret", ByteString::from(vec![0xEE; 16]));

        let mut w_subject = Map::new();
        w_subject.insert("type", WALLET_TYPE);
        w_subject.insert("format-version", WALLET_FORMAT_VERSION);
        let envelope = Envelope::new(CBOR::from(w_subject)).add_assertion("identity", id_env);

        let bytes = envelope.to_cbor_data();
        let err = from_envelope(&bytes).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("fingerprint does not match"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn decode_rejects_wrong_wallet_type() {
        let mut subject = Map::new();
        subject.insert("type", "recrypt.identity"); // wrong!
        subject.insert("format-version", WALLET_FORMAT_VERSION);
        let env = Envelope::new(CBOR::from(subject));
        let bytes = env.to_cbor_data();
        let err = from_envelope(&bytes).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Expected wallet type"), "unexpected: {msg}");
    }

    #[test]
    fn decode_rejects_wrong_format_version() {
        let mut subject = Map::new();
        subject.insert("type", WALLET_TYPE);
        subject.insert("format-version", 99u32);
        let env = Envelope::new(CBOR::from(subject));
        let bytes = env.to_cbor_data();
        let err = from_envelope(&bytes).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Unsupported wallet envelope format-version"),
            "unexpected: {msg}"
        );
    }

    #[test]
    fn pre_backend_string_roundtrip() {
        // Cover both Mock and Lattice variants — exercises both branches of
        // BackendId::from_str on decode.
        for backend in [BackendId::Mock, BackendId::Lattice] {
            let (name, mut identity) = mock_identity("alice", 1);
            identity.pre_backend = backend;
            let mut wallet = WalletData {
                identities: HashMap::new(),
                active_identity: None,
            };
            wallet.identities.insert(name.clone(), identity);

            let bytes = to_envelope(&wallet).unwrap();
            let decoded = from_envelope(&bytes).unwrap();
            assert_eq!(
                decoded.identities[&name].pre_backend, backend,
                "backend {backend} did not roundtrip"
            );
        }
    }
}
