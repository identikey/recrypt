//! Gordian Envelope encode/decode for wallet body.
//!
//! Spec: docs/standards/wallet-envelope-format.md (§3.1, §3.2, §8).
//!
//! Each identity inside the wallet is encoded by `recrypt_wire::Identity` —
//! the same encoder used for on-the-wire identity envelopes. This guarantees
//! the bytes for a given identity are byte-identical whether the identity is
//! sitting in a wallet on disk or being shipped over HTTP. See
//! `recrypt-cli/src/wallet/envelope.rs::tests::wallet_identity_bytes_match_wire`.
//!
//! ## §8 forward-compatibility: unknown assertions
//!
//! The wallet envelope decoder collects any wallet-level assertion whose
//! predicate is not in [`KNOWN_PREDICATES`] into `WalletData::unknown_assertions`,
//! and re-emits them in their original order on encode. Identity-level unknowns
//! are round-tripped through `recrypt_wire::Identity::unknown_assertions`,
//! which uses the same pattern in `crates/recrypt-wire/src/identity.rs`.
//! This preserves additive spec extensions (e.g. `keyspace-membership`,
//! `recovery-share`) across a load+save by an older client that doesn't
//! understand them.

use anyhow::{anyhow, Context as _, Result};
use bc_envelope::prelude::*;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::OnceLock;

use recrypt_core::pre::BackendId;
use recrypt_wire::{Identity as WireIdentity, MlDsaKeyPair, MultiFormat, PreKeyMaterial};

use super::format::{Identity, KeyPair, WalletData};

const WALLET_TYPE: &str = "recrypt.wallet";
const WALLET_FORMAT_VERSION: u32 = 2;

/// Wallet-level predicates the encoder/decoder recognizes. Any other predicate
/// is treated as an unknown forward-compat assertion (§8) and round-tripped
/// verbatim via `WalletData::unknown_assertions`.
const KNOWN_PREDICATES: &[&str] = &["active-identity", "identity"];

fn known_predicate_digests() -> &'static [Digest] {
    static CELL: OnceLock<Vec<Digest>> = OnceLock::new();
    CELL.get_or_init(|| {
        KNOWN_PREDICATES
            .iter()
            .map(|p| Envelope::new(*p).digest())
            .collect()
    })
}

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

    // Re-emit unknown wallet-level assertions in their original order so
    // additive spec extensions (§8) survive a load+save round-trip.
    for (pred, obj) in &wallet.unknown_assertions {
        let assertion = Envelope::new_assertion(pred.clone(), obj.clone());
        envelope = envelope
            .add_assertion_envelope(assertion)
            .map_err(|e| anyhow!("add unknown wallet assertion: {e}"))?;
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
        return Err(anyhow!("Expected wallet type '{WALLET_TYPE}', got '{ty}'"));
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

    let known = known_predicate_digests();
    let mut identities: HashMap<String, Identity> = HashMap::new();
    let mut unknown_assertions: Vec<(Envelope, Envelope)> = Vec::new();
    for assertion in envelope.assertions() {
        let (pred, obj) = match (assertion.as_predicate(), assertion.as_object()) {
            (Some(p), Some(o)) => (p, o),
            _ => continue,
        };

        if !known.contains(&pred.digest()) {
            unknown_assertions.push((pred, obj));
            continue;
        }

        // Known predicate. `active-identity` was already extracted above; we
        // only need to dispatch the `identity` arm here.
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
        let (name, identity) = identity_from_envelope(&obj)?;
        if identities.insert(name.clone(), identity).is_some() {
            return Err(anyhow!("Duplicate identity name: {name}"));
        }
    }

    Ok(WalletData {
        identities,
        active_identity,
        unknown_assertions,
    })
}

/// Build an identity envelope by delegating to `recrypt_wire::Identity`.
///
/// This guarantees byte-identical encoding between wallet-stored identities
/// and on-the-wire identity envelopes for the same content.
fn identity_to_envelope(name: &str, id: &Identity) -> Result<Envelope> {
    let wire_id = wallet_to_wire_identity(name, id)?;
    let bytes = wire_id
        .to_envelope()
        .map_err(|e| anyhow!("identity envelope encoding failed: {e}"))?;
    Envelope::try_from_cbor_data(bytes)
        .map_err(|e| anyhow!("identity envelope re-parse failed: {e}"))
}

fn identity_from_envelope(envelope: &Envelope) -> Result<(String, Identity)> {
    // Round-trip through wire crate: serialize the inner envelope to bytes,
    // parse via `recrypt_wire::Identity::from_envelope_bytes`, then map back.
    // This shares all subject/assertion/fingerprint validation with the wire
    // path — one source of truth.
    let bytes = envelope.to_cbor_data();
    let wire_id = WireIdentity::from_envelope_bytes(&bytes)
        .map_err(|e| anyhow!("identity envelope decode failed: {e}"))?;
    wire_to_wallet_identity(wire_id)
}

fn wallet_to_wire_identity(name: &str, id: &Identity) -> Result<WireIdentity> {
    let ed25519_public: [u8; 32] = id
        .ed25519
        .public
        .as_slice()
        .try_into()
        .with_context(|| format!("identity '{name}': ed25519 public must be 32 bytes"))?;
    let ed25519_secret: [u8; 32] = id
        .ed25519
        .secret
        .as_slice()
        .try_into()
        .with_context(|| format!("identity '{name}': ed25519 secret must be 32 bytes"))?;

    Ok(WireIdentity {
        fingerprint: id.fingerprint,
        ed25519_public,
        ed25519_secret: Some(ed25519_secret),
        name: Some(name.to_string()),
        created: Some(id.created_at),
        ml_dsa: Some(MlDsaKeyPair {
            public: id.ml_dsa.public.clone(),
            secret: Some(id.ml_dsa.secret.clone()),
        }),
        pre: Some(PreKeyMaterial {
            backend: id.pre_backend.to_string(),
            public: id.pre.public.clone(),
            secret: Some(id.pre.secret.clone()),
        }),
        unknown_assertions: id.unknown_assertions.clone(),
    })
}

fn wire_to_wallet_identity(wire: WireIdentity) -> Result<(String, Identity)> {
    let name = wire
        .name
        .clone()
        .ok_or_else(|| anyhow!("wallet identity envelope is missing 'name' assertion"))?;
    let created_at = wire
        .created
        .ok_or_else(|| anyhow!("wallet identity '{name}' missing 'created' assertion"))?;
    let ed25519_secret = wire
        .ed25519_secret
        .ok_or_else(|| anyhow!("wallet identity '{name}' missing 'ed25519-secret'"))?;
    let ml_dsa = wire
        .ml_dsa
        .clone()
        .ok_or_else(|| anyhow!("wallet identity '{name}' missing ml-dsa key material"))?;
    let ml_dsa_secret = ml_dsa
        .secret
        .clone()
        .ok_or_else(|| anyhow!("wallet identity '{name}' missing 'ml-dsa-secret'"))?;
    let pre = wire
        .pre
        .clone()
        .ok_or_else(|| anyhow!("wallet identity '{name}' missing pre key material"))?;
    let pre_secret = pre
        .secret
        .clone()
        .ok_or_else(|| anyhow!("wallet identity '{name}' missing 'pre-secret'"))?;
    let pre_backend = BackendId::from_str(&pre.backend).map_err(|e| {
        anyhow!(
            "identity '{name}': unknown pre-backend '{}': {e}",
            pre.backend
        )
    })?;

    let identity = Identity {
        created_at,
        fingerprint: wire.fingerprint,
        ed25519: KeyPair {
            public: wire.ed25519_public.to_vec(),
            secret: ed25519_secret.to_vec(),
        },
        ml_dsa: KeyPair {
            public: ml_dsa.public.clone(),
            secret: ml_dsa_secret,
        },
        pre: KeyPair {
            public: pre.public.clone(),
            secret: pre_secret,
        },
        pre_backend,
        unknown_assertions: wire.unknown_assertions.clone(),
    };
    Ok((name, identity))
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
            unknown_assertions: Vec::new(),
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
                "{name}: ed25519 pub"
            );
            assert_eq!(
                id_a.ed25519.secret, id_b.ed25519.secret,
                "{name}: ed25519 sec"
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
            unknown_assertions: Vec::new(),
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
            unknown_assertions: Vec::new(),
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
            unknown_assertions: Vec::new(),
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
            unknown_assertions: Vec::new(),
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
            unknown_assertions: Vec::new(),
        };
        wallet.identities.insert(name, identity);

        let err = to_envelope(&wallet).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.to_lowercase().contains("fingerprint"),
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
        // Cover both Mock and Lattice — exercises both branches of
        // BackendId::from_str on decode.
        for backend in [BackendId::Mock, BackendId::Lattice] {
            let (name, mut identity) = mock_identity("alice", 1);
            identity.pre_backend = backend;
            let mut wallet = WalletData {
                identities: HashMap::new(),
                active_identity: None,
                unknown_assertions: Vec::new(),
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

    /// The wallet's per-identity bytes MUST match what the wire crate would
    /// produce for the same identity content. This is the contract that
    /// makes `recrypt_wire::Identity` the single source of truth for
    /// `recrypt.identity` envelope encoding.
    #[test]
    fn wallet_identity_bytes_match_wire() {
        let (name, identity) = mock_identity("alice", 42);
        let wire_id = wallet_to_wire_identity(&name, &identity).unwrap();
        let wire_bytes = wire_id.to_envelope().unwrap();

        let wallet_id_envelope = identity_to_envelope(&name, &identity).unwrap();
        let wallet_bytes = wallet_id_envelope.to_cbor_data();

        assert_eq!(
            wallet_bytes, wire_bytes,
            "wallet identity envelope bytes must equal recrypt-wire identity envelope bytes"
        );
    }

    /// §8 forward-compat: a wallet-level assertion with an unknown predicate
    /// (e.g. a future `keyspace-membership` extension) must survive a
    /// load+save round-trip — both decoded into `unknown_assertions` and
    /// re-emitted byte-stably on encode.
    #[test]
    fn wallet_level_unknown_assertion_roundtrips() {
        let wallet = WalletData {
            identities: HashMap::new(),
            active_identity: None,
            unknown_assertions: vec![(
                Envelope::new("keyspace-membership"),
                Envelope::new("future-namespace-value"),
            )],
        };

        let bytes = to_envelope(&wallet).unwrap();
        let decoded = from_envelope(&bytes).unwrap();
        assert_eq!(
            decoded.unknown_assertions.len(),
            1,
            "wallet-level unknown assertion was dropped on decode"
        );
        let pred_text: String = decoded.unknown_assertions[0]
            .0
            .clone()
            .try_leaf()
            .unwrap()
            .try_into_text()
            .unwrap();
        assert_eq!(pred_text, "keyspace-membership");

        let bytes_again = to_envelope(&decoded).unwrap();
        assert_eq!(
            bytes, bytes_again,
            "wallet-level unknowns are not byte-stable across load+save"
        );
    }

    /// §8 forward-compat: an identity-level assertion with an unknown
    /// predicate (e.g. a future `recovery-share` extension) must survive a
    /// wallet load+save by round-tripping through
    /// `recrypt_wire::Identity::unknown_assertions`.
    #[test]
    fn identity_level_unknown_assertion_roundtrips() {
        let (name, mut identity) = mock_identity("alice", 9);
        identity.unknown_assertions.push((
            Envelope::new("recovery-share"),
            Envelope::new("future-share-blob"),
        ));
        let mut wallet = WalletData {
            identities: HashMap::new(),
            active_identity: Some(name.clone()),
            unknown_assertions: Vec::new(),
        };
        wallet.identities.insert(name.clone(), identity);

        let bytes = to_envelope(&wallet).unwrap();
        let decoded = from_envelope(&bytes).unwrap();
        let id_decoded = decoded
            .identities
            .get(&name)
            .expect("identity missing after roundtrip");
        assert_eq!(
            id_decoded.unknown_assertions.len(),
            1,
            "identity-level unknown assertion was dropped on decode"
        );
        let pred_text: String = id_decoded.unknown_assertions[0]
            .0
            .clone()
            .try_leaf()
            .unwrap()
            .try_into_text()
            .unwrap();
        assert_eq!(pred_text, "recovery-share");

        let bytes_again = to_envelope(&decoded).unwrap();
        assert_eq!(
            bytes, bytes_again,
            "identity-level unknowns are not byte-stable across load+save"
        );
    }
}
