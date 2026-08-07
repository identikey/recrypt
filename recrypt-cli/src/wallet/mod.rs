//! Recrypt's wallet: the generic `identikey-wallet` engine with Recrypt's
//! identity type layered on top.
//!
//! The encrypted file format (`IKEYW` v2), OS keychain caching, and the
//! Gordian Envelope container all live in the `identikey-wallet` crate.
//! This module supplies what is Recrypt-specific:
//!
//! - [`RECRYPT_PARAMS`] — the `recrypt.wallet` envelope type, the `recrypt`
//!   keychain service, and the `RECRYPT_*` environment variables, all
//!   byte/behavior-compatible with wallets written before the extraction.
//! - [`Identity`] — Ed25519 + ML-DSA-87 + PRE keypairs. Its envelope codec
//!   delegates to `recrypt_wire::Identity`, so wallet bytes stay identical
//!   to on-the-wire identity envelopes (spec:
//!   wallet-envelope-format.md in the identikey-protocol repo, docs/standards/).

use anyhow::{anyhow, Context as _, Result};
use bc_envelope::prelude::*;
use std::str::FromStr;
use zeroize::ZeroizeOnDrop;

use recrypt_core::pre::BackendId;
use recrypt_wire::{Identity as WireIdentity, MlDsaKeyPair, MultiFormat as _, PreKeyMaterial};

pub use identikey_wallet::{write_secret_file, CredentialProvider, KeyPair, WalletParams};
use identikey_wallet::WalletIdentity;

/// Recrypt's wallet parameters. `wallet_type`, keychain service, env var
/// names, and the v1 rejection string are all load-bearing compatibility
/// surfaces — do not change them without a format-version bump.
pub const RECRYPT_PARAMS: WalletParams = WalletParams {
    wallet_type: "recrypt.wallet",
    format_version: 2,
    keychain_service: "recrypt",
    env_password: "RECRYPT_WALLET_PASSWORD",
    env_key: "RECRYPT_WALLET_KEY",
    env_no_keychain: "RECRYPT_NO_KEYCHAIN",
    v1_rejection_msg:
        "Wallet format v1 is no longer supported. Create a new wallet with `recrypt identity new`.",
    dir_qualifier: "io",
    dir_organization: "identikey",
    dir_application: "recrypt",
    wallet_file_name: "wallet.ikeyw",
};

pub type Wallet = identikey_wallet::Wallet<Identity>;

/// Credential-provider selection with Recrypt's params (RECRYPT_NO_KEYCHAIN,
/// RECRYPT_WALLET_KEY, keychain service "recrypt").
pub mod credential {
    use super::RECRYPT_PARAMS;
    pub use identikey_wallet::CredentialProvider;

    pub fn default_provider_for(
        wallet_path: &std::path::Path,
    ) -> Box<dyn CredentialProvider> {
        identikey_wallet::default_provider_for(wallet_path, &RECRYPT_PARAMS)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, ZeroizeOnDrop)]
pub struct Identity {
    #[zeroize(skip)]
    pub created_at: u64,
    /// Blake3(ed25519_public). Raw bytes; encode with bs58 for display/wire.
    #[zeroize(skip)]
    pub fingerprint: [u8; 32],
    pub ed25519: KeyPair,
    pub ml_dsa: KeyPair,
    pub pre: KeyPair,
    #[zeroize(skip)]
    pub pre_backend: BackendId,
    /// Identity-level assertions not in the wire crate's `KNOWN_PREDICATES`.
    /// Round-tripped through `recrypt_wire::Identity::unknown_assertions` so
    /// additive spec extensions survive a wallet load+save (§8 forward-compat).
    #[serde(skip)]
    #[zeroize(skip)]
    pub unknown_assertions: Vec<(Envelope, Envelope)>,
}

impl WalletIdentity for Identity {
    const PARAMS: &'static WalletParams = &RECRYPT_PARAMS;

    /// Build an identity envelope by delegating to `recrypt_wire::Identity`.
    ///
    /// This guarantees byte-identical encoding between wallet-stored
    /// identities and on-the-wire identity envelopes for the same content.
    fn to_envelope(&self, name: &str) -> Result<Envelope> {
        let wire_id = wallet_to_wire_identity(name, self)?;
        let bytes = wire_id
            .to_envelope()
            .map_err(|e| anyhow!("identity envelope encoding failed: {e}"))?;
        Envelope::try_from_cbor_data(bytes)
            .map_err(|e| anyhow!("identity envelope re-parse failed: {e}"))
    }

    /// Round-trip through the wire crate: serialize the inner envelope to
    /// bytes, parse via `recrypt_wire::Identity::from_envelope_bytes`, then
    /// map back. This shares all subject/assertion/fingerprint validation
    /// with the wire path — one source of truth.
    fn from_envelope(envelope: &Envelope) -> Result<(String, Self)> {
        let bytes = envelope.to_cbor_data();
        let wire_id = WireIdentity::from_envelope_bytes(&bytes)
            .map_err(|e| anyhow!("identity envelope decode failed: {e}"))?;
        wire_to_wallet_identity(wire_id)
    }
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
pub(crate) fn test_identity(seed: u8) -> Identity {
    let ed_public = vec![seed; 32];
    let fingerprint = *blake3::hash(&ed_public).as_bytes();
    Identity {
        created_at: 1_704_067_200,
        fingerprint,
        ed25519: KeyPair {
            public: ed_public,
            secret: vec![seed.wrapping_add(1); 32],
        },
        ml_dsa: KeyPair {
            public: vec![seed.wrapping_add(2); 16],
            secret: vec![seed.wrapping_add(3); 32],
        },
        pre: KeyPair {
            public: vec![seed.wrapping_add(4); 8],
            secret: vec![seed.wrapping_add(5); 16],
        },
        pre_backend: BackendId::Mock,
        unknown_assertions: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identikey_wallet::format::{
        decrypt_wallet_with_key, encrypt_wallet_with_key, extract_salt,
    };
    use identikey_wallet::WalletData;
    use std::collections::HashMap;

    fn assert_wallet_eq(a: &WalletData<Identity>, b: &WalletData<Identity>) {
        assert_eq!(a.active_identity, b.active_identity, "active-identity");
        assert_eq!(a.identities.len(), b.identities.len(), "identity count");
        for (name, id_a) in &a.identities {
            let id_b = b
                .identities
                .get(name)
                .unwrap_or_else(|| panic!("missing identity {name} after roundtrip"));
            assert_eq!(id_a.created_at, id_b.created_at, "{name}: created_at");
            assert_eq!(id_a.fingerprint, id_b.fingerprint, "{name}: fingerprint");
            assert_eq!(id_a.ed25519.public, id_b.ed25519.public, "{name}: ed pub");
            assert_eq!(id_a.ed25519.secret, id_b.ed25519.secret, "{name}: ed sec");
            assert_eq!(id_a.ml_dsa.public, id_b.ml_dsa.public, "{name}: ml_dsa pub");
            assert_eq!(id_a.ml_dsa.secret, id_b.ml_dsa.secret, "{name}: ml_dsa sec");
            assert_eq!(id_a.pre.public, id_b.pre.public, "{name}: pre pub");
            assert_eq!(id_a.pre.secret, id_b.pre.secret, "{name}: pre sec");
            assert_eq!(id_a.pre_backend, id_b.pre_backend, "{name}: pre_backend");
        }
    }

    /// The wallet's per-identity bytes MUST match what the wire crate would
    /// produce for the same identity content. This is the contract that
    /// makes `recrypt_wire::Identity` the single source of truth for
    /// `recrypt.identity` envelope encoding.
    #[test]
    fn wallet_identity_bytes_match_wire() {
        let identity = test_identity(42);
        let wire_id = wallet_to_wire_identity("alice", &identity).unwrap();
        let wire_bytes = wire_id.to_envelope().unwrap();

        let wallet_id_envelope = WalletIdentity::to_envelope(&identity, "alice").unwrap();
        let wallet_bytes = wallet_id_envelope.to_cbor_data();

        assert_eq!(
            wallet_bytes, wire_bytes,
            "wallet identity envelope bytes must equal recrypt-wire identity envelope bytes"
        );
    }

    #[test]
    fn container_roundtrip_with_recrypt_params() {
        let mut wallet: WalletData<Identity> = WalletData::new();
        wallet.active_identity = Some("bob".to_string());
        for (name, seed) in [("alice", 1u8), ("bob", 2), ("carol", 3)] {
            let mut id = test_identity(seed);
            // Distinct ed25519 keys → distinct valid fingerprints.
            id.ed25519.public = vec![seed; 32];
            id.fingerprint = *blake3::hash(&id.ed25519.public).as_bytes();
            wallet.identities.insert(name.to_string(), id);
        }

        let key = [0x42u8; 32];
        let salt = [0x24u8; 32];
        let encrypted = encrypt_wallet_with_key(&wallet, &key, &salt, &RECRYPT_PARAMS).unwrap();
        let decrypted: WalletData<Identity> =
            decrypt_wallet_with_key(&encrypted, &key, &RECRYPT_PARAMS).unwrap();
        assert_wallet_eq(&wallet, &decrypted);
    }

    /// The spec'd exact v1 rejection string (identikey-protocol,
    /// docs/standards/wallet-envelope-format.md §7)
    /// must survive the extraction into the generic wallet crate.
    #[test]
    fn v1_wallet_rejected_with_spec_string() {
        let mut data = Vec::new();
        data.extend_from_slice(b"IKEYW");
        data.push(1u8);
        data.extend_from_slice(&[0u8; 32]); // salt
        data.extend_from_slice(&[0u8; 24]); // nonce
        data.extend_from_slice(&[0u8; 16]); // ciphertext

        let msg = extract_salt(&data, &RECRYPT_PARAMS).unwrap_err().to_string();
        assert_eq!(
            msg,
            "Wallet format v1 is no longer supported. Create a new wallet with `recrypt identity new`."
        );
    }

    /// Identity-level unknown assertions must survive a container
    /// round-trip via `recrypt_wire::Identity::unknown_assertions`.
    #[test]
    fn identity_level_unknown_assertion_roundtrips() {
        let mut identity = test_identity(9);
        identity.unknown_assertions.push((
            Envelope::new("recovery-share"),
            Envelope::new("future-share-blob"),
        ));
        let mut wallet: WalletData<Identity> = WalletData {
            identities: HashMap::new(),
            active_identity: Some("alice".to_string()),
            unknown_assertions: Vec::new(),
        };
        wallet.identities.insert("alice".to_string(), identity);

        let key = [0x12u8; 32];
        let salt = [0x34u8; 32];
        let bytes = encrypt_wallet_with_key(&wallet, &key, &salt, &RECRYPT_PARAMS).unwrap();
        let decoded: WalletData<Identity> =
            decrypt_wallet_with_key(&bytes, &key, &RECRYPT_PARAMS).unwrap();
        let id_decoded = decoded.identities.get("alice").expect("identity missing");
        assert_eq!(
            id_decoded.unknown_assertions.len(),
            1,
            "identity-level unknown assertion was dropped"
        );
    }
}
