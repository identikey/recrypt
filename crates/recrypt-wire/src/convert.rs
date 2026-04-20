//! Conversions between recrypt-core types and Gordian Envelope representations.

use bc_envelope::prelude::*;
use crate::error::{WireError, WireResult};
use recrypt_core::hybrid::EncryptedFile;
use recrypt_core::pre::{BackendId, Ciphertext};
use recrypt_core::sign::MultiSig;

// ---------------------------------------------------------------------------
// BackendId ↔ string
// ---------------------------------------------------------------------------

pub fn backend_to_string(id: BackendId) -> &'static str {
    match id {
        BackendId::Lattice => "lattice-bfv",
        BackendId::EcPairing => "ec-pairing",
        BackendId::EcSecp256k1 => "ec-secp256k1",
        BackendId::Mock => "mock",
    }
}

pub fn backend_from_string(s: &str) -> WireResult<BackendId> {
    match s {
        "lattice-bfv" => Ok(BackendId::Lattice),
        "ec-pairing" => Ok(BackendId::EcPairing),
        "ec-secp256k1" => Ok(BackendId::EcSecp256k1),
        "mock" => Ok(BackendId::Mock),
        _ => Err(WireError::InvalidFormat(format!("Unknown backend: {s}"))),
    }
}

// ---------------------------------------------------------------------------
// EncryptedFile → Envelope (wire-protocol.md §3.1)
// ---------------------------------------------------------------------------

pub fn encrypted_file_to_envelope(
    ef: &EncryptedFile,
    owner_fingerprint: Option<&[u8; 32]>,
) -> Envelope {
    let mut subject = Map::new();
    subject.insert("type", "recrypt.encrypted-file");
    subject.insert("format-version", 3_u32);
    subject.insert("bao-hash", ByteString::from(ef.bao_hash.to_vec()));

    let mut envelope = Envelope::new(CBOR::from(subject))
        .add_assertion_salted("backend", backend_to_string(ef.wrapped_key.backend()), true);

    if let Some(fp) = owner_fingerprint {
        envelope = envelope.add_assertion("owner", ByteString::from(fp.to_vec()));
    }

    // Inline the wrapped-key ciphertext bytes and its metadata.
    // For server-mediated flows these would be separate objects, but for
    // local CLI encrypt/decrypt and on-disk storage, they're inline.
    let wrapped_key_bytes = ef.wrapped_key.to_bytes();
    if !wrapped_key_bytes.is_empty() {
        envelope = envelope.add_assertion(
            "wrapped-key",
            ByteString::from(wrapped_key_bytes),
        );
    }

    // Inline the ciphertext bytes for local file storage.
    // For S3-backed server flows, this would be a content-addressed sidecar
    // referenced by bao-hash; the ciphertext assertion would be absent.
    if !ef.ciphertext.is_empty() {
        envelope = envelope.add_assertion(
            "ciphertext",
            ByteString::from(ef.ciphertext.clone()),
        );
    }

    envelope
}

pub fn encrypted_file_from_envelope(envelope: &Envelope) -> WireResult<(EncryptedFile, BackendId)> {
    // Get the subject CBOR → Map
    let subject_cbor = envelope
        .subject()
        .try_leaf()
        .map_err(|e| WireError::Envelope(format!("extract subject leaf: {e}")))?;

    let subject = match subject_cbor.into_case() {
        CBORCase::Map(m) => m,
        other => {
            return Err(WireError::Envelope(format!(
                "subject is not a map: {:?}",
                CBOR::from(other)
            )));
        }
    };

    // Verify type field
    let ty: String = subject
        .get("type")
        .ok_or_else(|| WireError::MissingField("type".into()))?;
    if ty != "recrypt.encrypted-file" {
        return Err(WireError::WrongType {
            expected: "recrypt.encrypted-file".into(),
            actual: ty,
        });
    }

    // Verify version
    let version: u32 = subject
        .get("format-version")
        .ok_or_else(|| WireError::MissingField("format-version".into()))?;
    if version != 3 {
        return Err(WireError::VersionMismatch {
            expected: 3,
            actual: version,
        });
    }

    // Extract bao-hash (32 bytes)
    let bao_hash_bs: ByteString = subject
        .get("bao-hash")
        .ok_or_else(|| WireError::MissingField("bao-hash".into()))?;
    let bao_hash: [u8; 32] = bao_hash_bs
        .to_vec()
        .try_into()
        .map_err(|_| WireError::InvalidFormat("bao-hash must be 32 bytes".into()))?;

    // Extract backend from assertions
    let backend_str: String = envelope
        .extract_object_for_predicate("backend")
        .map_err(|_| WireError::MissingField("backend assertion".into()))?;
    let backend = backend_from_string(&backend_str)?;

    // Extract inline wrapped-key if present (local file storage mode).
    // For server-mediated flows this assertion is absent — the wrapped-key
    // is a separate object discovered via the auth service.
    let wrapped_key = match envelope.extract_object_for_predicate::<ByteString>("wrapped-key") {
        Ok(bs) => Ciphertext::from_bytes(&bs.to_vec())
            .map_err(|e| WireError::InvalidFormat(format!("wrapped-key: {e}")))?,
        Err(_) => Ciphertext::new(backend, 0, Vec::new()),
    };

    // Extract inline ciphertext if present (local file storage mode).
    // For server-mediated flows this is absent — the ciphertext lives in
    // a content-addressed S3 sidecar identified by bao-hash.
    let ciphertext = match envelope.extract_object_for_predicate::<ByteString>("ciphertext") {
        Ok(bs) => bs.to_vec(),
        Err(_) => Vec::new(),
    };

    let ef = EncryptedFile {
        wrapped_key,
        bao_hash,
        ciphertext,
        signature: None,
    };

    Ok((ef, backend))
}

// ---------------------------------------------------------------------------
// MultiSig byte helpers
// ---------------------------------------------------------------------------

pub fn multisig_ed25519_bytes(sig: &MultiSig) -> Vec<u8> {
    sig.ed25519_sig.to_bytes().to_vec()
}

pub fn multisig_mldsa_bytes(sig: &MultiSig) -> Option<Vec<u8>> {
    sig.ml_dsa_sig.clone()
}
