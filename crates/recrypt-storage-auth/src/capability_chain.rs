//! Delegation chain verification for [`Capability`].
//!
//! `Capability` carries an optional `parent` digest pointing at a
//! parent capability's wrapped envelope. This module walks that chain
//! and confirms each delegation step is well-formed: signatures
//! verify, the entity that signed the child was the one the parent
//! delegated to, permissions are attenuated (never expanded), expiries
//! never extend, and the resource doesn't change. See
//! [`docs/decisions/2026-04-29-capability-chain-decisions.md`](../../../../docs/decisions/2026-04-29-capability-chain-decisions.md).
//!
//! # Library boundary
//!
//! Verification is I/O-free. Callers supply:
//! - **`issuer_keys_for`**: a closure mapping issuer fingerprint to
//!   that issuer's public keys (typically a lookup against `/accounts`).
//! - **`resolver`**: a [`ParentResolver`] mapping a parent digest to
//!   that parent's signed envelope bytes. The in-tree implementation
//!   [`BundledResolver`] holds parents in memory; an HTTP-backed
//!   resolver is a planned reversal trigger (see decision doc).
//!
//! # What this module does **not** check
//!
//! - **Root authority over the resource.** Whether the root issuer
//!   (the capability with `parent: None`) is actually the entity who
//!   may grant access to `subject` is a route-handler policy. Typical
//!   server policy: root issuer must be a registered account who owns
//!   the file (or holds the keyspace, etc.).
//! - **Leaf permission for the requested operation.** Use
//!   [`Capability::verify_full`] for that — chain verification only
//!   guarantees the leaf's permissions are a valid attenuation of an
//!   authorized chain.

use std::collections::HashMap;

use recrypt_core::sign::{VerifyPolicy, VerifyingKeys};

use crate::capability::Capability;
use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;

/// Look up the signed-envelope bytes of a parent capability by the
/// digest stored in a child's `parent` field
/// (`wrap().subject().digest()` of the parent envelope).
pub trait ParentResolver {
    fn resolve(&self, digest: &[u8; 32]) -> Option<&[u8]>;
}

/// Resolver backed by a `HashMap` of parent envelope bytes the holder
/// shipped alongside the leaf.
///
/// Use [`BundledResolver::from_envelopes`] to build one from a list of
/// signed parent envelopes; it computes each digest via
/// [`Capability::wrapped_subject_digest`] so callers don't have to.
#[derive(Default)]
pub struct BundledResolver {
    by_digest: HashMap<[u8; 32], Vec<u8>>,
}

impl BundledResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a parent envelope under an explicit digest. Prefer
    /// [`Self::from_envelopes`] or [`Self::insert_envelope`] — they
    /// derive the digest for you.
    pub fn insert_with_digest(&mut self, digest: [u8; 32], envelope_bytes: Vec<u8>) {
        self.by_digest.insert(digest, envelope_bytes);
    }

    /// Insert a parent envelope, computing its digest automatically.
    pub fn insert_envelope(&mut self, envelope_bytes: Vec<u8>) -> AuthResult<()> {
        let digest = Capability::wrapped_subject_digest(&envelope_bytes)?;
        self.by_digest.insert(digest, envelope_bytes);
        Ok(())
    }

    /// Build a resolver from an iterator of signed parent envelopes.
    pub fn from_envelopes<I, B>(envelopes: I) -> AuthResult<Self>
    where
        I: IntoIterator<Item = B>,
        B: Into<Vec<u8>>,
    {
        let mut me = Self::new();
        for env in envelopes {
            me.insert_envelope(env.into())?;
        }
        Ok(me)
    }
}

impl ParentResolver for BundledResolver {
    fn resolve(&self, digest: &[u8; 32]) -> Option<&[u8]> {
        self.by_digest.get(digest).map(|v| v.as_slice())
    }
}

/// Knobs for [`verify_chain`].
#[derive(Clone, Debug)]
pub struct ChainPolicy {
    /// Maximum total number of capabilities in the chain (leaf + all
    /// ancestors). Default: 8.
    pub max_depth: usize,
    /// Signature policy applied at every step. Default:
    /// [`VerifyPolicy::PqRequired`].
    pub signature_policy: VerifyPolicy,
}

impl Default for ChainPolicy {
    fn default() -> Self {
        Self {
            max_depth: 8,
            signature_policy: VerifyPolicy::PqRequired,
        }
    }
}

/// Verify a delegation chain from the leaf back to its self-signed root.
///
/// Returns the parsed chain, leaf-first (root last). On success every
/// step has been signature-checked against `issuer_keys_for(issuer)`,
/// and the relationships listed in the decision doc (granted-to /
/// issuer linkage, permission attenuation, subject identity, expiry
/// monotonicity, parent must permit `Delegate`) all hold.
///
/// On failure, the error indicates which invariant broke. The walk is
/// short-circuiting; the returned `Vec` is dropped.
pub fn verify_chain(
    leaf_envelope_bytes: &[u8],
    issuer_keys_for: &dyn Fn(&PublicKeyFingerprint) -> Option<VerifyingKeys>,
    resolver: &dyn ParentResolver,
    policy: &ChainPolicy,
) -> AuthResult<Vec<Capability>> {
    use crate::keyspace::Permission;

    let mut chain: Vec<Capability> = Vec::new();
    let mut current_bytes: Vec<u8> = leaf_envelope_bytes.to_vec();

    loop {
        if chain.len() >= policy.max_depth {
            return Err(AuthError::ChainTooDeep {
                max: policy.max_depth,
            });
        }

        let issuer_fp = Capability::peek_issuer(&current_bytes)?;
        let keys = issuer_keys_for(&issuer_fp).ok_or_else(|| {
            AuthError::UnknownIssuer(format!("no keys registered for issuer {issuer_fp}"))
        })?;
        let cap = Capability::verify(&current_bytes, &keys, policy.signature_policy)?;

        // If we already pushed a child, validate the (parent, child)
        // relationship now that we've parsed and signature-verified
        // the parent.
        if let Some(child) = chain.last() {
            if cap.granted_to != child.issuer {
                return Err(AuthError::ChainInvalid(
                    "parent.granted_to does not match child.issuer".into(),
                ));
            }
            if !cap.permits(Permission::Delegate) {
                return Err(AuthError::ChainInvalid(
                    "parent does not permit Delegate".into(),
                ));
            }
            if !child.permissions.is_subset(&cap.permissions) {
                return Err(AuthError::ChainInvalid(
                    "child permissions are not a subset of parent permissions".into(),
                ));
            }
            if cap.subject != child.subject || cap.subject_kind != child.subject_kind {
                return Err(AuthError::ChainInvalid(
                    "subject or subject_kind changed across delegation".into(),
                ));
            }
            if cap.is_expired() {
                return Err(AuthError::CapabilityExpired);
            }
            // Expiry monotonicity: a child must not outlast its parent.
            // If the parent has a bound, the child must too, and it
            // must not exceed the parent's. An unbounded parent allows
            // any child expiry (or none).
            match (child.expires_at, cap.expires_at) {
                (_, None) => {}
                (None, Some(_)) => {
                    return Err(AuthError::ChainInvalid(
                        "child has no expiry but parent does".into(),
                    ));
                }
                (Some(child_exp), Some(parent_exp)) if child_exp > parent_exp => {
                    return Err(AuthError::ChainInvalid(
                        "child expiry exceeds parent expiry".into(),
                    ));
                }
                (Some(_), Some(_)) => {}
            }
        }

        let parent_digest = cap.parent;
        chain.push(cap);

        match parent_digest {
            None => return Ok(chain),
            Some(d) => {
                let bytes = resolver.resolve(&d).ok_or_else(|| {
                    AuthError::ChainInvalid(format!(
                        "parent envelope not found for digest {}",
                        bs58::encode(d).into_string()
                    ))
                })?;
                current_bytes = bytes.to_vec();
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use recrypt_core::sign::SigningKeys;
    use recrypt_ffi::ed25519::ed25519_keygen;
    use recrypt_ffi::liboqs::{PqAlgorithm, pq_keygen};

    use crate::capability::SubjectKind;
    use crate::keyspace::Permission;

    /// A test principal with both signing and verifying material.
    struct Principal {
        fp: PublicKeyFingerprint,
        signing: SigningKeys,
        verifying: VerifyingKeys,
    }

    fn make_principal() -> Principal {
        let ed = ed25519_keygen();
        let pq = pq_keygen(PqAlgorithm::MlDsa87).unwrap();
        let fp = PublicKeyFingerprint::from_public_key(ed.verifying_key.as_bytes());
        Principal {
            fp,
            signing: SigningKeys {
                ed25519: ed.signing_key,
                ml_dsa: Some(pq.secret_key.clone()),
            },
            verifying: VerifyingKeys {
                ed25519: ed.verifying_key,
                ml_dsa: Some(pq.public_key.clone()),
            },
        }
    }

    /// Build a `issuer_keys_for` closure from a slice of principals.
    fn keys_for<'a>(
        principals: &'a [&'a Principal],
    ) -> impl Fn(&PublicKeyFingerprint) -> Option<VerifyingKeys> + 'a {
        move |fp: &PublicKeyFingerprint| {
            principals
                .iter()
                .find(|p| p.fp == *fp)
                .map(|p| p.verifying.clone())
        }
    }

    fn cap_for(
        issuer: &Principal,
        grantee: &PublicKeyFingerprint,
        permissions: BTreeSet<Permission>,
        expires_at: Option<u64>,
        parent: Option<[u8; 32]>,
    ) -> (Capability, Vec<u8>) {
        let mut cap = Capability::new(
            [7u8; 32],
            SubjectKind::File,
            *grantee,
            issuer.fp,
            permissions,
            expires_at,
        );
        if let Some(p) = parent {
            cap = cap.with_parent(p);
        }
        let bytes = cap.sign(&issuer.signing).unwrap();
        (cap, bytes)
    }

    /// Build a 3-step chain: alice → bob → carol, all on the same
    /// subject, attenuating permissions and expiry along the way.
    fn three_step_chain() -> (Principal, Principal, Principal, Vec<u8>, Vec<Vec<u8>>) {
        let alice = make_principal();
        let bob = make_principal();
        let carol = make_principal();

        // Root: alice grants bob {Read, Delegate}, expiring well in
        // the future so the chain itself is not rejected as expired.
        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read, Permission::Delegate]),
            Some(4_000_000_000),
            None,
        );
        let alice_to_bob_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        // Bob delegates to carol with attenuated expiry; carol gets only Read.
        let (_, bob_to_carol_bytes) = cap_for(
            &bob,
            &carol.fp,
            BTreeSet::from([Permission::Read]),
            Some(3_500_000_000),
            Some(alice_to_bob_digest),
        );

        (
            alice,
            bob,
            carol,
            bob_to_carol_bytes,
            vec![alice_to_bob_bytes],
        )
    }

    #[test]
    fn happy_path_two_link_chain() {
        let (alice, bob, _carol, leaf_bytes, parents) = three_step_chain();
        let resolver = BundledResolver::from_envelopes(parents.clone()).unwrap();
        let principals = [&alice, &bob];
        let lookup = keys_for(&principals);

        let chain =
            verify_chain(&leaf_bytes, &lookup, &resolver, &ChainPolicy::default()).unwrap();

        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].issuer, bob.fp, "leaf should be issued by bob");
        assert_eq!(chain[1].issuer, alice.fp, "root should be issued by alice");
        assert!(chain[1].parent.is_none(), "root must be self-signed");
    }

    #[test]
    fn single_self_signed_capability_is_a_valid_chain() {
        let alice = make_principal();
        let bob_fp = PublicKeyFingerprint::from_bytes([2u8; 32]);
        let (_, bytes) = cap_for(
            &alice,
            &bob_fp,
            BTreeSet::from([Permission::Read]),
            None,
            None,
        );
        let resolver = BundledResolver::new();
        let principals = [&alice];
        let chain =
            verify_chain(&bytes, &keys_for(&principals), &resolver, &ChainPolicy::default())
                .unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn unknown_issuer_rejected() {
        let alice = make_principal();
        let bob_fp = PublicKeyFingerprint::from_bytes([2u8; 32]);
        let (_, bytes) = cap_for(
            &alice,
            &bob_fp,
            BTreeSet::from([Permission::Read]),
            None,
            None,
        );
        let resolver = BundledResolver::new();
        // No principals registered.
        let lookup = keys_for(&[]);
        let err = verify_chain(&bytes, &lookup, &resolver, &ChainPolicy::default()).unwrap_err();
        assert!(matches!(err, AuthError::UnknownIssuer(_)), "got {err:?}");
    }

    #[test]
    fn missing_parent_in_resolver_rejected() {
        let (alice, bob, _carol, leaf_bytes, _parents) = three_step_chain();
        let resolver = BundledResolver::new(); // empty
        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("parent envelope not found")),
            "got {err:?}"
        );
    }

    #[test]
    fn permission_expansion_rejected() {
        let alice = make_principal();
        let bob = make_principal();
        let carol = make_principal();

        // Root: alice grants bob Read+Delegate only.
        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read, Permission::Delegate]),
            None,
            None,
        );
        let parent_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        // Bob illegally tries to grant carol Write — not in his set.
        let (_, leaf_bytes) = cap_for(
            &bob,
            &carol.fp,
            BTreeSet::from([Permission::Read, Permission::Write]),
            None,
            Some(parent_digest),
        );

        let resolver = BundledResolver::from_envelopes(vec![alice_to_bob_bytes]).unwrap();
        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("not a subset")),
            "got {err:?}"
        );
    }

    #[test]
    fn parent_without_delegate_permission_rejected() {
        let alice = make_principal();
        let bob = make_principal();
        let carol = make_principal();

        // Alice grants bob Read but **not** Delegate.
        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read]),
            None,
            None,
        );
        let parent_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        // Bob tries to delegate Read down to carol anyway.
        let (_, leaf_bytes) = cap_for(
            &bob,
            &carol.fp,
            BTreeSet::from([Permission::Read]),
            None,
            Some(parent_digest),
        );

        let resolver = BundledResolver::from_envelopes(vec![alice_to_bob_bytes]).unwrap();
        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("Delegate")),
            "got {err:?}"
        );
    }

    #[test]
    fn granted_to_mismatch_rejected() {
        // Alice grants to bob, but eve (not bob) tries to mint a child
        // claiming bob's parent. Eve's signature won't match the
        // granted-to linkage even if eve is a valid issuer in our
        // lookup table.
        let alice = make_principal();
        let bob = make_principal();
        let eve = make_principal();
        let carol = make_principal();

        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read, Permission::Delegate]),
            None,
            None,
        );
        let parent_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        // Eve signs a leaf citing alice's-grant-to-bob as her parent.
        let (_, leaf_bytes) = cap_for(
            &eve,
            &carol.fp,
            BTreeSet::from([Permission::Read]),
            None,
            Some(parent_digest),
        );

        let resolver = BundledResolver::from_envelopes(vec![alice_to_bob_bytes]).unwrap();
        let principals = [&alice, &bob, &eve];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("granted_to")),
            "got {err:?}"
        );
    }

    #[test]
    fn subject_change_rejected() {
        let alice = make_principal();
        let bob = make_principal();
        let carol = make_principal();

        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read, Permission::Delegate]),
            None,
            None,
        );
        let parent_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        // Bob mints a leaf for a different subject than the parent.
        let mut leaf = Capability::new(
            [9u8; 32], // different from parent's [7u8; 32]
            SubjectKind::File,
            carol.fp,
            bob.fp,
            BTreeSet::from([Permission::Read]),
            None,
        );
        leaf = leaf.with_parent(parent_digest);
        let leaf_bytes = leaf.sign(&bob.signing).unwrap();

        let resolver = BundledResolver::from_envelopes(vec![alice_to_bob_bytes]).unwrap();
        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("subject")),
            "got {err:?}"
        );
    }

    #[test]
    fn expiry_extension_rejected() {
        let alice = make_principal();
        let bob = make_principal();
        let carol = make_principal();

        // Parent valid until ~2065 (well in the future at the time of
        // writing) so it is not itself expired.
        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read, Permission::Delegate]),
            Some(3_000_000_000),
            None,
        );
        let parent_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        // Bob tries to mint a leaf valid until ~2286, beyond the parent.
        let (_, leaf_bytes) = cap_for(
            &bob,
            &carol.fp,
            BTreeSet::from([Permission::Read]),
            Some(9_999_999_999),
            Some(parent_digest),
        );

        let resolver = BundledResolver::from_envelopes(vec![alice_to_bob_bytes]).unwrap();
        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("expiry")),
            "got {err:?}"
        );
    }

    #[test]
    fn unbounded_child_under_bounded_parent_rejected() {
        let alice = make_principal();
        let bob = make_principal();
        let carol = make_principal();

        // Future expiry so the parent is not itself rejected as expired.
        let (_, alice_to_bob_bytes) = cap_for(
            &alice,
            &bob.fp,
            BTreeSet::from([Permission::Read, Permission::Delegate]),
            Some(3_000_000_000),
            None,
        );
        let parent_digest = Capability::wrapped_subject_digest(&alice_to_bob_bytes).unwrap();

        let (_, leaf_bytes) = cap_for(
            &bob,
            &carol.fp,
            BTreeSet::from([Permission::Read]),
            None,
            Some(parent_digest),
        );

        let resolver = BundledResolver::from_envelopes(vec![alice_to_bob_bytes]).unwrap();
        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, AuthError::ChainInvalid(ref s) if s.contains("expiry")),
            "got {err:?}"
        );
    }

    #[test]
    fn max_depth_enforced() {
        // Build a 3-deep chain (leaf + 2 ancestors) but cap depth at 2.
        let (alice, bob, _carol, leaf_bytes, parents) = three_step_chain();
        let resolver = BundledResolver::from_envelopes(parents).unwrap();
        let principals = [&alice, &bob];
        let policy = ChainPolicy {
            max_depth: 1,
            ..ChainPolicy::default()
        };
        let err = verify_chain(&leaf_bytes, &keys_for(&principals), &resolver, &policy)
            .unwrap_err();
        assert!(matches!(err, AuthError::ChainTooDeep { max: 1 }), "got {err:?}");
    }

    #[test]
    fn tampered_parent_envelope_fails_signature() {
        let (alice, bob, _carol, leaf_bytes, mut parents) = three_step_chain();
        // Flip a byte in the parent envelope. Even though we still
        // index it under the *original* digest, the verify step will
        // re-derive the wrapped subject digest and the signature
        // payload from the tampered bytes — both shift, so verification
        // fails before any chain-step check runs.
        let parent_digest = Capability::wrapped_subject_digest(&parents[0]).unwrap();
        let mid = parents[0].len() / 2;
        parents[0][mid] = parents[0][mid].wrapping_add(1);

        let mut resolver = BundledResolver::new();
        resolver.insert_with_digest(parent_digest, parents.into_iter().next().unwrap());

        let principals = [&alice, &bob];
        let err = verify_chain(
            &leaf_bytes,
            &keys_for(&principals),
            &resolver,
            &ChainPolicy::default(),
        )
        .unwrap_err();
        // Tampering may surface as either an invalid signature
        // (different subject digest → wrong signature payload) or
        // chain-broken (mismatched parent). Both are valid rejections.
        assert!(
            matches!(
                err,
                AuthError::InvalidSignature
                    | AuthError::InvalidEncoding(_)
                    | AuthError::ChainInvalid(_)
            ),
            "got {err:?}"
        );
    }
}
