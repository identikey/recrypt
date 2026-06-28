# IdentiKey Auth — Platform Enclave Backend Notes

**Status:** Implementation notes
**Date:** 2026-06-27
**Scope:** Guidance for implementing `Signer` backends against hardware key stores
(Apple Secure Enclave ✅ done; Windows TPM/Hello ⬜; Linux TPM ⬜).
**Companion:** [`identikey-auth-challenge-v1.md`](./identikey-auth-challenge-v1.md) (protocol, §8 key storage)

These are the cross-platform engineering lessons learned implementing the macOS Secure
Enclave backend. They generalize — read before adding the Windows or Linux backend.

## 1. The `Signer` trait is `Send + Sync`; native key handles usually are not

`SecKey` (macOS), `NCRYPT_KEY_HANDLE` (Windows), and TPM ESYS contexts (Linux) are all
effectively `!Send` in their Rust bindings. Two ways to bridge to `Signer: Send + Sync`:

- **Hold the handle** behind a wrapper with `unsafe impl Send + Sync`. Sound when the
  platform API is documented thread-safe (Apple's Security framework is). This is what
  the macOS backend does (`SendKey`). Fastest (no per-sign reload).
- **Re-open per operation** — store only an identifier (label / key name / persistent
  handle id), reopen the key inside `sign_classical`. Avoids `unsafe` but needs the key
  to be persisted first (see §3) and costs a lookup per signature.

The macOS backend started with re-open-per-sign and switched to hold-the-handle once
persistence proved entitlement-gated (§3).

## 2. Signature formats differ — normalize to the protocol's fixed form

The protocol's `p256` signature is the **fixed 64-byte `r‖s`** form
(`p256::ecdsa::Signature` / SEC1). Hardware emits different encodings:

- **Apple Secure Enclave** (`ECDSASignatureMessageX962SHA256`) → **DER / X9.62**.
  Convert with `p256::ecdsa::Signature::from_der(&der)?.to_bytes()`.
- **Windows CNG** (`NCryptSignHash` with ECDSA) → typically **raw `r‖s`** already
  (`BCRYPT_ECDSA_*`), so likely no conversion — but confirm length/order.
- **Linux TPM** (`tss-esapi` `sign`) → a `TPMT_SIGNATURE` struct; extract `r` and `s`
  and concatenate to 64 bytes.

Always normalize in the backend so the wire form stays identical across platforms.

Also mind **who hashes**: the macOS `…MessageX962SHA256` algorithm hashes the message
itself (don't pre-hash). Some APIs expect a pre-computed digest — match the protocol's
"sign the raw signing payload" contract (see spec §4.3) accordingly.

## 3. Persistence and biometric gating are the fiddly parts (per-OS)

The key must (a) survive relaunch and (b) require a biometric/user-presence check on use.

**macOS (done):**
- A key is persisted **only** if `GenerateKeyOptions` has a `Location` set
  (`security-framework` ties `kSecAttrIsPermanent` to `location.is_some()`).
- Persisting a Secure-Enclave key needs the **`keychain-access-groups` entitlement**
  (else `errSecMissingEntitlement` / `-34018`).
- That entitlement is **restricted**: signing a *bare CLI* with it makes AMFI kill the
  process on launch (`Killed: 9`) because the CLI's identity can't claim the app's
  access group. It is valid only in the real signed `.app` whose bundle id matches the
  group. → Provide an **ephemeral** (session-only, no-persistence, no-entitlement)
  constructor for tooling/CI, and a **persistent** constructor for the app.
- Biometric gating = `SecAccessControl` with
  `kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet`; the Touch ID
  sheet appears automatically on first key use (signing), not at generation.
- Use the **file keychain** (`Location::DefaultFileKeychain`), not the data-protection
  keychain, for a Developer-ID (non-App-Store) app.

**Windows (done, verified on a vTPM):** persisted CNG keys via
`MS_PLATFORM_CRYPTO_PROVIDER` (`NCryptCreatePersistedKey` + `NCryptFinalizeKey`);
user-presence via `NCRYPT_UI_POLICY` (interactive — gate behind a flag, not headless).
No hosted-domain / entitlement analog. `NCryptSignHash` returns **raw `r‖s`** (no DER).
`NTE_BAD_KEYSET` (0x80090016) = key-not-found. CNG handles are `usize` newtypes, so the
signer is `Send + Sync` with no wrapper (unlike macOS `SecKey`).

**Linux (done, verified on a hardware TPM):** TPM 2.0 via `tss-esapi` 7.7. No uniform
biometric prompt — "user presence" is not a standard concept. Gotchas learned:
- Use `PublicEccParametersBuilder::new_unrestricted_signing_key(...)`; a hand-rolled
  builder omits the KDF scheme → runtime `WrapperError(ParamsMissing)`.
- The TPM returns big-endian coordinates / signature components with leading zeros
  stripped — **left-pad X, Y, r, s to 32 bytes** before assembling SEC1 / raw `r‖s`.
- `Context` is `!Send`, so (like macOS) hold the TCTI string + cached pubkey and open a
  `Context` per op. `create_primary` on `Hierarchy::Null` = ephemeral (no persistent TPM
  state); `Hierarchy::Owner` + `evict_control` for persistence. `sign` needs a null
  `HashcheckTicket`; wrap ops in `execute_with_nullauth_session`.
- `/dev/tpmrm0` is `root:tss` mode 660 — run as a member of `tss` or via sudo; override
  the TCTI with `TPM2TOOLS_TCTI` (e.g. `swtpm:host=…,port=…`) for a software TPM.
- `tss-esapi-sys` ships pre-generated bindings on x86_64/aarch64 Linux, so libclang is
  not needed unless you enable `generate-bindings`; it does need tpm2-tss via pkg-config.

## 4. Curve choice

P-256 is the only curve every mainstream enclave supports (Apple SE is P-256-only), so
it is the hardware default. Ed25519 identities can't live in the SE and must be wrapped
at rest under an enclave P-256 key (spec §8; tracked separately).

## 5. Crate/version footguns

- `security-framework` is at **3.x** but `security-framework-sys` is at **2.x** — they
  version independently; don't pin the sys crate to `3`.
- Target-gate the platform deps (`[target.'cfg(target_os = "macos")'.dependencies]`) so
  the base crate stays dependency-lean and `no_std`-friendly elsewhere.
- **Edition-2024 `unsafe_op_in_unsafe_fn`**: calling an `unsafe fn` (every `windows`/`NCrypt`
  and `tss-esapi` FFI call) is no longer implicitly allowed inside an `unsafe fn` body —
  you get a warning unless you wrap each call in an explicit `unsafe { }`. Prefer making
  helpers **safe `fn`s** that encapsulate their FFI in `unsafe { }` blocks (as both the
  macOS and Windows backends do). This will hit the Linux `tss-esapi` backend too.

## 6. How to verify a backend without the full app

The `enclave_demo` example uses the **ephemeral** constructor so it can prove
generate → biometric-sign → verify end-to-end from a plain code-signed binary, with no
entitlement and no `.app` bundle:

```sh
cargo build -p identikey-auth --example enclave_demo
codesign --force --sign "Developer ID Application: …" target/debug/examples/enclave_demo
./target/debug/examples/enclave_demo   # expect a biometric prompt, then VERIFIED
```

The **persistent** path can only be fully verified inside the signed application (it
needs the platform's app-identity / entitlement). Add an equivalent ephemeral demo for
Windows/Linux so each backend is CI-/desk-verifiable.
