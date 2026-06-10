//! Minimal OpenFHE bindings for Proxy Recryption (PRE)
//!
//! This crate provides the raw FFI layer to OpenFHE, exposing only the
//! ~15 functions needed for PRE operations with the BFV scheme.
//!
//! Higher-level safe Rust wrappers are provided by `recrypt-ffi`.

#[cxx::bridge(namespace = "recrypt_openfhe")]
pub mod ffi {
    unsafe extern "C++" {
        include!("recrypt-openfhe-sys/src/wrapper.h");

        // Opaque types (defined in C++ with complete definitions)
        type CryptoContext;
        type KeyPair;
        type PublicKey;
        type PrivateKey;
        type Plaintext;
        type Ciphertext;
        type RecryptKey;

        // Every function returns Result: OpenFHE signals failure with C++
        // exceptions (OpenFHEException, cereal::Exception, bad_alloc), and an
        // exception escaping a non-Result fn would cross the cxx boundary and
        // std::terminate() (SIGABRT) — uncatchable from Rust. The trycatch
        // behavior in wrapper.h converts them to Err instead.

        // Context creation and properties
        fn create_bfv_context(
            plaintext_modulus: u64,
            scaling_mod_size: u32,
        ) -> Result<UniquePtr<CryptoContext>>;
        fn enable_pke(ctx: &CryptoContext) -> Result<()>;
        fn enable_keyswitch(ctx: &CryptoContext) -> Result<()>;
        fn enable_leveledshe(ctx: &CryptoContext) -> Result<()>;
        fn enable_pre(ctx: &CryptoContext) -> Result<()>;
        fn get_ring_dimension(ctx: &CryptoContext) -> Result<u32>;

        // Key generation
        fn keygen(ctx: &CryptoContext) -> Result<UniquePtr<KeyPair>>;
        fn get_public_key(kp: &KeyPair) -> Result<UniquePtr<PublicKey>>;
        fn get_private_key(kp: &KeyPair) -> Result<UniquePtr<PrivateKey>>;

        // Plaintext operations
        fn make_packed_plaintext(
            ctx: &CryptoContext,
            values: &[i64],
        ) -> Result<UniquePtr<Plaintext>>;
        fn get_packed_value(pt: &Plaintext) -> Result<Vec<i64>>;

        // Encryption/Decryption
        fn encrypt(
            ctx: &CryptoContext,
            pk: &PublicKey,
            pt: &Plaintext,
        ) -> Result<UniquePtr<Ciphertext>>;
        fn decrypt(
            ctx: &CryptoContext,
            sk: &PrivateKey,
            ct: &Ciphertext,
        ) -> Result<UniquePtr<Plaintext>>;

        // PRE (recryption) operations
        fn generate_recrypt_key(
            ctx: &CryptoContext,
            from_sk: &PrivateKey,
            to_pk: &PublicKey,
        ) -> Result<UniquePtr<RecryptKey>>;
        fn recrypt(
            ctx: &CryptoContext,
            rk: &RecryptKey,
            ct: &Ciphertext,
        ) -> Result<UniquePtr<Ciphertext>>;

        // Serialization (byte-based)
        fn serialize_ciphertext(ct: &Ciphertext) -> Result<Vec<u8>>;
        fn deserialize_ciphertext(
            ctx: &CryptoContext,
            data: &[u8],
        ) -> Result<UniquePtr<Ciphertext>>;
        fn serialize_public_key(pk: &PublicKey) -> Result<Vec<u8>>;
        fn deserialize_public_key(
            ctx: &CryptoContext,
            data: &[u8],
        ) -> Result<UniquePtr<PublicKey>>;
        fn serialize_private_key(sk: &PrivateKey) -> Result<Vec<u8>>;
        fn deserialize_private_key(
            ctx: &CryptoContext,
            data: &[u8],
        ) -> Result<UniquePtr<PrivateKey>>;
        fn serialize_recrypt_key(rk: &RecryptKey) -> Result<Vec<u8>>;
        fn deserialize_recrypt_key(
            ctx: &CryptoContext,
            data: &[u8],
        ) -> Result<UniquePtr<RecryptKey>>;
    }
}

// Re-export for convenience
pub use ffi::*;

#[cfg(test)]
mod tests {
    use super::ffi;

    #[test]
    fn test_create_context() {
        let ctx = ffi::create_bfv_context(65537, 60).unwrap();
        assert!(!ctx.is_null());

        ffi::enable_pke(&ctx).unwrap();
        ffi::enable_keyswitch(&ctx).unwrap();
        ffi::enable_leveledshe(&ctx).unwrap();
        ffi::enable_pre(&ctx).unwrap();

        let ring_dim = ffi::get_ring_dimension(&ctx).unwrap();
        assert!(ring_dim > 0);
        println!("Ring dimension: {ring_dim}");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let ctx = ffi::create_bfv_context(65537, 60).unwrap();
        ffi::enable_pke(&ctx).unwrap();
        ffi::enable_keyswitch(&ctx).unwrap();
        ffi::enable_leveledshe(&ctx).unwrap();
        ffi::enable_pre(&ctx).unwrap();

        let kp = ffi::keygen(&ctx).unwrap();
        let pk = ffi::get_public_key(&kp).unwrap();
        let sk = ffi::get_private_key(&kp).unwrap();

        let values: Vec<i64> = vec![1, 2, 3, 4, 5];
        let pt = ffi::make_packed_plaintext(&ctx, &values).unwrap();

        let ct = ffi::encrypt(&ctx, &pk, &pt).unwrap();
        let pt_dec = ffi::decrypt(&ctx, &sk, &ct).unwrap();

        let recovered = ffi::get_packed_value(&pt_dec).unwrap();
        assert_eq!(&recovered[..5], &values[..]);
        println!("Roundtrip successful: {:?}", &recovered[..5]);
    }

    #[test]
    fn test_pre_recryption() {
        let ctx = ffi::create_bfv_context(65537, 60).unwrap();
        ffi::enable_pke(&ctx).unwrap();
        ffi::enable_keyswitch(&ctx).unwrap();
        ffi::enable_leveledshe(&ctx).unwrap();
        ffi::enable_pre(&ctx).unwrap();

        // Alice and Bob generate their keypairs
        let alice_kp = ffi::keygen(&ctx).unwrap();
        let alice_pk = ffi::get_public_key(&alice_kp).unwrap();
        let alice_sk = ffi::get_private_key(&alice_kp).unwrap();

        let bob_kp = ffi::keygen(&ctx).unwrap();
        let bob_pk = ffi::get_public_key(&bob_kp).unwrap();
        let bob_sk = ffi::get_private_key(&bob_kp).unwrap();

        // Alice encrypts data to herself
        let values: Vec<i64> = vec![42, 123, 456];
        let pt = ffi::make_packed_plaintext(&ctx, &values).unwrap();
        let ct_alice = ffi::encrypt(&ctx, &alice_pk, &pt).unwrap();

        // Alice generates a recryption key to Bob
        let rk = ffi::generate_recrypt_key(&ctx, &alice_sk, &bob_pk).unwrap();

        // Proxy transforms the ciphertext (without seeing plaintext)
        let ct_bob = ffi::recrypt(&ctx, &rk, &ct_alice).unwrap();

        // Bob decrypts with his own secret key
        let pt_bob = ffi::decrypt(&ctx, &bob_sk, &ct_bob).unwrap();
        let recovered = ffi::get_packed_value(&pt_bob).unwrap();

        assert_eq!(&recovered[..3], &values[..]);
        println!("PRE recryption successful: {:?}", &recovered[..3]);
    }
}
