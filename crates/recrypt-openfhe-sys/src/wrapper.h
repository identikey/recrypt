#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "rust/cxx.h"

// OpenFHE headers
// MUST include scheme-specific headers for serialization to work
#include "openfhe.h"

// Serialization headers for BFV/PRE
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

// cxx converts a C++ exception thrown by a bridge fn declared `Result<T>` into
// a Rust Err via this hook. The cxx default only catches std::exception; the
// catch-all clause ensures non-std throws also become Err instead of escaping
// to std::terminate() (SIGABRT), which Rust cannot catch.
namespace rust {
namespace behavior {
template <typename Try, typename Fail>
static void trycatch(Try &&func, Fail &&fail) noexcept try {
  func();
} catch (const std::exception &e) {
  fail(e.what());
} catch (...) {
  fail("non-std C++ exception in OpenFHE FFI");
}
} // namespace behavior
} // namespace rust

namespace recrypt_openfhe {

// Wrapper classes that own OpenFHE objects
// These are "complete" types that cxx can work with

class CryptoContext final {
public:
  lbcrypto::CryptoContext<lbcrypto::DCRTPoly> inner;

  CryptoContext() = default;
  explicit CryptoContext(lbcrypto::CryptoContext<lbcrypto::DCRTPoly> ctx)
      : inner(std::move(ctx)) {}
};

class KeyPair final {
public:
  lbcrypto::KeyPair<lbcrypto::DCRTPoly> inner;

  KeyPair() = default;
  explicit KeyPair(lbcrypto::KeyPair<lbcrypto::DCRTPoly> kp)
      : inner(std::move(kp)) {}
};

class PublicKey final {
public:
  lbcrypto::PublicKey<lbcrypto::DCRTPoly> inner;

  PublicKey() = default;
  explicit PublicKey(lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk)
      : inner(std::move(pk)) {}
};

class PrivateKey final {
public:
  lbcrypto::PrivateKey<lbcrypto::DCRTPoly> inner;

  PrivateKey() = default;
  explicit PrivateKey(lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk)
      : inner(std::move(sk)) {}
};

class Plaintext final {
public:
  lbcrypto::Plaintext inner;

  Plaintext() = default;
  explicit Plaintext(lbcrypto::Plaintext pt) : inner(std::move(pt)) {}
};

class Ciphertext final {
public:
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> inner;

  Ciphertext() = default;
  explicit Ciphertext(lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct)
      : inner(std::move(ct)) {}
};

class RecryptKey final {
public:
  lbcrypto::EvalKey<lbcrypto::DCRTPoly> inner;

  RecryptKey() = default;
  explicit RecryptKey(lbcrypto::EvalKey<lbcrypto::DCRTPoly> rk)
      : inner(std::move(rk)) {}
};

// Context creation and properties
std::unique_ptr<CryptoContext> create_bfv_context(uint64_t plaintext_modulus,
                                                  uint32_t scaling_mod_size);
void enable_pke(const CryptoContext &ctx);
void enable_keyswitch(const CryptoContext &ctx);
void enable_leveledshe(const CryptoContext &ctx);
void enable_pre(const CryptoContext &ctx);
uint32_t get_ring_dimension(const CryptoContext &ctx);

// Key generation
std::unique_ptr<KeyPair> keygen(const CryptoContext &ctx);
std::unique_ptr<PublicKey> get_public_key(const KeyPair &kp);
std::unique_ptr<PrivateKey> get_private_key(const KeyPair &kp);

// Plaintext operations
std::unique_ptr<Plaintext>
make_packed_plaintext(const CryptoContext &ctx,
                      rust::Slice<const int64_t> values);
rust::Vec<int64_t> get_packed_value(const Plaintext &pt);

// Encryption/Decryption
std::unique_ptr<Ciphertext> encrypt(const CryptoContext &ctx,
                                    const PublicKey &pk, const Plaintext &pt);
std::unique_ptr<Plaintext> decrypt(const CryptoContext &ctx,
                                   const PrivateKey &sk, const Ciphertext &ct);

// PRE (recryption) operations
std::unique_ptr<RecryptKey> generate_recrypt_key(const CryptoContext &ctx,
                                                 const PrivateKey &from_sk,
                                                 const PublicKey &to_pk);
std::unique_ptr<Ciphertext> recrypt(const CryptoContext &ctx,
                                    const RecryptKey &rk, const Ciphertext &ct);

// Serialization (byte-based via stringstream)
rust::Vec<uint8_t> serialize_ciphertext(const Ciphertext &ct);
std::unique_ptr<Ciphertext>
deserialize_ciphertext(const CryptoContext &ctx,
                       rust::Slice<const uint8_t> data);
rust::Vec<uint8_t> serialize_public_key(const PublicKey &pk);
std::unique_ptr<PublicKey>
deserialize_public_key(const CryptoContext &ctx,
                       rust::Slice<const uint8_t> data);
rust::Vec<uint8_t> serialize_private_key(const PrivateKey &sk);
std::unique_ptr<PrivateKey>
deserialize_private_key(const CryptoContext &ctx,
                        rust::Slice<const uint8_t> data);
rust::Vec<uint8_t> serialize_recrypt_key(const RecryptKey &rk);
std::unique_ptr<RecryptKey>
deserialize_recrypt_key(const CryptoContext &ctx,
                        rust::Slice<const uint8_t> data);

} // namespace recrypt_openfhe
