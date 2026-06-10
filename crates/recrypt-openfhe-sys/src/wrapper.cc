#include "recrypt-openfhe-sys/src/wrapper.h"

#include <sstream>
#include <stdexcept>
#include <string>

// Exception policy: every bridge fn is declared Result<T> on the Rust side,
// so any C++ exception thrown here (or inside OpenFHE) is converted to a Rust
// Err by the rust::behavior::trycatch hook in wrapper.h. Functions therefore
// throw on failure rather than returning null sentinels.

namespace recrypt_openfhe {

// Context creation
std::unique_ptr<CryptoContext> create_bfv_context(uint64_t plaintext_modulus,
                                                  uint32_t scaling_mod_size) {
  lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> params;
  params.SetPlaintextModulus(plaintext_modulus);
  params.SetScalingModSize(scaling_mod_size);

  auto cc = lbcrypto::GenCryptoContext(params);
  return std::make_unique<CryptoContext>(cc);
}

void enable_pke(const CryptoContext &ctx) { ctx.inner->Enable(lbcrypto::PKE); }

void enable_keyswitch(const CryptoContext &ctx) {
  ctx.inner->Enable(lbcrypto::KEYSWITCH);
}

void enable_leveledshe(const CryptoContext &ctx) {
  ctx.inner->Enable(lbcrypto::LEVELEDSHE);
}

void enable_pre(const CryptoContext &ctx) { ctx.inner->Enable(lbcrypto::PRE); }

uint32_t get_ring_dimension(const CryptoContext &ctx) {
  return ctx.inner->GetRingDimension();
}

// Key generation
std::unique_ptr<KeyPair> keygen(const CryptoContext &ctx) {
  auto kp = ctx.inner->KeyGen();
  return std::make_unique<KeyPair>(kp);
}

std::unique_ptr<PublicKey> get_public_key(const KeyPair &kp) {
  return std::make_unique<PublicKey>(kp.inner.publicKey);
}

std::unique_ptr<PrivateKey> get_private_key(const KeyPair &kp) {
  return std::make_unique<PrivateKey>(kp.inner.secretKey);
}

// Plaintext operations
std::unique_ptr<Plaintext>
make_packed_plaintext(const CryptoContext &ctx,
                      rust::Slice<const int64_t> values) {
  std::vector<int64_t> vec(values.begin(), values.end());
  auto pt = ctx.inner->MakePackedPlaintext(vec);
  return std::make_unique<Plaintext>(pt);
}

rust::Vec<int64_t> get_packed_value(const Plaintext &pt) {
  auto &packed = pt.inner->GetPackedValue();
  rust::Vec<int64_t> result;
  result.reserve(packed.size());
  for (const auto &val : packed) {
    result.push_back(val);
  }
  return result;
}

// Encryption/Decryption
std::unique_ptr<Ciphertext> encrypt(const CryptoContext &ctx,
                                    const PublicKey &pk, const Plaintext &pt) {
  auto ct = ctx.inner->Encrypt(pk.inner, pt.inner);
  return std::make_unique<Ciphertext>(ct);
}

std::unique_ptr<Plaintext> decrypt(const CryptoContext &ctx,
                                   const PrivateKey &sk, const Ciphertext &ct) {
  lbcrypto::Plaintext pt;
  ctx.inner->Decrypt(sk.inner, ct.inner, &pt);
  return std::make_unique<Plaintext>(pt);
}

// PRE operations
std::unique_ptr<RecryptKey> generate_recrypt_key(const CryptoContext &ctx,
                                                 const PrivateKey &from_sk,
                                                 const PublicKey &to_pk) {
  auto rk = ctx.inner->ReKeyGen(from_sk.inner, to_pk.inner);
  return std::make_unique<RecryptKey>(rk);
}

std::unique_ptr<Ciphertext>
recrypt(const CryptoContext &ctx, const RecryptKey &rk, const Ciphertext &ct) {
  auto new_ct = ctx.inner->ReEncrypt(ct.inner, rk.inner);
  return std::make_unique<Ciphertext>(new_ct);
}

// Serialization helpers
rust::Vec<uint8_t> serialize_ciphertext(const Ciphertext &ct) {
  std::stringstream ss;
  lbcrypto::Serial::Serialize(ct.inner, ss, lbcrypto::SerType::BINARY);
  std::string str = ss.str();
  rust::Vec<uint8_t> result;
  result.reserve(str.size());
  for (char c : str) {
    result.push_back(static_cast<uint8_t>(c));
  }
  return result;
}

std::unique_ptr<Ciphertext>
deserialize_ciphertext(const CryptoContext &ctx,
                       rust::Slice<const uint8_t> data) {
  std::string str(data.begin(), data.end());
  std::stringstream ss(str);
  lbcrypto::Ciphertext<lbcrypto::DCRTPoly> ct;
  lbcrypto::Serial::Deserialize(ct, ss, lbcrypto::SerType::BINARY);
  // Cereal can deserialize a smart pointer to null without throwing; using
  // such an object later aborts deep inside OpenFHE (e.g. ValidateKey).
  if (!ct) {
    throw std::runtime_error("deserialized ciphertext is null");
  }
  return std::make_unique<Ciphertext>(ct);
}

rust::Vec<uint8_t> serialize_public_key(const PublicKey &pk) {
  std::stringstream ss;
  lbcrypto::Serial::Serialize(pk.inner, ss, lbcrypto::SerType::BINARY);
  std::string str = ss.str();
  rust::Vec<uint8_t> result;
  result.reserve(str.size());
  for (char c : str) {
    result.push_back(static_cast<uint8_t>(c));
  }
  return result;
}

std::unique_ptr<PublicKey>
deserialize_public_key(const CryptoContext &ctx,
                       rust::Slice<const uint8_t> data) {
  std::string str(data.begin(), data.end());
  std::stringstream ss(str);
  lbcrypto::PublicKey<lbcrypto::DCRTPoly> pk;
  lbcrypto::Serial::Deserialize(pk, ss, lbcrypto::SerType::BINARY);
  if (!pk) {
    throw std::runtime_error("deserialized public key is null");
  }
  return std::make_unique<PublicKey>(pk);
}

rust::Vec<uint8_t> serialize_private_key(const PrivateKey &sk) {
  std::stringstream ss;
  lbcrypto::Serial::Serialize(sk.inner, ss, lbcrypto::SerType::BINARY);
  std::string str = ss.str();
  rust::Vec<uint8_t> result;
  result.reserve(str.size());
  for (char c : str) {
    result.push_back(static_cast<uint8_t>(c));
  }
  return result;
}

std::unique_ptr<PrivateKey>
deserialize_private_key(const CryptoContext &ctx,
                        rust::Slice<const uint8_t> data) {
  std::string str(data.begin(), data.end());
  std::stringstream ss(str);
  lbcrypto::PrivateKey<lbcrypto::DCRTPoly> sk;
  lbcrypto::Serial::Deserialize(sk, ss, lbcrypto::SerType::BINARY);
  if (!sk) {
    throw std::runtime_error("deserialized private key is null");
  }
  return std::make_unique<PrivateKey>(sk);
}

rust::Vec<uint8_t> serialize_recrypt_key(const RecryptKey &rk) {
  std::stringstream ss;
  lbcrypto::Serial::Serialize(rk.inner, ss, lbcrypto::SerType::BINARY);
  std::string str = ss.str();
  rust::Vec<uint8_t> result;
  result.reserve(str.size());
  for (char c : str) {
    result.push_back(static_cast<uint8_t>(c));
  }
  return result;
}

std::unique_ptr<RecryptKey>
deserialize_recrypt_key(const CryptoContext &ctx,
                        rust::Slice<const uint8_t> data) {
  std::string str(data.begin(), data.end());
  std::stringstream ss(str);
  lbcrypto::EvalKey<lbcrypto::DCRTPoly> rk;
  lbcrypto::Serial::Deserialize(rk, ss, lbcrypto::SerType::BINARY);
  if (!rk) {
    throw std::runtime_error("deserialized recrypt key is null");
  }
  return std::make_unique<RecryptKey>(rk);
}

} // namespace recrypt_openfhe
