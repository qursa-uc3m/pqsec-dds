/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool test_kem(const char* algorithm) {
  std::string error;
  OpenDDS_PQSec::Kem initiator(algorithm);
  if (!initiator.generate(error)) {
    std::cerr << error << '\n';
    return false;
  }

  std::vector<unsigned char> public_key;
  if (!initiator.public_key(public_key, error)) {
    std::cerr << error << '\n';
    return false;
  }

  OpenDDS_PQSec::Kem replier(algorithm);
  std::vector<unsigned char> ciphertext, replier_secret, initiator_secret;
  if (!replier.import_public(public_key, error) ||
      !replier.encapsulate(ciphertext, replier_secret, error) ||
      !initiator.decapsulate(ciphertext, initiator_secret, error)) {
    std::cerr << error << '\n';
    return false;
  }

  const bool equal = initiator_secret == replier_secret && !initiator_secret.empty();
  if (!initiator_secret.empty())
    OPENSSL_cleanse(&initiator_secret[0], initiator_secret.size());
  if (!replier_secret.empty())
    OPENSSL_cleanse(&replier_secret[0], replier_secret.size());
  if (!equal)
    std::cerr << algorithm << " shared-secret mismatch\n";
  return equal;
}

bool test_signature(const char* algorithm) {
  EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_from_name(0, algorithm, 0);
  EVP_PKEY* key = 0;
  if (!key_context || EVP_PKEY_keygen_init(key_context) != 1 ||
      EVP_PKEY_generate(key_context, &key) != 1) {
    EVP_PKEY_CTX_free(key_context);
    std::cerr << OpenDDS_PQSec::openssl_errors("ML-DSA key generation failed") << '\n';
    return false;
  }
  EVP_PKEY_CTX_free(key_context);

  const unsigned char message[] = "OpenDDS PQSec transcript";
  EVP_MD_CTX* sign_context = EVP_MD_CTX_new();
  size_t signature_size = 0;
  bool ok = sign_context && EVP_DigestSignInit_ex(sign_context, 0, 0, 0, 0, key, 0) == 1 &&
            EVP_DigestSign(sign_context, 0, &signature_size, message, sizeof message) == 1;
  std::vector<unsigned char> signature(signature_size);
  ok = ok &&
       EVP_DigestSign(sign_context, &signature[0], &signature_size, message, sizeof message) == 1;
  EVP_MD_CTX_free(sign_context);

  EVP_MD_CTX* verify_context = EVP_MD_CTX_new();
  ok =
      ok && verify_context && EVP_DigestVerifyInit_ex(verify_context, 0, 0, 0, 0, key, 0) == 1 &&
      EVP_DigestVerify(verify_context, &signature[0], signature_size, message, sizeof message) == 1;
  EVP_MD_CTX_free(verify_context);
  EVP_PKEY_free(key);
  if (!ok)
    std::cerr << OpenDDS_PQSec::openssl_errors("ML-DSA sign/verify failed") << '\n';
  return ok;
}

// A replier must refuse an encapsulation key that fails the FIPS 203 check,
// and for the hybrid one whose X25519 share is a low-order point.
bool test_invalid_public_keys() {
  std::string error;
  OpenDDS_PQSec::Kem mlkem("ML-KEM-768");
  if (mlkem.import_public(std::vector<unsigned char>(1184, 0xff), error)) {
    std::cerr << "ML-KEM-768 key with coefficients above q was accepted\n";
    return false;
  }

  OpenDDS_PQSec::Kem hybrid("X25519MLKEM768");
  std::vector<unsigned char> key;
  if (!hybrid.generate(error) || !hybrid.public_key(key, error)) {
    std::cerr << error << '\n';
    return false;
  }
  std::fill(key.end() - 32, key.end(), 0);
  OpenDDS_PQSec::Kem peer("X25519MLKEM768");
  std::vector<unsigned char> ciphertext, secret;
  if (peer.import_public(key, error) && peer.encapsulate(ciphertext, secret, error)) {
    std::cerr << "encapsulated to an X25519MLKEM768 key with a zero X25519 share\n";
    return false;
  }
  return true;
}

// The X25519 part of a hybrid ciphertext is checked; the ML-KEM part is not,
// because ML-KEM decapsulation of a wrong ciphertext returns a different key.
bool test_invalid_ciphertexts() {
  std::string error;
  OpenDDS_PQSec::Kem initiator("X25519MLKEM768");
  std::vector<unsigned char> key, ciphertext, secret, decapsulated;
  OpenDDS_PQSec::Kem replier("X25519MLKEM768");
  if (!initiator.generate(error) || !initiator.public_key(key, error) ||
      !replier.import_public(key, error) || !replier.encapsulate(ciphertext, secret, error)) {
    std::cerr << error << '\n';
    return false;
  }

  std::vector<unsigned char> zero_share(ciphertext);
  std::fill(zero_share.end() - 32, zero_share.end(), 0);
  if (initiator.decapsulate(zero_share, decapsulated, error)) {
    std::cerr << "X25519MLKEM768 ciphertext with a zero X25519 share was accepted\n";
    return false;
  }
  std::vector<unsigned char> short_ciphertext(ciphertext.begin(), ciphertext.end() - 1);
  if (initiator.decapsulate(short_ciphertext, decapsulated, error)) {
    std::cerr << "short X25519MLKEM768 ciphertext was accepted\n";
    return false;
  }

  std::vector<unsigned char> altered(ciphertext);
  altered[0] ^= 1;
  if (!initiator.decapsulate(altered, decapsulated, error) || decapsulated == secret) {
    std::cerr << "altered ML-KEM ciphertext did not decapsulate to a different key\n";
    return false;
  }
  return true;
}

} // namespace

int main() {
  const char* kems[] = {"ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768"};
  const char* signatures[] = {"ML-DSA-65", "ML-DSA-87"};
  for (size_t i = 0; i != sizeof kems / sizeof kems[0]; ++i) {
    if (!test_kem(kems[i]))
      return 1;
  }
  for (size_t i = 0; i != sizeof signatures / sizeof signatures[0]; ++i) {
    if (!test_signature(signatures[i]))
      return 1;
  }
  return test_invalid_public_keys() && test_invalid_ciphertexts() ? 0 : 1;
}
