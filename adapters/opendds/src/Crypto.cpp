/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Crypto.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include <sstream>

namespace OpenDDS_PQSec {

std::string openssl_errors(const std::string& prefix) {
  std::ostringstream out;
  out << prefix;
  unsigned long code = 0;
  while ((code = ERR_get_error()) != 0) {
    char text[256];
    ERR_error_string_n(code, text, sizeof text);
    out << ": " << text;
  }
  return out.str();
}

Kem::Kem(const std::string& algorithm) : algorithm_(algorithm) {}

bool Kem::generate(std::string& error) {
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(0, algorithm_.c_str(), 0);
  if (!context) {
    error = openssl_errors("EVP_PKEY_CTX_new_from_name(" + algorithm_ + ")");
    return false;
  }
  EVP_PKEY* generated = 0;
  const bool ok = EVP_PKEY_keygen_init(context) == 1 && EVP_PKEY_generate(context, &generated) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    EVP_PKEY_free(generated);
    error = openssl_errors("ML-KEM key generation failed");
    return false;
  }
  key_.reset(generated);
  return true;
}

bool Kem::import_public(const std::vector<unsigned char>& public_key, std::string& error) {
  if (public_key.empty()) {
    error = "ML-KEM public key is empty";
    return false;
  }
  // OpenSSL runs the FIPS 203 encapsulation key check on import. A hybrid key
  // with a low-order X25519 share is refused when encapsulating to it.
  EVP_PKEY* imported =
      EVP_PKEY_new_raw_public_key_ex(0, algorithm_.c_str(), 0, &public_key[0], public_key.size());
  if (!imported) {
    error = openssl_errors("ML-KEM public-key import failed");
    return false;
  }
  key_.reset(imported);
  return true;
}

bool Kem::public_key(std::vector<unsigned char>& result, std::string& error) const {
  if (!key_) {
    error = "ML-KEM key has not been initialized";
    return false;
  }
  unsigned char* encoded = 0;
  const size_t size = EVP_PKEY_get1_encoded_public_key(key_.get(), &encoded);
  if (!size) {
    error = openssl_errors("ML-KEM public-key export failed");
    return false;
  }
  result.assign(encoded, encoded + size);
  OPENSSL_free(encoded);
  return true;
}

bool Kem::encapsulate(std::vector<unsigned char>& ciphertext, std::vector<unsigned char>& secret,
                      std::string& error) const {
  if (!key_) {
    error = "ML-KEM public key has not been initialized";
    return false;
  }
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_pkey(0, key_.get(), 0);
  size_t ciphertext_size = 0, secret_size = 0;
  const bool initialized = context && EVP_PKEY_encapsulate_init(context, 0) == 1 &&
                           EVP_PKEY_encapsulate(context, 0, &ciphertext_size, 0, &secret_size) == 1;
  if (!initialized || !ciphertext_size || !secret_size) {
    EVP_PKEY_CTX_free(context);
    error = openssl_errors("ML-KEM encapsulation size query failed");
    return false;
  }
  ciphertext.resize(ciphertext_size);
  secret.resize(secret_size);
  const bool ok = EVP_PKEY_encapsulate(context, &ciphertext[0], &ciphertext_size, &secret[0],
                                       &secret_size) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    OPENSSL_cleanse(&secret[0], secret.size());
    secret.clear();
    error = openssl_errors("ML-KEM encapsulation failed");
    return false;
  }
  ciphertext.resize(ciphertext_size);
  secret.resize(secret_size);
  return true;
}

bool Kem::decapsulate(const std::vector<unsigned char>& ciphertext,
                      std::vector<unsigned char>& secret, std::string& error) const {
  if (!key_ || ciphertext.empty()) {
    error = "ML-KEM private key or ciphertext is missing";
    return false;
  }
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_pkey(0, key_.get(), 0);
  size_t secret_size = 0;
  const bool initialized =
      context && EVP_PKEY_decapsulate_init(context, 0) == 1 &&
      EVP_PKEY_decapsulate(context, 0, &secret_size, &ciphertext[0], ciphertext.size()) == 1;
  if (!initialized || !secret_size) {
    EVP_PKEY_CTX_free(context);
    error = openssl_errors("ML-KEM decapsulation size query failed");
    return false;
  }
  secret.resize(secret_size);
  const bool ok = EVP_PKEY_decapsulate(context, &secret[0], &secret_size, &ciphertext[0],
                                       ciphertext.size()) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    OPENSSL_cleanse(&secret[0], secret.size());
    secret.clear();
    error = openssl_errors("ML-KEM decapsulation failed");
    return false;
  }
  secret.resize(secret_size);
  return true;
}

std::vector<unsigned char> shared_secret(std::vector<unsigned char>& kem_secret) {
  std::vector<unsigned char> result(SHA256_DIGEST_LENGTH);
  SHA256(kem_secret.data(), kem_secret.size(), &result[0]);
  if (!kem_secret.empty())
    OPENSSL_cleanse(&kem_secret[0], kem_secret.size());
  return result;
}

} // namespace OpenDDS_PQSec
