#include "Crypto.h"

#include <openssl/err.h>

#include <sstream>

namespace OpenDDS_PQSec {

std::string openssl_errors(const std::string& prefix)
{
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

bool openssl_supports(const std::string& algorithm)
{
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(0, algorithm.c_str(), 0);
  if (!context) return false;
  EVP_PKEY_CTX_free(context);
  return true;
}

Kem::Kem(const std::string& algorithm)
  : algorithm_(algorithm)
{
}

bool Kem::generate(std::string& error)
{
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(0, algorithm_.c_str(), 0);
  if (!context) {
    error = openssl_errors("EVP_PKEY_CTX_new_from_name(" + algorithm_ + ")");
    return false;
  }
  EVP_PKEY* generated = 0;
  const bool ok = EVP_PKEY_keygen_init(context) == 1 &&
    EVP_PKEY_generate(context, &generated) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    EVP_PKEY_free(generated);
    error = openssl_errors("ML-KEM key generation failed");
    return false;
  }
  key_.reset(generated);
  return true;
}

bool Kem::import_public(const std::vector<unsigned char>& public_key, std::string& error)
{
  if (public_key.empty()) {
    error = "ML-KEM public key is empty";
    return false;
  }
  EVP_PKEY* imported = EVP_PKEY_new_raw_public_key_ex(
    0, algorithm_.c_str(), 0, &public_key[0], public_key.size());
  if (!imported) {
    error = openssl_errors("ML-KEM public-key import failed");
    return false;
  }
  key_.reset(imported);
  return true;
}

bool Kem::public_key(std::vector<unsigned char>& result, std::string& error) const
{
  if (!key_) {
    error = "ML-KEM key has not been initialized";
    return false;
  }
  size_t size = 0;
  if (EVP_PKEY_get_raw_public_key(key_.get(), 0, &size) != 1 || !size) {
    error = openssl_errors("ML-KEM public-key size query failed");
    return false;
  }
  result.resize(size);
  if (EVP_PKEY_get_raw_public_key(key_.get(), &result[0], &size) != 1) {
    error = openssl_errors("ML-KEM public-key export failed");
    return false;
  }
  result.resize(size);
  return true;
}

bool Kem::encapsulate(std::vector<unsigned char>& ciphertext,
                      std::vector<unsigned char>& secret,
                      std::string& error) const
{
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
  const bool ok = EVP_PKEY_encapsulate(context, &ciphertext[0], &ciphertext_size,
                                        &secret[0], &secret_size) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    error = openssl_errors("ML-KEM encapsulation failed");
    return false;
  }
  ciphertext.resize(ciphertext_size);
  secret.resize(secret_size);
  return true;
}

bool Kem::decapsulate(const std::vector<unsigned char>& ciphertext,
                      std::vector<unsigned char>& secret,
                      std::string& error) const
{
  if (!key_ || ciphertext.empty()) {
    error = "ML-KEM private key or ciphertext is missing";
    return false;
  }
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_pkey(0, key_.get(), 0);
  size_t secret_size = 0;
  const bool initialized = context && EVP_PKEY_decapsulate_init(context, 0) == 1 &&
    EVP_PKEY_decapsulate(context, 0, &secret_size,
                         &ciphertext[0], ciphertext.size()) == 1;
  if (!initialized || !secret_size) {
    EVP_PKEY_CTX_free(context);
    error = openssl_errors("ML-KEM decapsulation size query failed");
    return false;
  }
  secret.resize(secret_size);
  const bool ok = EVP_PKEY_decapsulate(context, &secret[0], &secret_size,
                                        &ciphertext[0], ciphertext.size()) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    error = openssl_errors("ML-KEM decapsulation failed");
    return false;
  }
  secret.resize(secret_size);
  return true;
}

} // namespace OpenDDS_PQSec
