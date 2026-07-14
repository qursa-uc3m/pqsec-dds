#include "Crypto.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <iostream>
#include <string>
#include <vector>

namespace {

bool test_kem(const char* algorithm)
{
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
  if (!initiator_secret.empty()) OPENSSL_cleanse(&initiator_secret[0], initiator_secret.size());
  if (!replier_secret.empty()) OPENSSL_cleanse(&replier_secret[0], replier_secret.size());
  if (!equal) std::cerr << algorithm << " shared-secret mismatch\n";
  return equal;
}

bool test_signature(const char* algorithm)
{
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
  bool ok = sign_context &&
    EVP_DigestSignInit_ex(sign_context, 0, 0, 0, 0, key, 0) == 1 &&
    EVP_DigestSign(sign_context, 0, &signature_size, message, sizeof message) == 1;
  std::vector<unsigned char> signature(signature_size);
  ok = ok && EVP_DigestSign(sign_context, &signature[0], &signature_size,
                            message, sizeof message) == 1;
  EVP_MD_CTX_free(sign_context);

  EVP_MD_CTX* verify_context = EVP_MD_CTX_new();
  ok = ok && verify_context &&
    EVP_DigestVerifyInit_ex(verify_context, 0, 0, 0, 0, key, 0) == 1 &&
    EVP_DigestVerify(verify_context, &signature[0], signature_size,
                     message, sizeof message) == 1;
  EVP_MD_CTX_free(verify_context);
  EVP_PKEY_free(key);
  if (!ok) std::cerr << OpenDDS_PQSec::openssl_errors("ML-DSA sign/verify failed") << '\n';
  return ok;
}

} // namespace

int main()
{
  const char* kems[] = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519MLKEM768"
  };
  const char* signatures[] = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};
  for (size_t i = 0; i != sizeof kems / sizeof kems[0]; ++i) {
    if (!test_kem(kems[i])) return 1;
  }
  for (size_t i = 0; i != sizeof signatures / sizeof signatures[0]; ++i) {
    if (!test_signature(signatures[i])) return 1;
  }
  return 0;
}
