#ifndef OPENDDS_PQSEC_CRYPTO_H
#define OPENDDS_PQSEC_CRYPTO_H

#include <openssl/evp.h>

#include <memory>
#include <string>
#include <vector>

namespace OpenDDS_PQSec {

struct PkeyDeleter {
  void operator()(EVP_PKEY* value) const { EVP_PKEY_free(value); }
};
typedef std::unique_ptr<EVP_PKEY, PkeyDeleter> PkeyPtr;

class Kem {
public:
  explicit Kem(const std::string& algorithm = "ML-KEM-768");

  bool generate(std::string& error);
  bool import_public(const std::vector<unsigned char>& public_key, std::string& error);
  bool public_key(std::vector<unsigned char>& result, std::string& error) const;
  bool encapsulate(std::vector<unsigned char>& ciphertext,
                   std::vector<unsigned char>& secret,
                   std::string& error) const;
  bool decapsulate(const std::vector<unsigned char>& ciphertext,
                   std::vector<unsigned char>& secret,
                   std::string& error) const;

  const std::string& algorithm() const { return algorithm_; }

private:
  std::string algorithm_;
  PkeyPtr key_;
};

bool openssl_supports(const std::string& algorithm);
std::string openssl_errors(const std::string& prefix);

} // namespace OpenDDS_PQSec

#endif
