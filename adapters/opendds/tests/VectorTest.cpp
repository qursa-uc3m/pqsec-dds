/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Crypto.h"
#include "Transcript.h"

#include <dds/DCPS/Serializer.h>
#include <dds/DCPS/security/SSL/Utils.h>
#include <dds/DdsDcpsCoreTypeSupportImpl.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> Bytes;
typedef std::map<std::string, Bytes> Vectors;

bool load(const char* path, Vectors& vectors) {
  std::ifstream input(path);
  std::string line;
  while (std::getline(input, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    const std::string::size_type separator = line.find(" = ");
    if (separator == std::string::npos || (line.size() - separator - 3) % 2)
      return false;
    Bytes& value = vectors[line.substr(0, separator)];
    for (std::string::size_type i = separator + 3; i < line.size(); i += 2)
      value.push_back(static_cast<unsigned char>(std::strtoul(line.substr(i, 2).c_str(), 0, 16)));
  }
  return !vectors.empty();
}

std::string text(const Bytes& value) {
  return value.empty() ? std::string() : std::string(value.begin(), value.end() - 1);
}

Bytes serialize(const DDS::BinaryPropertySeq& properties) {
  const OpenDDS::DCPS::Encoding encoding(OpenDDS::DCPS::Encoding::KIND_XCDR1,
                                         OpenDDS::DCPS::ENDIAN_BIG);
  ACE_Message_Block buffer(OpenDDS::DCPS::serialized_size(encoding, properties));
  OpenDDS::DCPS::Serializer serializer(&buffer, encoding);
  if (!(serializer << properties))
    return Bytes();
  return Bytes(buffer.rd_ptr(), buffer.rd_ptr() + buffer.length());
}

bool credential_hash(Vectors& vectors, const std::string& algorithm, const std::string& party,
                     Bytes& result) {
  DDS::OctetSeq hash;
  if (OpenDDS_PQSec::credential_hash(OpenDDS_PQSec::octets(vectors[party + ".id"]),
                                     OpenDDS_PQSec::octets(vectors[party + ".perm"]),
                                     OpenDDS_PQSec::octets(vectors[party + ".pdata"]),
                                     text(vectors[algorithm + ".dsign_algo"]),
                                     text(vectors[algorithm + ".kagree_algo"]), hash))
    return false;
  result = OpenDDS_PQSec::bytes(hash);
  return true;
}

bool expect(Vectors& vectors, const std::string& name, const Bytes& actual) {
  if (actual == vectors[name])
    return true;
  std::cerr << name << " does not match the protocol vector\n";
  return false;
}

bool check(Vectors& vectors, const std::string& algorithm) {
  const std::string prefix = algorithm + ".";
  if (vectors[prefix + "dh1"].empty()) {
    std::cerr << "No vectors for " << algorithm << '\n';
    return false;
  }
  Bytes hash_c1, hash_c2;
  if (!credential_hash(vectors, algorithm, "c1", hash_c1) ||
      !credential_hash(vectors, algorithm, "c2", hash_c2) ||
      !expect(vectors, prefix + "hash_c1", hash_c1) ||
      !expect(vectors, prefix + "hash_c2", hash_c2))
    return false;

  const DDS::OctetSeq challenge1 = OpenDDS_PQSec::octets(vectors["challenge1"]);
  const DDS::OctetSeq challenge2 = OpenDDS_PQSec::octets(vectors["challenge2"]);
  const DDS::OctetSeq dh1 = OpenDDS_PQSec::octets(vectors[prefix + "dh1"]);
  const DDS::OctetSeq dh2 = OpenDDS_PQSec::octets(vectors[prefix + "dh2"]);
  const DDS::BinaryPropertySeq reply =
      OpenDDS_PQSec::reply_transcript(OpenDDS_PQSec::octets(hash_c2), challenge2, dh2, challenge1,
                                      dh1, OpenDDS_PQSec::octets(hash_c1));
  const DDS::BinaryPropertySeq final_data =
      OpenDDS_PQSec::final_transcript(OpenDDS_PQSec::octets(hash_c1), challenge1, dh1, challenge2,
                                      dh2, OpenDDS_PQSec::octets(hash_c2));
  Bytes secret = vectors[prefix + "secret"];
  return expect(vectors, prefix + "reply_transcript", serialize(reply)) &&
         expect(vectors, prefix + "final_transcript", serialize(final_data)) &&
         expect(vectors, prefix + "shared_secret", OpenDDS_PQSec::shared_secret(secret));
}

} // namespace

int main() {
  Vectors vectors;
  if (!load(PQSEC_VECTORS_FILE, vectors)) {
    std::cerr << "Cannot read " << PQSEC_VECTORS_FILE << '\n';
    return 1;
  }
  return check(vectors, "ML-KEM-768") && check(vectors, "ML-KEM-1024") &&
                 check(vectors, "X25519MLKEM768")
             ? 0
             : 1;
}
