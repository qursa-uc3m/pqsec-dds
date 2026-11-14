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

bool credential_hash(Vectors& vectors, const std::string& prefix, Bytes& result) {
  DDS::OctetSeq hash;
  if (OpenDDS_PQSec::credential_hash(OpenDDS_PQSec::octets(vectors[prefix + ".id"]),
                                     OpenDDS_PQSec::octets(vectors[prefix + ".perm"]),
                                     OpenDDS_PQSec::octets(vectors[prefix + ".pdata"]),
                                     text(vectors[prefix + ".dsign_algo"]),
                                     text(vectors[prefix + ".kagree_algo"]), hash))
    return false;
  result = OpenDDS_PQSec::bytes(hash);
  return true;
}

bool expect(Vectors& vectors, const char* name, const Bytes& actual) {
  if (actual == vectors[name])
    return true;
  std::cerr << name << " does not match the protocol vector\n";
  return false;
}

} // namespace

int main() {
  Vectors vectors;
  if (!load(PQSEC_VECTORS_FILE, vectors)) {
    std::cerr << "Cannot read " << PQSEC_VECTORS_FILE << '\n';
    return 1;
  }

  Bytes hash_c1, hash_c2;
  if (!credential_hash(vectors, "c1", hash_c1) || !credential_hash(vectors, "c2", hash_c2) ||
      !expect(vectors, "hash_c1", hash_c1) || !expect(vectors, "hash_c2", hash_c2))
    return 1;

  const DDS::OctetSeq challenge1 = OpenDDS_PQSec::octets(vectors["challenge1"]);
  const DDS::OctetSeq challenge2 = OpenDDS_PQSec::octets(vectors["challenge2"]);
  const DDS::OctetSeq public_key = OpenDDS_PQSec::octets(vectors["kem_public"]);
  const DDS::OctetSeq ciphertext = OpenDDS_PQSec::octets(vectors["kem_ciphertext"]);
  const DDS::BinaryPropertySeq reply =
      OpenDDS_PQSec::reply_transcript(OpenDDS_PQSec::octets(hash_c2), challenge2, ciphertext,
                                      challenge1, public_key, OpenDDS_PQSec::octets(hash_c1));
  const DDS::BinaryPropertySeq final_data =
      OpenDDS_PQSec::final_transcript(OpenDDS_PQSec::octets(hash_c1), challenge1, public_key,
                                      challenge2, ciphertext, OpenDDS_PQSec::octets(hash_c2));
  if (!expect(vectors, "reply_transcript", serialize(reply)) ||
      !expect(vectors, "final_transcript", serialize(final_data)))
    return 1;

  DDS::OctetSeq transcript_hash;
  Bytes shared_secret;
  std::string error;
  if (OpenDDS::Security::SSL::hash_serialized(final_data, transcript_hash) ||
      !expect(vectors, "transcript_hash", OpenDDS_PQSec::bytes(transcript_hash)) ||
      !OpenDDS_PQSec::derive_shared_secret(
          vectors["kem_secret"], OpenDDS_PQSec::bytes(transcript_hash), shared_secret, error) ||
      !expect(vectors, "shared_secret", shared_secret)) {
    std::cerr << error;
    return 1;
  }
  return 0;
}
