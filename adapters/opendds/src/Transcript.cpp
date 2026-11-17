/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Transcript.h"

#include <dds/DCPS/SequenceIterator.h>
#include <dds/DCPS/security/SSL/Utils.h>

#include <cstring>

namespace OpenDDS_PQSec {

DDS::OctetSeq octets(const std::vector<unsigned char>& value) {
  DDS::OctetSeq result;
  result.length(static_cast<CORBA::ULong>(value.size()));
  if (!value.empty())
    std::memcpy(result.get_buffer(), &value[0], value.size());
  return result;
}

std::vector<unsigned char> bytes(const DDS::OctetSeq& value) {
  return std::vector<unsigned char>(value.get_buffer(), value.get_buffer() + value.length());
}

bool equal(const DDS::OctetSeq& lhs, const DDS::OctetSeq& rhs) {
  return lhs.length() == rhs.length() &&
         (!lhs.length() || std::memcmp(lhs.get_buffer(), rhs.get_buffer(), lhs.length()) == 0);
}

void append(DDS::BinaryPropertySeq& properties, const char* name, const DDS::OctetSeq& value) {
  OpenDDS::DCPS::SequenceBackInsertIterator<DDS::BinaryPropertySeq> out(properties);
  DDS::BinaryProperty_t property;
  property.name = name;
  property.value = value;
  property.propagate = true;
  *out = property;
}

void append(DDS::BinaryPropertySeq& properties, const char* name, const std::string& value) {
  DDS::OctetSeq data;
  data.length(static_cast<CORBA::ULong>(value.size() + 1));
  std::memcpy(data.get_buffer(), value.c_str(), value.size() + 1);
  append(properties, name, data);
}

int credential_hash(const DDS::OctetSeq& certificate, const DDS::OctetSeq& permissions,
                    const DDS::OctetSeq& participant_data, const std::string& signature_algorithm,
                    const std::string& kem_algorithm, DDS::OctetSeq& result) {
  DDS::BinaryPropertySeq properties;
  append(properties, "c.id", certificate);
  append(properties, "c.perm", permissions);
  append(properties, "c.pdata", participant_data);
  append(properties, "c.dsign_algo", signature_algorithm);
  append(properties, "c.kagree_algo", kem_algorithm);
  return OpenDDS::Security::SSL::hash_serialized(properties, result);
}

DDS::BinaryPropertySeq reply_transcript(const DDS::OctetSeq& hash_c2,
                                        const DDS::OctetSeq& challenge2, const DDS::OctetSeq& dh2,
                                        const DDS::OctetSeq& challenge1, const DDS::OctetSeq& dh1,
                                        const DDS::OctetSeq& hash_c1) {
  DDS::BinaryPropertySeq result;
  append(result, "hash_c2", hash_c2);
  append(result, "challenge2", challenge2);
  append(result, "dh2", dh2);
  append(result, "challenge1", challenge1);
  append(result, "dh1", dh1);
  append(result, "hash_c1", hash_c1);
  return result;
}

DDS::BinaryPropertySeq final_transcript(const DDS::OctetSeq& hash_c1,
                                        const DDS::OctetSeq& challenge1, const DDS::OctetSeq& dh1,
                                        const DDS::OctetSeq& challenge2, const DDS::OctetSeq& dh2,
                                        const DDS::OctetSeq& hash_c2) {
  DDS::BinaryPropertySeq result;
  append(result, "hash_c1", hash_c1);
  append(result, "challenge1", challenge1);
  append(result, "dh1", dh1);
  append(result, "challenge2", challenge2);
  append(result, "dh2", dh2);
  append(result, "hash_c2", hash_c2);
  return result;
}

} // namespace OpenDDS_PQSec
