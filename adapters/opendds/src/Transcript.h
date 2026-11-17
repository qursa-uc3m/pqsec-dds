/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#ifndef OPENDDS_PQSEC_TRANSCRIPT_H
#define OPENDDS_PQSEC_TRANSCRIPT_H

#include <dds/DdsSecurityCoreC.h>

#include <string>
#include <vector>

namespace OpenDDS_PQSec {

DDS::OctetSeq octets(const std::vector<unsigned char>& value);
std::vector<unsigned char> bytes(const DDS::OctetSeq& value);
bool equal(const DDS::OctetSeq& lhs, const DDS::OctetSeq& rhs);

void append(DDS::BinaryPropertySeq& properties, const char* name, const DDS::OctetSeq& value);
void append(DDS::BinaryPropertySeq& properties, const char* name, const std::string& value);

// The DDS:Auth:PKI-DH credential hash (hash_c1 or hash_c2) and the two signed
// transcripts of DDS Security 1.2, 10.3.2.5.
int credential_hash(const DDS::OctetSeq& certificate, const DDS::OctetSeq& permissions,
                    const DDS::OctetSeq& participant_data, const std::string& signature_algorithm,
                    const std::string& kem_algorithm, DDS::OctetSeq& result);

DDS::BinaryPropertySeq reply_transcript(const DDS::OctetSeq& hash_c2,
                                        const DDS::OctetSeq& challenge2, const DDS::OctetSeq& dh2,
                                        const DDS::OctetSeq& challenge1, const DDS::OctetSeq& dh1,
                                        const DDS::OctetSeq& hash_c1);

DDS::BinaryPropertySeq final_transcript(const DDS::OctetSeq& hash_c1,
                                        const DDS::OctetSeq& challenge1, const DDS::OctetSeq& dh1,
                                        const DDS::OctetSeq& challenge2, const DDS::OctetSeq& dh2,
                                        const DDS::OctetSeq& hash_c2);

} // namespace OpenDDS_PQSec

#endif
