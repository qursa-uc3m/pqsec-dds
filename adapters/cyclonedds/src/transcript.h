/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * Credential hashes and signed transcripts of protocol pqsec-dds.auth:1.1.
 * Everything here works on the caller's data; nothing is copied.
 */

#ifndef PQSEC_DDS_TRANSCRIPT_H
#define PQSEC_DDS_TRANSCRIPT_H

#include <dds/security/dds_security_api_types.h>
#include <openssl/sha.h>

#include <stdbool.h>

#define PQSEC_TRANSCRIPT_SIZE 8

typedef unsigned char HashValue_t[SHA256_DIGEST_LENGTH];

typedef struct pqsec_transcript {
  DDS_Security_BinaryProperty_t properties[PQSEC_TRANSCRIPT_SIZE];
  const DDS_Security_BinaryProperty_t *items[PQSEC_TRANSCRIPT_SIZE];
} pqsec_transcript;

/* SHA-256 of the protocol and role separators followed by c.id, c.perm,
 * c.pdata, c.dsign_algo and c.kagree_algo, in that order. */
void pqsec_credential_hash(HashValue_t hash,
                           const DDS_Security_BinaryProperty_t *const credentials[5]);

/* The Reply transcript, or the Final transcript when final is true. */
void pqsec_transcript_init(pqsec_transcript *transcript, bool final, const HashValue_t hash_c1,
                           const HashValue_t hash_c2, const unsigned char *challenge1,
                           const unsigned char *challenge2, const DDS_Security_OctetSeq *kem_public,
                           const DDS_Security_OctetSeq *kem_ciphertext);

void pqsec_transcript_hash(const pqsec_transcript *transcript, HashValue_t hash);

#endif /* PQSEC_DDS_TRANSCRIPT_H */
