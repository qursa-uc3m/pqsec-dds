/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * Checks the credential hashes, transcripts and key derivation against the
 * shared protocol vectors in tests/vectors.
 */

#include "pq_kem.h"
#include "transcript.h"

#include <dds/ddsrt/heap.h>
#include <dds/security/core/dds_security_serialize.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VECTORS 32

typedef struct {
  char name[32];
  DDS_Security_OctetSeq value;
} vector;

static vector vectors[MAX_VECTORS];
static size_t vector_count;

static bool load(const char *path) {
  FILE *file = fopen(path, "r");
  static char line[1 << 16];
  if (!file) {
    return false;
  }
  while (vector_count < MAX_VECTORS && fgets(line, sizeof line, file)) {
    char *separator = strstr(line, " = ");
    if (line[0] == '#' || !separator || (size_t)(separator - line) >= sizeof vectors[0].name) {
      continue;
    }
    vector *v = &vectors[vector_count++];
    const char *hex = separator + 3;
    const size_t length = strcspn(hex, "\r\n") / 2;
    memcpy(v->name, line, (size_t)(separator - line));
    v->value._buffer = ddsrt_malloc(length ? length : 1);
    v->value._length = v->value._maximum = (uint32_t)length;
    for (size_t i = 0; i < length; ++i) {
      const char byte[3] = {hex[2 * i], hex[2 * i + 1], '\0'};
      v->value._buffer[i] = (unsigned char)strtoul(byte, NULL, 16);
    }
  }
  fclose(file);
  return vector_count > 0;
}

static const DDS_Security_OctetSeq *get(const char *name) {
  for (size_t i = 0; i < vector_count; ++i) {
    if (strcmp(vectors[i].name, name) == 0) {
      return &vectors[i].value;
    }
  }
  fprintf(stderr, "Missing vector %s\n", name);
  exit(1);
}

static bool expect(const char *name, const unsigned char *actual, size_t size) {
  const DDS_Security_OctetSeq *expected = get(name);
  if (expected->_length == size && memcmp(expected->_buffer, actual, size) == 0) {
    return true;
  }
  fprintf(stderr, "%s does not match the protocol vector\n", name);
  return false;
}

static void credential_hash(const char *prefix, HashValue_t hash) {
  static const char *const fields[] = {"id", "perm", "pdata", "dsign_algo", "kagree_algo"};
  static const char *const names[] = {"c.id", "c.perm", "c.pdata", "c.dsign_algo", "c.kagree_algo"};
  DDS_Security_BinaryProperty_t properties[5];
  const DDS_Security_BinaryProperty_t *credentials[5];
  char name[32];

  for (size_t i = 0; i < 5; ++i) {
    snprintf(name, sizeof name, "%s.%s", prefix, fields[i]);
    properties[i].name = (char *)names[i];
    properties[i].value = *get(name);
    properties[i].propagate = true;
    credentials[i] = &properties[i];
  }
  pqsec_credential_hash(hash, credentials);
}

static bool expect_transcript(const char *name, const pqsec_transcript *transcript) {
  unsigned char *buffer;
  size_t size;
  DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);
  DDS_Security_Serialize_BinaryPropertyArray(
      serializer, (const DDS_Security_BinaryProperty_t **)transcript->items, PQSEC_TRANSCRIPT_SIZE);
  DDS_Security_Serializer_buffer(serializer, &buffer, &size);
  const bool ok = expect(name, buffer, size);
  ddsrt_free(buffer);
  DDS_Security_Serializer_free(serializer);
  return ok;
}

int main(void) {
  HashValue_t hash_c1, hash_c2, transcript_hash;
  uint8_t shared_secret[PQSEC_SHARED_SECRET_SIZE];
  pqsec_transcript reply, final;

  if (!load(PQSEC_VECTORS_FILE)) {
    fprintf(stderr, "Cannot read %s\n", PQSEC_VECTORS_FILE);
    return 1;
  }

  credential_hash("c1", hash_c1);
  credential_hash("c2", hash_c2);
  pqsec_transcript_init(&reply, false, hash_c1, hash_c2, get("challenge1")->_buffer,
                        get("challenge2")->_buffer, get("kem_public"), get("kem_ciphertext"));
  pqsec_transcript_init(&final, true, hash_c1, hash_c2, get("challenge1")->_buffer,
                        get("challenge2")->_buffer, get("kem_public"), get("kem_ciphertext"));
  pqsec_transcript_hash(&final, transcript_hash);
  const DDS_Security_OctetSeq *kem_secret = get("kem_secret");

  if (!expect("hash_c1", hash_c1, sizeof hash_c1) || !expect("hash_c2", hash_c2, sizeof hash_c2) ||
      !expect_transcript("reply_transcript", &reply) ||
      !expect_transcript("final_transcript", &final) ||
      !expect("transcript_hash", transcript_hash, sizeof transcript_hash) ||
      !pqsec_derive_shared_secret(kem_secret->_buffer, kem_secret->_length, transcript_hash,
                                  shared_secret) ||
      !expect("shared_secret", shared_secret, sizeof shared_secret)) {
    return 1;
  }
  return 0;
}
