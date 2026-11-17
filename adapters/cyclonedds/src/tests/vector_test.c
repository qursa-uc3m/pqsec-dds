/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * Checks the credential hashes, transcripts and SharedSecret against the shared
 * PKI-DH vectors in tests/vectors, for each key establishment algorithm.
 */

#include "pq_kem.h"
#include "transcript.h"

#include <dds/ddsrt/heap.h>
#include <dds/security/core/dds_security_serialize.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_VECTORS 64

typedef struct {
  char name[48];
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

static const DDS_Security_OctetSeq *get_for(const char *algorithm, const char *field) {
  char name[48];
  snprintf(name, sizeof name, "%s.%s", algorithm, field);
  return get(name);
}

static bool expect_for(const char *algorithm, const char *field, const unsigned char *actual,
                       size_t size) {
  char name[48];
  snprintf(name, sizeof name, "%s.%s", algorithm, field);
  return expect(name, actual, size);
}

static void credential_hash(const char *algorithm, const char *party, HashValue_t hash) {
  static const char *const names[] = {"c.id", "c.perm", "c.pdata", "c.dsign_algo", "c.kagree_algo"};
  const DDS_Security_OctetSeq *values[] = {
      get_for(party, "id"), get_for(party, "perm"), get_for(party, "pdata"),
      get_for(algorithm, "dsign_algo"), get_for(algorithm, "kagree_algo")};
  DDS_Security_BinaryProperty_t properties[5];
  const DDS_Security_BinaryProperty_t *credentials[5];

  for (size_t i = 0; i < 5; ++i) {
    properties[i].name = (char *)names[i];
    properties[i].value = *values[i];
    properties[i].propagate = true;
    credentials[i] = &properties[i];
  }
  pqsec_credential_hash(hash, credentials);
}

static bool expect_transcript(const char *algorithm, const char *field,
                              const pqsec_transcript *transcript) {
  unsigned char *buffer;
  size_t size;
  DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);
  DDS_Security_Serialize_BinaryPropertyArray(
      serializer, (const DDS_Security_BinaryProperty_t **)transcript->items, PQSEC_TRANSCRIPT_SIZE);
  DDS_Security_Serializer_buffer(serializer, &buffer, &size);
  const bool ok = expect_for(algorithm, field, buffer, size);
  ddsrt_free(buffer);
  DDS_Security_Serializer_free(serializer);
  return ok;
}

static bool check(const char *algorithm) {
  HashValue_t hash_c1, hash_c2;
  uint8_t shared_secret[PQSEC_SHARED_SECRET_SIZE];
  pqsec_transcript reply, final;
  const DDS_Security_OctetSeq *secret = get_for(algorithm, "secret");

  credential_hash(algorithm, "c1", hash_c1);
  credential_hash(algorithm, "c2", hash_c2);
  pqsec_transcript_init(&reply, false, hash_c1, hash_c2, get("challenge1")->_buffer,
                        get("challenge2")->_buffer, get_for(algorithm, "dh1"),
                        get_for(algorithm, "dh2"));
  pqsec_transcript_init(&final, true, hash_c1, hash_c2, get("challenge1")->_buffer,
                        get("challenge2")->_buffer, get_for(algorithm, "dh1"),
                        get_for(algorithm, "dh2"));
  pqsec_shared_secret(secret->_buffer, secret->_length, shared_secret);

  return expect_for(algorithm, "hash_c1", hash_c1, sizeof hash_c1) &&
         expect_for(algorithm, "hash_c2", hash_c2, sizeof hash_c2) &&
         expect_transcript(algorithm, "reply_transcript", &reply) &&
         expect_transcript(algorithm, "final_transcript", &final) &&
         expect_for(algorithm, "shared_secret", shared_secret, sizeof shared_secret);
}

int main(void) {
  if (!load(PQSEC_VECTORS_FILE)) {
    fprintf(stderr, "Cannot read %s\n", PQSEC_VECTORS_FILE);
    return 1;
  }
  return check("ML-KEM-768") && check("ML-KEM-1024") && check("X25519MLKEM768") ? 0 : 1;
}
