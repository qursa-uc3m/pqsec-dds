/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "transcript.h"

#include "auth_tokens.h"

#include <dds/ddsrt/heap.h>
#include <dds/security/core/dds_security_serialize.h>

#include <string.h>

static void set_property(DDS_Security_BinaryProperty_t *property, const char *name,
                         const void *data, size_t size) {
  property->name = (char *)name;
  property->value._length = property->value._maximum = (uint32_t)size;
  property->value._buffer = (unsigned char *)data;
  property->propagate = true;
}

static void hash_properties(const DDS_Security_BinaryProperty_t **properties, uint32_t count,
                            HashValue_t hash) {
  unsigned char *buffer;
  size_t size;
  DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);
  DDS_Security_Serialize_BinaryPropertyArray(serializer, properties, count);
  DDS_Security_Serializer_buffer(serializer, &buffer, &size);
  SHA256(buffer, size, hash);
  ddsrt_free(buffer);
  DDS_Security_Serializer_free(serializer);
}

void pqsec_credential_hash(HashValue_t hash,
                           const DDS_Security_BinaryProperty_t *const credentials[5]) {
  hash_properties((const DDS_Security_BinaryProperty_t **)credentials, 5, hash);
}

void pqsec_transcript_init(pqsec_transcript *transcript, bool final, const HashValue_t hash_c1,
                           const HashValue_t hash_c2, const unsigned char *challenge1,
                           const unsigned char *challenge2, const DDS_Security_OctetSeq *dh1,
                           const DDS_Security_OctetSeq *dh2) {
  DDS_Security_BinaryProperty_t *p = transcript->properties;
  const size_t challenge_size = DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE;

  if (final) {
    set_property(&p[0], DDS_AUTHTOKEN_PROP_HASH_C1, hash_c1, sizeof(HashValue_t));
    set_property(&p[1], DDS_AUTHTOKEN_PROP_CHALLENGE1, challenge1, challenge_size);
    set_property(&p[2], DDS_AUTHTOKEN_PROP_DH1, dh1->_buffer, dh1->_length);
    set_property(&p[3], DDS_AUTHTOKEN_PROP_CHALLENGE2, challenge2, challenge_size);
    set_property(&p[4], DDS_AUTHTOKEN_PROP_DH2, dh2->_buffer, dh2->_length);
    set_property(&p[5], DDS_AUTHTOKEN_PROP_HASH_C2, hash_c2, sizeof(HashValue_t));
  } else {
    set_property(&p[0], DDS_AUTHTOKEN_PROP_HASH_C2, hash_c2, sizeof(HashValue_t));
    set_property(&p[1], DDS_AUTHTOKEN_PROP_CHALLENGE2, challenge2, challenge_size);
    set_property(&p[2], DDS_AUTHTOKEN_PROP_DH2, dh2->_buffer, dh2->_length);
    set_property(&p[3], DDS_AUTHTOKEN_PROP_CHALLENGE1, challenge1, challenge_size);
    set_property(&p[4], DDS_AUTHTOKEN_PROP_DH1, dh1->_buffer, dh1->_length);
    set_property(&p[5], DDS_AUTHTOKEN_PROP_HASH_C1, hash_c1, sizeof(HashValue_t));
  }
  for (size_t i = 0; i < PQSEC_TRANSCRIPT_SIZE; ++i) {
    transcript->items[i] = &p[i];
  }
}
