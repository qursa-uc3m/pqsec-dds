/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "auth_utils.h"

#include <dds/ddsrt/heap.h>
#include <dds/security/core/dds_security_utils.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

/* A transcript signed with the key verifies, and a changed signature does
 * not. */
static bool round_trip(const char *name, EVP_PKEY *key) {
  const unsigned char challenge[] = {0x01, 0x02, 0x03, 0x04};
  const unsigned char ciphertext[] = {0x10, 0x20, 0x30};
  DDS_Security_BinaryProperty_t challenge_property = {
      .name = "challenge1",
      .value = {._length = sizeof(challenge), ._buffer = (unsigned char *)challenge}};
  DDS_Security_BinaryProperty_t ciphertext_property = {
      .name = "dh2",
      .value = {._length = sizeof(ciphertext), ._buffer = (unsigned char *)ciphertext}};
  const DDS_Security_BinaryProperty_t *transcript[] = {&challenge_property, &ciphertext_property};
  DDS_Security_SecurityException exception = {0};
  unsigned char *signature = NULL;
  size_t signature_size = 0;
  bool ok = false;

  if (!key ||
      create_signature(key, transcript, 2, &signature, &signature_size, &exception) !=
          DDS_SECURITY_VALIDATION_OK ||
      validate_signature(key, transcript, 2, signature, signature_size, &exception) !=
          DDS_SECURITY_VALIDATION_OK) {
    fprintf(stderr, "%s transcript round trip failed\n", name);
    goto cleanup;
  }
  signature[signature_size / 2] ^= 1;
  if (validate_signature(key, transcript, 2, signature, signature_size, &exception) ==
      DDS_SECURITY_VALIDATION_OK) {
    fprintf(stderr, "Tampered %s signature was accepted\n", name);
    goto cleanup;
  }
  ok = true;

cleanup:
  ddsrt_free(signature);
  EVP_PKEY_free(key);
  DDS_Security_Exception_reset(&exception);
  return ok;
}

int main(void) {
  const bool ok = round_trip("ML-DSA-65", EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65")) &&
                  round_trip("ECDSA P-256", EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"));
  return ok ? 0 : 1;
}
