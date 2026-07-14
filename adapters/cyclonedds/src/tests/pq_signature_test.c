/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "auth_utils.h"

#include <dds/ddsrt/heap.h>
#include <dds/security/core/dds_security_utils.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <string.h>

static EVP_PKEY *generate_mldsa44(void) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
  EVP_PKEY *key = NULL;
  if (!context || EVP_PKEY_keygen_init(context) != 1 || EVP_PKEY_generate(context, &key) != 1) {
    EVP_PKEY_free(key);
    key = NULL;
  }
  EVP_PKEY_CTX_free(context);
  return key;
}

int main(void) {
  const unsigned char challenge[] = {0x01, 0x02, 0x03, 0x04};
  const unsigned char ciphertext[] = {0x10, 0x20, 0x30};
  DDS_Security_BinaryProperty_t challenge_property = {
      .name = "challenge1",
      .value = {._length = sizeof(challenge), ._buffer = (unsigned char *)challenge}};
  DDS_Security_BinaryProperty_t ciphertext_property = {
      .name = "pqsec-dds.kem_ciphertext",
      .value = {._length = sizeof(ciphertext), ._buffer = (unsigned char *)ciphertext}};
  const DDS_Security_BinaryProperty_t *transcript[] = {&challenge_property, &ciphertext_property};
  DDS_Security_SecurityException exception = {0};
  EVP_PKEY *key = generate_mldsa44();
  unsigned char *signature = NULL;
  size_t signature_size = 0;
  int result = 1;

  if (!key ||
      create_pq_signature(key, transcript, 2, &signature, &signature_size, &exception, NULL,
                          AUTH_ALGO_KIND_ML_DSA_44, NULL) != DDS_SECURITY_VALIDATION_OK ||
      validate_pq_signature(key, transcript, 2, signature, signature_size, &exception, NULL) !=
          DDS_SECURITY_VALIDATION_OK) {
    fprintf(stderr, "ML-DSA transcript round trip failed\n");
    goto cleanup;
  }

  signature[0] ^= 1;
  if (validate_pq_signature(key, transcript, 2, signature, signature_size, &exception, NULL) ==
      DDS_SECURITY_VALIDATION_OK) {
    fprintf(stderr, "Tampered ML-DSA signature was accepted\n");
    goto cleanup;
  }

  result = 0;

cleanup:
  ddsrt_free(signature);
  EVP_PKEY_free(key);
  DDS_Security_Exception_reset(&exception);
  return result;
}
