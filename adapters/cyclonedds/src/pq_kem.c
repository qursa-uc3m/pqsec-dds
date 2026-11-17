/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 */

#include "pq_kem.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <stdlib.h>
#include <string.h>

static EVP_PKEY_CTX *new_keygen_context(AuthenticationAlgoKind_t kind) {
  const char *name = get_kem_openssl_name_by_kind(kind);
  return name && name[0] ? EVP_PKEY_CTX_new_from_name(NULL, name, NULL) : NULL;
}

static bool export_public_key(EVP_PKEY *key, uint8_t **public_key, size_t *public_key_size) {
  *public_key_size = EVP_PKEY_get1_encoded_public_key(key, public_key);
  return *public_key_size != 0;
}

/* OpenSSL runs the FIPS 203 encapsulation key check here. A hybrid key with a
 * low-order X25519 share is refused when encapsulating to it. */
static EVP_PKEY *import_public_key(const char *name, const uint8_t *public_key,
                                   size_t public_key_size) {
  return EVP_PKEY_new_raw_public_key_ex(NULL, name, NULL, public_key, public_key_size);
}

void pqsec_kem_buffer_free(uint8_t *buffer) {
  OPENSSL_free(buffer);
}

void pqsec_kem_secret_free(uint8_t *secret, size_t secret_size) {
  OPENSSL_clear_free(secret, secret_size);
}

void pqsec_kem_keypair_free(pqsec_kem_keypair *keypair) {
  if (!keypair) {
    return;
  }
  EVP_PKEY_free(keypair->key);
  pqsec_kem_buffer_free(keypair->public_key);
  OPENSSL_cleanse(keypair, sizeof(*keypair));
  free(keypair);
}

bool pqsec_kem_keypair_generate(AuthenticationAlgoKind_t kind, pqsec_kem_keypair **keypair) {
  EVP_PKEY_CTX *context = NULL;
  pqsec_kem_keypair *result = NULL;

  if (!keypair) {
    return false;
  }
  *keypair = NULL;

  context = new_keygen_context(kind);
  result = calloc(1, sizeof(*result));
  if (!context || !result || EVP_PKEY_keygen_init(context) != 1 ||
      EVP_PKEY_generate(context, &result->key) != 1 ||
      !export_public_key(result->key, &result->public_key, &result->public_key_size)) {
    goto error;
  }

  result->kind = kind;
  EVP_PKEY_CTX_free(context);
  *keypair = result;
  return true;

error:
  EVP_PKEY_CTX_free(context);
  pqsec_kem_keypair_free(result);
  return false;
}

bool pqsec_kem_encapsulate(AuthenticationAlgoKind_t kind, const uint8_t *public_key,
                           size_t public_key_size, uint8_t **ciphertext, size_t *ciphertext_size,
                           uint8_t **shared_secret, size_t *shared_secret_size) {
  const char *name = get_kem_openssl_name_by_kind(kind);
  EVP_PKEY *remote_key = NULL;
  EVP_PKEY_CTX *context = NULL;

  if (!name || !public_key || !ciphertext || !ciphertext_size || !shared_secret ||
      !shared_secret_size) {
    return false;
  }
  *ciphertext = NULL;
  *ciphertext_size = 0;
  *shared_secret = NULL;
  *shared_secret_size = 0;

  remote_key = import_public_key(name, public_key, public_key_size);
  context = remote_key ? EVP_PKEY_CTX_new_from_pkey(NULL, remote_key, NULL) : NULL;
  if (!context || EVP_PKEY_encapsulate_init(context, NULL) != 1 ||
      EVP_PKEY_encapsulate(context, NULL, ciphertext_size, NULL, shared_secret_size) != 1) {
    goto error;
  }

  *ciphertext = OPENSSL_malloc(*ciphertext_size);
  *shared_secret = OPENSSL_malloc(*shared_secret_size);
  if (!*ciphertext || !*shared_secret ||
      EVP_PKEY_encapsulate(context, *ciphertext, ciphertext_size, *shared_secret,
                           shared_secret_size) != 1) {
    goto error;
  }

  EVP_PKEY_CTX_free(context);
  EVP_PKEY_free(remote_key);
  return true;

error:
  EVP_PKEY_CTX_free(context);
  EVP_PKEY_free(remote_key);
  pqsec_kem_buffer_free(*ciphertext);
  pqsec_kem_secret_free(*shared_secret, *shared_secret_size);
  *ciphertext = NULL;
  *ciphertext_size = 0;
  *shared_secret = NULL;
  *shared_secret_size = 0;
  return false;
}

bool pqsec_kem_decapsulate(const pqsec_kem_keypair *keypair, const uint8_t *ciphertext,
                           size_t ciphertext_size, uint8_t **shared_secret,
                           size_t *shared_secret_size) {
  EVP_PKEY_CTX *context = NULL;

  if (!keypair || !keypair->key || !ciphertext || !shared_secret || !shared_secret_size) {
    return false;
  }
  *shared_secret = NULL;
  *shared_secret_size = 0;

  context = EVP_PKEY_CTX_new_from_pkey(NULL, keypair->key, NULL);
  if (!context || EVP_PKEY_decapsulate_init(context, NULL) != 1 ||
      EVP_PKEY_decapsulate(context, NULL, shared_secret_size, ciphertext, ciphertext_size) != 1) {
    goto error;
  }

  *shared_secret = OPENSSL_malloc(*shared_secret_size);
  if (!*shared_secret || EVP_PKEY_decapsulate(context, *shared_secret, shared_secret_size,
                                              ciphertext, ciphertext_size) != 1) {
    goto error;
  }

  EVP_PKEY_CTX_free(context);
  return true;

error:
  EVP_PKEY_CTX_free(context);
  pqsec_kem_secret_free(*shared_secret, *shared_secret_size);
  *shared_secret = NULL;
  *shared_secret_size = 0;
  return false;
}

bool pqsec_derive_shared_secret(const uint8_t *kem_secret, size_t kem_secret_size,
                                const uint8_t transcript_hash[32],
                                uint8_t shared_secret[PQSEC_SHARED_SECRET_SIZE]) {
  static const char label[] = "pqsec-dds.auth:1.1 shared-secret";
  uint8_t info[sizeof label - 1 + 32];
  char digest[] = "SHA256";
  EVP_KDF *kdf;
  EVP_KDF_CTX *context;
  bool ok;

  if (!kem_secret || kem_secret_size == 0) {
    return false;
  }
  memcpy(info, label, sizeof label - 1);
  memcpy(info + sizeof label - 1, transcript_hash, 32);
  OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)kem_secret, kem_secret_size),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof info),
      OSSL_PARAM_construct_end()};

  kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  context = kdf ? EVP_KDF_CTX_new(kdf) : NULL;
  EVP_KDF_free(kdf);
  ok = context && EVP_KDF_derive(context, shared_secret, PQSEC_SHARED_SECRET_SIZE, params) == 1;
  EVP_KDF_CTX_free(context);
  return ok;
}
