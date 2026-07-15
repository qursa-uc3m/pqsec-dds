/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 */

#include "pq_kem.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>

#include <stdlib.h>

static EVP_PKEY_CTX *new_keygen_context(AuthenticationAlgoKind_t kind) {
  const char *name = get_kem_openssl_name_by_kind(kind);
  return name && name[0] ? EVP_PKEY_CTX_new_from_name(NULL, name, NULL) : NULL;
}

static bool export_public_key(EVP_PKEY *key, uint8_t **public_key, size_t *public_key_size) {
  *public_key_size = EVP_PKEY_get1_encoded_public_key(key, public_key);
  if (*public_key_size != 0) {
    return true;
  }

  if (EVP_PKEY_get_raw_public_key(key, NULL, public_key_size) != 1) {
    return false;
  }
  *public_key = OPENSSL_malloc(*public_key_size);
  return *public_key && EVP_PKEY_get_raw_public_key(key, *public_key, public_key_size) == 1;
}

static EVP_PKEY *import_public_key(const char *name, const uint8_t *public_key,
                                   size_t public_key_size) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
  EVP_PKEY *key = NULL;
  OSSL_PARAM params[] = {OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                           (void *)public_key, public_key_size),
                         OSSL_PARAM_construct_end()};

  if (context && EVP_PKEY_fromdata_init(context) == 1 &&
      EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) == 1) {
    EVP_PKEY_CTX_free(context);
    return key;
  }

  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(context);
  ERR_clear_error();
  return EVP_PKEY_new_raw_public_key_ex(NULL, name, NULL, public_key, public_key_size);
}

bool pqsec_kem_is_available(AuthenticationAlgoKind_t kind) {
  EVP_PKEY_CTX *context = new_keygen_context(kind);
  const bool available = context != NULL;
  if (!available) {
    ERR_clear_error();
  }
  EVP_PKEY_CTX_free(context);
  return available;
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
