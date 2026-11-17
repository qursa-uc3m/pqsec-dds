/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 *
 * OpenSSL EVP KEM operations for the algorithms of the profile, all supplied by
 * OpenSSL's default provider.
 */

#ifndef PQSEC_DDS_PQ_KEM_H
#define PQSEC_DDS_PQ_KEM_H

#include "auth_algs.h"

#include <openssl/evp.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct pqsec_kem_keypair {
  AuthenticationAlgoKind_t kind;
  EVP_PKEY *key;
  uint8_t *public_key;
  size_t public_key_size;
} pqsec_kem_keypair;

bool pqsec_kem_keypair_generate(AuthenticationAlgoKind_t kind, pqsec_kem_keypair **keypair);

void pqsec_kem_keypair_free(pqsec_kem_keypair *keypair);

bool pqsec_kem_encapsulate(AuthenticationAlgoKind_t kind, const uint8_t *public_key,
                           size_t public_key_size, uint8_t **ciphertext, size_t *ciphertext_size,
                           uint8_t **shared_secret, size_t *shared_secret_size);

bool pqsec_kem_decapsulate(const pqsec_kem_keypair *keypair, const uint8_t *ciphertext,
                           size_t ciphertext_size, uint8_t **shared_secret,
                           size_t *shared_secret_size);

void pqsec_kem_buffer_free(uint8_t *buffer);
void pqsec_kem_secret_free(uint8_t *secret, size_t secret_size);

#define PQSEC_SHARED_SECRET_SIZE 32

/* SharedSecret is SHA-256 of the KEM secret (DDS Security 1.2, 10.3.2.5.2). */
void pqsec_shared_secret(const uint8_t *kem_secret, size_t kem_secret_size,
                         uint8_t shared_secret[PQSEC_SHARED_SECRET_SIZE]);

#endif /* PQSEC_DDS_PQ_KEM_H */
