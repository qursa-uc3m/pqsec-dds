/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "auth_algs.h"
#include "pq_kem.h"

#include <stdio.h>
#include <string.h>

static int exercise(AuthenticationAlgoKind_t kind) {
  pqsec_kem_keypair *keypair = NULL;
  uint8_t *ciphertext = NULL;
  uint8_t *sender_secret = NULL;
  uint8_t *receiver_secret = NULL;
  size_t ciphertext_size = 0;
  size_t sender_secret_size = 0;
  size_t receiver_secret_size = 0;
  uint8_t *invalid_ciphertext = NULL;
  uint8_t *invalid_secret = NULL;
  size_t invalid_ciphertext_size = 0;
  size_t invalid_secret_size = 0;
  int result = 1;

  if (!pqsec_kem_keypair_generate(kind, &keypair) ||
      keypair->public_key_size != get_kem_public_key_size(kind) ||
      !pqsec_kem_encapsulate(kind, keypair->public_key, keypair->public_key_size, &ciphertext,
                             &ciphertext_size, &sender_secret, &sender_secret_size) ||
      ciphertext_size != get_kem_ciphertext_size(kind) ||
      !pqsec_kem_decapsulate(keypair, ciphertext, ciphertext_size, &receiver_secret,
                             &receiver_secret_size) ||
      sender_secret_size != receiver_secret_size ||
      memcmp(sender_secret, receiver_secret, sender_secret_size) != 0) {
    fprintf(stderr, "KEM round trip failed for %s\n", get_authentication_algo(kind));
    goto cleanup;
  }

  /* OpenSSL must reject malformed network input before encapsulation. */
  if (pqsec_kem_encapsulate(kind, keypair->public_key, keypair->public_key_size - 1,
                            &invalid_ciphertext, &invalid_ciphertext_size, &invalid_secret,
                            &invalid_secret_size)) {
    fprintf(stderr, "Malformed public key was accepted\n");
    goto cleanup;
  }

  result = 0;

cleanup:
  pqsec_kem_buffer_free(ciphertext);
  pqsec_kem_secret_free(sender_secret, sender_secret_size);
  pqsec_kem_secret_free(receiver_secret, receiver_secret_size);
  pqsec_kem_buffer_free(invalid_ciphertext);
  pqsec_kem_secret_free(invalid_secret, invalid_secret_size);
  pqsec_kem_keypair_free(keypair);
  return result;
}

/* A replier must refuse an encapsulation key that fails the FIPS 203 check, and
 * for the hybrid one whose X25519 share is a low-order point. */
static int invalid_public_keys(void) {
  uint8_t key[1216];
  pqsec_kem_keypair *keypair = NULL;
  uint8_t *ciphertext = NULL, *secret = NULL;
  size_t ciphertext_size = 0, secret_size = 0;
  int result = 1;

  memset(key, 0xff, sizeof key);
  if (pqsec_kem_encapsulate(AUTH_ALGO_KIND_ML_KEM_768, key, 1184, &ciphertext, &ciphertext_size,
                            &secret, &secret_size)) {
    fprintf(stderr, "ML-KEM-768 key with coefficients above q was accepted\n");
    goto cleanup;
  }
  if (!pqsec_kem_keypair_generate(AUTH_ALGO_KIND_X25519_ML_KEM_768, &keypair) ||
      keypair->public_key_size != sizeof key) {
    goto cleanup;
  }
  memcpy(key, keypair->public_key, sizeof key);
  memset(key + 1184, 0, 32);
  if (pqsec_kem_encapsulate(AUTH_ALGO_KIND_X25519_ML_KEM_768, key, sizeof key, &ciphertext,
                            &ciphertext_size, &secret, &secret_size)) {
    fprintf(stderr, "encapsulated to an X25519MLKEM768 key with a zero X25519 share\n");
    goto cleanup;
  }
  result = 0;

cleanup:
  pqsec_kem_buffer_free(ciphertext);
  pqsec_kem_secret_free(secret, secret_size);
  pqsec_kem_keypair_free(keypair);
  return result;
}

/* The X25519 part of a hybrid ciphertext is checked; the ML-KEM part is not,
 * because ML-KEM decapsulation of a wrong ciphertext returns a different key. */
static int invalid_ciphertexts(void) {
  pqsec_kem_keypair *keypair = NULL;
  uint8_t *ciphertext = NULL, *secret = NULL, *decapsulated = NULL;
  size_t ciphertext_size = 0, secret_size = 0, decapsulated_size = 0;
  int result = 1;

  if (!pqsec_kem_keypair_generate(AUTH_ALGO_KIND_X25519_ML_KEM_768, &keypair) ||
      !pqsec_kem_encapsulate(AUTH_ALGO_KIND_X25519_ML_KEM_768, keypair->public_key,
                             keypair->public_key_size, &ciphertext, &ciphertext_size, &secret,
                             &secret_size)) {
    goto cleanup;
  }
  if (pqsec_kem_decapsulate(keypair, ciphertext, ciphertext_size - 1, &decapsulated,
                            &decapsulated_size)) {
    fprintf(stderr, "short X25519MLKEM768 ciphertext was accepted\n");
    goto cleanup;
  }
  ciphertext[0] ^= 1;
  if (!pqsec_kem_decapsulate(keypair, ciphertext, ciphertext_size, &decapsulated,
                             &decapsulated_size) ||
      (decapsulated_size == secret_size && memcmp(decapsulated, secret, secret_size) == 0)) {
    fprintf(stderr, "altered ML-KEM ciphertext did not decapsulate to a different key\n");
    goto cleanup;
  }
  pqsec_kem_secret_free(decapsulated, decapsulated_size);
  decapsulated = NULL;
  ciphertext[0] ^= 1;
  memset(ciphertext + ciphertext_size - 32, 0, 32);
  if (pqsec_kem_decapsulate(keypair, ciphertext, ciphertext_size, &decapsulated,
                            &decapsulated_size)) {
    fprintf(stderr, "X25519MLKEM768 ciphertext with a zero X25519 share was accepted\n");
    goto cleanup;
  }
  result = 0;

cleanup:
  pqsec_kem_buffer_free(ciphertext);
  pqsec_kem_secret_free(secret, secret_size);
  pqsec_kem_secret_free(decapsulated, decapsulated_size);
  pqsec_kem_keypair_free(keypair);
  return result;
}

int main(void) {
  const AuthenticationAlgoKind_t algorithms[] = {
      AUTH_ALGO_KIND_ML_KEM_768, AUTH_ALGO_KIND_ML_KEM_1024, AUTH_ALGO_KIND_X25519_ML_KEM_768};

  for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i) {
    if (exercise(algorithms[i]) != 0) {
      return 1;
    }
  }
  return invalid_public_keys() || invalid_ciphertexts();
}
