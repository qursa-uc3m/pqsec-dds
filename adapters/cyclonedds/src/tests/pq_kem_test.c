/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "auth_algs.h"
#include "pq_kem.h"

#include <openssl/provider.h>

#include <stdlib.h>
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

  if (!pqsec_kem_is_available(kind) || !pqsec_kem_keypair_generate(kind, &keypair) ||
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

int main(void) {
  const AuthenticationAlgoKind_t algorithms[] = {
      AUTH_ALGO_KIND_ML_KEM_512, AUTH_ALGO_KIND_ML_KEM_768, AUTH_ALGO_KIND_ML_KEM_1024,
      AUTH_ALGO_KIND_X25519_ML_KEM_768, AUTH_ALGO_KIND_P256_ML_KEM_768};

  for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i) {
    if (exercise(algorithms[i]) != 0) {
      return 1;
    }
  }

  if (getenv("PQSEC_TEST_OQS_PROVIDER")) {
    const char *provider_name = getenv("PQSEC_OPENSSL_PROVIDER");
    OSSL_PROVIDER *provider;
    const AuthenticationAlgoKind_t experimental_algorithms[] = {
        AUTH_ALGO_KIND_FRODO_640_SHAKE, AUTH_ALGO_KIND_BIKE_L1, AUTH_ALGO_KIND_HQC_128};

    if (!provider_name || provider_name[0] == '\0') {
      provider_name = "oqsprovider";
    }
    provider = OSSL_PROVIDER_try_load(NULL, provider_name, 1);
    if (!provider) {
      fprintf(stderr, "Unable to load test provider %s\n", provider_name);
      return 1;
    }
    for (size_t i = 0; i < sizeof(experimental_algorithms) / sizeof(experimental_algorithms[0]);
         ++i) {
      if (exercise(experimental_algorithms[i]) != 0) {
        OSSL_PROVIDER_unload(provider);
        return 1;
      }
    }
    OSSL_PROVIDER_unload(provider);
  }
  return 0;
}
