/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * auth_algs.h - Post-quantum authentication algorithms interface
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security through OpenSSL providers. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#ifndef AUTH_ALGS_H
#define AUTH_ALGS_H

#include <dds/security/dds_security_api_types.h>
#include <openssl/x509.h>
#include <stdbool.h>

// =============================================================================
// ALGORITHM TYPES
// =============================================================================

typedef enum {
  AUTH_ALGO_KIND_UNKNOWN = 0,

  // Classical algorithms
  AUTH_ALGO_KIND_RSA_2048,
  AUTH_ALGO_KIND_EC_PRIME256V1,

  // ML-KEM algorithms
  AUTH_ALGO_KIND_ML_KEM_512,
  AUTH_ALGO_KIND_ML_KEM_768,
  AUTH_ALGO_KIND_ML_KEM_1024,

  // ML-DSA algorithms
  AUTH_ALGO_KIND_ML_DSA_44,
  AUTH_ALGO_KIND_ML_DSA_65,
  AUTH_ALGO_KIND_ML_DSA_87,

  /* Native OpenSSL hybrid algorithms. */
  AUTH_ALGO_KIND_X25519_ML_KEM_768,
  AUTH_ALGO_KIND_P256_ML_KEM_768,

  /* Experimental algorithms exposed through oqs-provider. */
  AUTH_ALGO_KIND_FRODO_640_SHAKE,
  AUTH_ALGO_KIND_BIKE_L1,
  AUTH_ALGO_KIND_HQC_128
} AuthenticationAlgoKind_t;

typedef struct {
  AuthenticationAlgoKind_t kind;
  size_t public_key_size;
  size_t secret_key_size;
  size_t ciphertext_size;
} KemKeySizes;

// =============================================================================
// DEFAULT ALGORITHM SELECTION
// =============================================================================

// Default KEM algorithm if not specified at compile time
#ifndef SELECTED_KEM_ALGORITHM
#ifdef PQ_CRYPTO
#define SELECTED_KEM_ALGORITHM "mlkem768"
#else
#define SELECTED_KEM_ALGORITHM "ecdh_p256"
#endif
#endif

// =============================================================================
// FUNCTION DECLARATIONS
// =============================================================================

// Algorithm detection (from certificates)
AuthenticationAlgoKind_t get_authentication_algo_kind(X509 *cert);

// Algorithm information functions
const char *get_authentication_algo(AuthenticationAlgoKind_t kind);
const char *get_dsign_algo(AuthenticationAlgoKind_t kind);
const char *get_kagree_algo(AuthenticationAlgoKind_t kind);

// Algorithm selection from names
AuthenticationAlgoKind_t get_dsign_algo_from_octseq(const DDS_Security_OctetSeq *name);
AuthenticationAlgoKind_t get_kagree_algo_from_octseq(const DDS_Security_OctetSeq *name);

// Compile-time selected algorithm functions
AuthenticationAlgoKind_t get_default_kem_algorithm_kind(void);
const char *get_default_kem_openssl_name(void);
const char *get_kem_openssl_name_by_kind(AuthenticationAlgoKind_t kind);
const char *get_default_kem_name(void);

// Validation helper
bool is_supported_kem_algorithm(const char *name);

size_t get_kem_public_key_size(AuthenticationAlgoKind_t kind);
size_t get_kem_ciphertext_size(AuthenticationAlgoKind_t kind);
size_t get_kem_secret_key_size(AuthenticationAlgoKind_t kind);
bool validate_kem_public_key_size(AuthenticationAlgoKind_t kind, size_t actual_size,
                                  const char *algorithm_name);
bool get_kem_key_sizes(AuthenticationAlgoKind_t kind, KemKeySizes *sizes);

#endif // AUTH_ALGS_H
