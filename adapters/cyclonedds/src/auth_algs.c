/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "auth_algs.h"

#include <openssl/evp.h>
#include <string.h>

typedef struct {
  const char *configuration_name;
  AuthenticationAlgoKind_t kind;
  const char *openssl_name;
  const char *wire_name;
} AlgorithmInfo;

static const AlgorithmInfo kem_algorithms[] = {
    {"ecdh_p256", AUTH_ALGO_KIND_EC_PRIME256V1, "EC", "ECDH+prime256v1-CEUM"},
    {"dh_2048", AUTH_ALGO_KIND_RSA_2048, "DH", "DH+MODP-2048-256"},
    {"mlkem512", AUTH_ALGO_KIND_ML_KEM_512, "ML-KEM-512", "ML-KEM-512"},
    {"mlkem768", AUTH_ALGO_KIND_ML_KEM_768, "ML-KEM-768", "ML-KEM-768"},
    {"mlkem1024", AUTH_ALGO_KIND_ML_KEM_1024, "ML-KEM-1024", "ML-KEM-1024"},
    {"x25519_mlkem768", AUTH_ALGO_KIND_X25519_ML_KEM_768, "X25519MLKEM768", "X25519MLKEM768"},
    {"p256_mlkem768", AUTH_ALGO_KIND_P256_ML_KEM_768, "SecP256r1MLKEM768", "SecP256r1MLKEM768"},
    {"frodo640shake", AUTH_ALGO_KIND_FRODO_640_SHAKE, "frodo640shake", "FrodoKEM-640-SHAKE"},
    {"bikel1", AUTH_ALGO_KIND_BIKE_L1, "bikel1", "BIKE-L1"},
    {"hqc128", AUTH_ALGO_KIND_HQC_128, "hqc128", "HQC-128"},
    {NULL, AUTH_ALGO_KIND_UNKNOWN, NULL, NULL}};

static const AlgorithmInfo signature_algorithms[] = {
    {"rsa2048", AUTH_ALGO_KIND_RSA_2048, "RSA", "RSASSA-PSS-SHA256"},
    {"ecdsa_p256", AUTH_ALGO_KIND_EC_PRIME256V1, "EC", "ECDSA-SHA256"},
    {"mldsa44", AUTH_ALGO_KIND_ML_DSA_44, "ML-DSA-44", "ML-DSA-44"},
    {"mldsa65", AUTH_ALGO_KIND_ML_DSA_65, "ML-DSA-65", "ML-DSA-65"},
    {"mldsa87", AUTH_ALGO_KIND_ML_DSA_87, "ML-DSA-87", "ML-DSA-87"},
    {NULL, AUTH_ALGO_KIND_UNKNOWN, NULL, NULL}};

static const AlgorithmInfo *find_by_configuration_name(const AlgorithmInfo *table,
                                                       const char *name) {
  if (!name) {
    return NULL;
  }
  for (size_t i = 0; table[i].configuration_name; ++i) {
    if (strcmp(table[i].configuration_name, name) == 0) {
      return &table[i];
    }
  }
  return NULL;
}

static const AlgorithmInfo *find_by_kind(const AlgorithmInfo *table,
                                         AuthenticationAlgoKind_t kind) {
  for (size_t i = 0; table[i].configuration_name; ++i) {
    if (table[i].kind == kind) {
      return &table[i];
    }
  }
  return NULL;
}

static bool octets_equal_string(const DDS_Security_OctetSeq *octets, const char *text) {
  size_t length;
  if (!octets || !text || (!octets->_buffer && octets->_length != 0)) {
    return false;
  }
  length = strlen(text);
  return (octets->_length == length ||
          (octets->_length == length + 1 && octets->_buffer[length] == 0)) &&
         memcmp(octets->_buffer, text, length) == 0;
}

static AuthenticationAlgoKind_t find_wire_kind(const AlgorithmInfo *table,
                                               const DDS_Security_OctetSeq *name) {
  for (size_t i = 0; table[i].configuration_name; ++i) {
    if (octets_equal_string(name, table[i].wire_name)) {
      return table[i].kind;
    }
  }
  return AUTH_ALGO_KIND_UNKNOWN;
}

AuthenticationAlgoKind_t get_authentication_algo_kind(X509 *certificate) {
  AuthenticationAlgoKind_t result = AUTH_ALGO_KIND_UNKNOWN;
  EVP_PKEY *key;

  if (!certificate || !(key = X509_get_pubkey(certificate))) {
    return result;
  }

  if (EVP_PKEY_is_a(key, "ML-DSA-44") || EVP_PKEY_is_a(key, "MLDSA44")) {
    result = AUTH_ALGO_KIND_ML_DSA_44;
  } else if (EVP_PKEY_is_a(key, "ML-DSA-65") || EVP_PKEY_is_a(key, "MLDSA65")) {
    result = AUTH_ALGO_KIND_ML_DSA_65;
  } else if (EVP_PKEY_is_a(key, "ML-DSA-87") || EVP_PKEY_is_a(key, "MLDSA87")) {
    result = AUTH_ALGO_KIND_ML_DSA_87;
  } else if (EVP_PKEY_is_a(key, "RSA") && EVP_PKEY_get_bits(key) == 2048) {
    result = AUTH_ALGO_KIND_RSA_2048;
  } else if (EVP_PKEY_is_a(key, "EC") && EVP_PKEY_get_bits(key) == 256) {
    result = AUTH_ALGO_KIND_EC_PRIME256V1;
  }

  EVP_PKEY_free(key);
  return result;
}

const char *get_authentication_algo(AuthenticationAlgoKind_t kind) {
  const AlgorithmInfo *info = find_by_kind(signature_algorithms, kind);
  if (!info) {
    info = find_by_kind(kem_algorithms, kind);
  }
  return info ? info->configuration_name : "unknown";
}

const char *get_dsign_algo(AuthenticationAlgoKind_t kind) {
  const AlgorithmInfo *info = find_by_kind(signature_algorithms, kind);
  return info ? info->wire_name : "";
}

const char *get_kagree_algo(AuthenticationAlgoKind_t kind) {
  const AlgorithmInfo *info = find_by_kind(kem_algorithms, kind);
  return info ? info->wire_name : "";
}

AuthenticationAlgoKind_t get_dsign_algo_from_octseq(const DDS_Security_OctetSeq *name) {
  return find_wire_kind(signature_algorithms, name);
}

AuthenticationAlgoKind_t get_kagree_algo_from_octseq(const DDS_Security_OctetSeq *name) {
  return find_wire_kind(kem_algorithms, name);
}

AuthenticationAlgoKind_t get_default_kem_algorithm_kind(void) {
  const AlgorithmInfo *info = find_by_configuration_name(kem_algorithms, SELECTED_KEM_ALGORITHM);
  return info ? info->kind : AUTH_ALGO_KIND_UNKNOWN;
}

const char *get_default_kem_openssl_name(void) {
  return get_kem_openssl_name_by_kind(get_default_kem_algorithm_kind());
}

const char *get_kem_openssl_name_by_kind(AuthenticationAlgoKind_t kind) {
  const AlgorithmInfo *info = find_by_kind(kem_algorithms, kind);
  return info ? info->openssl_name : NULL;
}

const char *get_default_kem_name(void) {
  return SELECTED_KEM_ALGORITHM;
}

bool is_supported_kem_algorithm(const char *name) {
  return find_by_configuration_name(kem_algorithms, name) != NULL;
}

static const KemKeySizes kem_key_sizes[] = {{AUTH_ALGO_KIND_EC_PRIME256V1, 65, 32, 65},
                                            {AUTH_ALGO_KIND_RSA_2048, 256, 256, 256},
                                            {AUTH_ALGO_KIND_ML_KEM_512, 800, 1632, 768},
                                            {AUTH_ALGO_KIND_ML_KEM_768, 1184, 2400, 1088},
                                            {AUTH_ALGO_KIND_ML_KEM_1024, 1568, 3168, 1568},
                                            {AUTH_ALGO_KIND_X25519_ML_KEM_768, 1216, 0, 1120},
                                            {AUTH_ALGO_KIND_P256_ML_KEM_768, 1249, 0, 1153},
                                            {AUTH_ALGO_KIND_FRODO_640_SHAKE, 9616, 19888, 9720},
                                            {AUTH_ALGO_KIND_BIKE_L1, 1541, 5223, 1573},
                                            {AUTH_ALGO_KIND_HQC_128, 2249, 2289, 4481},
                                            {AUTH_ALGO_KIND_UNKNOWN, 0, 0, 0}};

static const KemKeySizes *find_sizes(AuthenticationAlgoKind_t kind) {
  for (size_t i = 0; kem_key_sizes[i].kind != AUTH_ALGO_KIND_UNKNOWN; ++i) {
    if (kem_key_sizes[i].kind == kind) {
      return &kem_key_sizes[i];
    }
  }
  return NULL;
}

size_t get_kem_public_key_size(AuthenticationAlgoKind_t kind) {
  const KemKeySizes *sizes = find_sizes(kind);
  return sizes ? sizes->public_key_size : 0;
}

size_t get_kem_ciphertext_size(AuthenticationAlgoKind_t kind) {
  const KemKeySizes *sizes = find_sizes(kind);
  return sizes ? sizes->ciphertext_size : 0;
}

size_t get_kem_secret_key_size(AuthenticationAlgoKind_t kind) {
  const KemKeySizes *sizes = find_sizes(kind);
  return sizes ? sizes->secret_key_size : 0;
}

bool validate_kem_public_key_size(AuthenticationAlgoKind_t kind, size_t actual_size,
                                  const char *algorithm_name) {
  (void)algorithm_name;
  return actual_size != 0 && actual_size == get_kem_public_key_size(kind);
}

bool get_kem_key_sizes(AuthenticationAlgoKind_t kind, KemKeySizes *sizes) {
  const KemKeySizes *found = find_sizes(kind);
  if (!found || !sizes) {
    return false;
  }
  *sizes = *found;
  return true;
}
