/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * auth_algs.c - Post-quantum authentication algorithms implementation
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#include "auth_algs.h"
#include "dds/security/dds_security_api_types.h"
#include <assert.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    const char *name;
    AuthenticationAlgoKind_t kind;
    const char *openssl_name;
    const char *dds_identifier;
} AlgorithmInfo;

// KEM algorithm mapping
static const AlgorithmInfo kem_algorithms[] = {
    // Classical
    {"ecdh_p256", AUTH_ALGO_KIND_EC_PRIME256V1, "prime256v1", "ECDH+prime256v1-CEUM"},
    {"dh_2048", AUTH_ALGO_KIND_RSA_2048, "dh", "DH+MODP-2048-256"},

    // ML-KEM
    {"mlkem512", AUTH_ALGO_KIND_ML_KEM_512, "mlkem512", "mlkem512"},
    {"mlkem768", AUTH_ALGO_KIND_ML_KEM_768, "mlkem768", "mlkem768"},
    {"mlkem1024", AUTH_ALGO_KIND_ML_KEM_1024, "mlkem1024", "mlkem1024"},

    // Hybrid (for future)
    {"X25519MLKEM768", AUTH_ALGO_KIND_X25519_ML_KEM_768, "X25519MLKEM768", "X25519MLKEM768"},
    {"p256_mlkem768", AUTH_ALGO_KIND_P256_ML_KEM_768, "p256_mlkem768", "p256_mlkem768"},

    // End marker
    {NULL, AUTH_ALGO_KIND_UNKNOWN, NULL, NULL}};

// Signature algorithm mapping
static const AlgorithmInfo signature_algorithms[] = {
    // Classical
    {"rsa2048", AUTH_ALGO_KIND_RSA_2048, "rsa", "RSASSA-PSS-SHA256"},
    {"ecdsa_p256", AUTH_ALGO_KIND_EC_PRIME256V1, "prime256v1", "ECDSA-SHA256"},

    // ML-DSA
    {"mldsa44", AUTH_ALGO_KIND_ML_DSA_44, "dilithium3", "dilithium3"},
    {"mldsa65", AUTH_ALGO_KIND_ML_DSA_65, "dilithium5", "dilithium5"},
    {"mldsa87", AUTH_ALGO_KIND_ML_DSA_87, "dilithium87", "dilithium87"},

    // End marker
    {NULL, AUTH_ALGO_KIND_UNKNOWN, NULL, NULL}};

static const AlgorithmInfo *find_algorithm_by_name(const AlgorithmInfo *table, const char *name) {
    if (!name)
        return NULL;

    for (int i = 0; table[i].name != NULL; i++) {
        if (strcmp(table[i].name, name) == 0) {
            return &table[i];
        }
    }
    return NULL;
}

static const AlgorithmInfo *find_algorithm_by_kind(const AlgorithmInfo *table,
                                                   AuthenticationAlgoKind_t kind) {
    for (int i = 0; table[i].name != NULL; i++) {
        if (table[i].kind == kind) {
            return &table[i];
        }
    }
    return NULL;
}

static bool str_octseq_equal(const char *str, const DDS_Security_OctetSeq *binstr) {
    size_t i;
    for (i = 0; str[i] && i < binstr->_length; i++)
        if ((unsigned char)str[i] != binstr->_buffer[i])
            return false;

    return (str[i] == 0 &&
            (i == binstr->_length || (i + 1 == binstr->_length && binstr->_buffer[i] == 0)));
}

AuthenticationAlgoKind_t get_authentication_algo_kind(X509 *cert) {
    AuthenticationAlgoKind_t kind = AUTH_ALGO_KIND_UNKNOWN;
    assert(cert);
#ifdef PQ_CRYPTO
    /* When compiling the plugin code, OQS provider should be added*/
    /*Actual Openssl does not obtain the pq attributes of a cert. With the provider functions they
     * can be obtained*/
    /* For the moment we use a predifined algorithm*/
    kind = AUTH_ALGO_KIND_ML_DSA_44;
#else
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey) {
        switch (EVP_PKEY_id(pkey)) {
        case EVP_PKEY_RSA:
            if (EVP_PKEY_bits(pkey) == 2048)
                kind = AUTH_ALGO_KIND_RSA_2048;
            break;
        case EVP_PKEY_EC:
            if (EVP_PKEY_bits(pkey) == 256)
                kind = AUTH_ALGO_KIND_EC_PRIME256V1;
            break;
        }
        EVP_PKEY_free(pkey);
    }
#endif
    return kind;
}

const char *get_authentication_algo(AuthenticationAlgoKind_t kind) {
    // Check signature algorithms first
    const AlgorithmInfo *info = find_algorithm_by_kind(signature_algorithms, kind);
    if (info)
        return info->name;

    // Check KEM algorithms
    info = find_algorithm_by_kind(kem_algorithms, kind);
    if (info)
        return info->name;

    // Handle legacy cases for compatibility
    switch (kind) {
    case AUTH_ALGO_KIND_RSA_2048:
        return "RSA-2048";
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        return "EC-prime256v1";
    case AUTH_ALGO_KIND_ML_KEM_768:
        return "mlkem768";
    case AUTH_ALGO_KIND_ML_DSA_44:
        return "mldsa44";
    default:
        return "unknown";
    }
}

const char *get_kem_openssl_name_by_kind(AuthenticationAlgoKind_t kind) {
    const AlgorithmInfo *info = find_algorithm_by_kind(kem_algorithms, kind);
    if (info) {
        return info->openssl_name;
    }

    // Fallback for compatibility
    switch (kind) {
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        return "prime256v1";
    case AUTH_ALGO_KIND_ML_KEM_512:
        return "mlkem512";
    case AUTH_ALGO_KIND_ML_KEM_768:
        return "mlkem768";
    case AUTH_ALGO_KIND_ML_KEM_1024:
        return "mlkem1024";
    case AUTH_ALGO_KIND_X25519_ML_KEM_768:
        return "X25519MLKEM768";
    case AUTH_ALGO_KIND_P256_ML_KEM_768:
        return "p256_mlkem768";
    default:
        return NULL;
    }
}

const char *get_dsign_algo(AuthenticationAlgoKind_t kind) {
    const AlgorithmInfo *info = find_algorithm_by_kind(signature_algorithms, kind);
    if (info)
        return info->dds_identifier;

    // Handle cases not in signature_algorithms table for compatibility
    switch (kind) {
#ifndef PQ_CRYPTO
    case AUTH_ALGO_KIND_RSA_2048:
        return "RSASSA-PSS-SHA256";
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        return "ECDSA-SHA256";
#else
    case AUTH_ALGO_KIND_ML_DSA_44:
        return "dilithium3";
#endif
    default:
        return "";
    }
}

const char *get_kagree_algo(AuthenticationAlgoKind_t kind) {
    const AlgorithmInfo *info = find_algorithm_by_kind(kem_algorithms, kind);
    if (info)
        return info->dds_identifier;

    // Handle cases not in kem_algorithms table for compatibility
    switch (kind) {
#ifndef PQ_CRYPTO
    case AUTH_ALGO_KIND_RSA_2048:
        return "DH+MODP-2048-256";
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        return "ECDH+prime256v1-CEUM";
#else
    case AUTH_ALGO_KIND_ML_KEM_768:
        return "mlkem768";
#endif
    default:
        return "";
    }
}

AuthenticationAlgoKind_t get_dsign_algo_from_octseq(const DDS_Security_OctetSeq *name) {
    // Try table lookup first
    for (int i = 0; signature_algorithms[i].name != NULL; i++) {
        if (str_octseq_equal(signature_algorithms[i].dds_identifier, name)) {
            return signature_algorithms[i].kind;
        }
    }

    // Fallback for compatibility with existing constants
#ifndef PQ_CRYPTO
    if (str_octseq_equal("RSASSA-PSS-SHA256", name))
        return AUTH_ALGO_KIND_RSA_2048;
    if (str_octseq_equal("ECDSA-SHA256", name))
        return AUTH_ALGO_KIND_EC_PRIME256V1;
#else
    if (str_octseq_equal("dilithium3", name))
        return AUTH_ALGO_KIND_ML_DSA_44;
#endif

    return AUTH_ALGO_KIND_UNKNOWN;
}

AuthenticationAlgoKind_t get_kagree_algo_from_octseq(const DDS_Security_OctetSeq *name) {
    // Try table lookup first
    for (int i = 0; kem_algorithms[i].name != NULL; i++) {
        if (str_octseq_equal(kem_algorithms[i].dds_identifier, name)) {
            return kem_algorithms[i].kind;
        }
    }

    // Fallback for compatibility with existing constants
#ifndef PQ_CRYPTO
    if (str_octseq_equal("DH+MODP-2048-256", name))
        return AUTH_ALGO_KIND_RSA_2048;
    if (str_octseq_equal("ECDH+prime256v1-CEUM", name))
        return AUTH_ALGO_KIND_EC_PRIME256V1;
#else
    if (str_octseq_equal("mlkem768", name))
        return AUTH_ALGO_KIND_ML_KEM_768;
#endif

    return AUTH_ALGO_KIND_UNKNOWN;
}

// =============================================================================
// COMPILE-TIME SELECTED ALGORITHM FUNCTIONS
// =============================================================================

AuthenticationAlgoKind_t get_default_kem_algorithm_kind(void) {
    const AlgorithmInfo *info = find_algorithm_by_name(kem_algorithms, SELECTED_KEM_ALGORITHM);
    if (!info) {
        // This should cause a compilation error if the algorithm is invalid
        assert(0 && "Invalid SELECTED_KEM_ALGORITHM");
        return AUTH_ALGO_KIND_UNKNOWN;
    }
    return info->kind;
}

const char *get_default_kem_openssl_name(void) {
    const AlgorithmInfo *info = find_algorithm_by_name(kem_algorithms, SELECTED_KEM_ALGORITHM);
    return info ? info->openssl_name : NULL;
}

const char *get_default_kem_name(void) { return SELECTED_KEM_ALGORITHM; }

// =============================================================================
// VALIDATION HELPER
// =============================================================================

bool is_supported_kem_algorithm(const char *name) {
    return find_algorithm_by_name(kem_algorithms, name) != NULL;
}

// Key sizes related:

// KEM algorithm key sizes (based on NIST specifications)
static const KemKeySizes kem_key_sizes[] = {
    // Classical algorithms
    {AUTH_ALGO_KIND_EC_PRIME256V1, 65, 32, 65}, // Uncompressed P-256 point
    {AUTH_ALGO_KIND_RSA_2048, 256, 256, 256},   // RSA-2048 sizes

    // ML-KEM algorithms (NIST standardized sizes)
    {AUTH_ALGO_KIND_ML_KEM_512, 800, 1632, 768},
    {AUTH_ALGO_KIND_ML_KEM_768, 1184, 2400, 1088},
    {AUTH_ALGO_KIND_ML_KEM_1024, 1568, 3168, 1568},

    // Hybrid algorithms (example sizes - adjust based on actual implementation)
    {AUTH_ALGO_KIND_X25519_ML_KEM_768, 1216, 2432, 1120}, // X25519(32) + ML-KEM-768
    {AUTH_ALGO_KIND_P256_ML_KEM_768, 1249, 2465, 1153},   // P-256(65) + ML-KEM-768

    // End marker
    {AUTH_ALGO_KIND_UNKNOWN, 0, 0, 0}};

static const KemKeySizes *find_kem_key_sizes(AuthenticationAlgoKind_t kind) {
    for (int i = 0; kem_key_sizes[i].kind != AUTH_ALGO_KIND_UNKNOWN; i++) {
        if (kem_key_sizes[i].kind == kind) {
            return &kem_key_sizes[i];
        }
    }
    return NULL;
}

size_t get_kem_public_key_size(AuthenticationAlgoKind_t kind) {
    const KemKeySizes *sizes = find_kem_key_sizes(kind);
    return sizes ? sizes->public_key_size : 0;
}

size_t get_kem_ciphertext_size(AuthenticationAlgoKind_t kind) {
    const KemKeySizes *sizes = find_kem_key_sizes(kind);
    return sizes ? sizes->ciphertext_size : 0;
}

size_t get_kem_secret_key_size(AuthenticationAlgoKind_t kind) {
    const KemKeySizes *sizes = find_kem_key_sizes(kind);
    return sizes ? sizes->secret_key_size : 0;
}

bool validate_kem_public_key_size(AuthenticationAlgoKind_t kind, size_t actual_size,
                                  const char *algorithm_name) {
    const KemKeySizes *sizes = find_kem_key_sizes(kind);
    if (!sizes) {
        return false; // Unknown algorithm
    }
    return actual_size == sizes->public_key_size;
}

bool get_kem_key_sizes(AuthenticationAlgoKind_t kind, KemKeySizes *sizes) {
    const KemKeySizes *found = find_kem_key_sizes(kind);
    if (!found || !sizes) {
        return false;
    }
    *sizes = *found;
    return true;
}