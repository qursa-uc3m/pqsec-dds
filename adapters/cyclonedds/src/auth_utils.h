/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 * Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M) - Initial PQ integration
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * auth_utils.h - Authentication utility functions and helpers
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#ifndef AUTH_UTILS_H
#define AUTH_UTILS_H

#ifdef _WIN32
/* supposedly WinSock2 must be included before openssl 1.0.2 headers otherwise winsock will be used
 */
#include <WinSock2.h>
#endif
#include <openssl/evp.h>
#include <openssl/x509.h>
#ifdef PQ_CRYPTO
#include <openssl/provider.h>
#endif

#include "auth_algs.h"
#include "dds/ddsrt/time.h"
#include "dds/security/dds_security_api.h"
#include "oqs/oqs.h"

#define DDS_AUTH_PLUGIN_CONTEXT "Authentication"

typedef struct AuthenticationChallenge {
    unsigned char value[DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE];
} AuthenticationChallenge;

typedef struct {
    uint32_t length;
    X509 **buffer;
} X509Seq;

/* Return the subject name of contained in a X509 certificate
 * Note that the returned string should be freed.
 */
char *get_certificate_subject_name(X509 *cert,
                                   DDS_Security_SecurityException *ex) ddsrt_nonnull_all;

/* Return the expiry date of contained in a X509 certificate */
dds_time_t get_certificate_expiry(const X509 *cert);

/* Return the subject name of a X509 certificate DER
 * encoded. The DER encoded subject name is returned in
 * the provided buffer. The length of the allocated
 * buffer is returned
 *
 * return length of allocated buffer or -1 on error
 */
DDS_Security_ValidationResult_t get_subject_name_DER_encoded(const X509 *cert,
                                                             unsigned char **buffer, size_t *size,
                                                             DDS_Security_SecurityException *ex);

/* Load a X509 certificate for the provided data (PEM format) */
DDS_Security_ValidationResult_t load_X509_certificate_from_data(const char *data, int len,
                                                                X509 **x509Cert,
                                                                OSSL_LIB_CTX *oqs_libctx,
                                                                DDS_Security_SecurityException *ex);

/* Load a X509 certificate for the provided data (certificate uri) */
DDS_Security_ValidationResult_t load_X509_certificate(const char *data, X509 **x509Cert,
                                                      OSSL_LIB_CTX *oqs_libctx,
                                                      DDS_Security_SecurityException *ex);

/* Load a X509 certificate for the provided file */
DDS_Security_ValidationResult_t load_X509_certificate_from_file(const char *filename,
                                                                X509 **x509Cert,
                                                                OSSL_LIB_CTX *oqs_libctx,
                                                                DDS_Security_SecurityException *ex);

/* Load a Private Key for the provided data (private key uri) */
DDS_Security_ValidationResult_t load_X509_private_key(const char *data, const char *password,
                                                      EVP_PKEY **privateKey,
                                                      OSSL_LIB_CTX *oqs_libctx,
                                                      DDS_Security_SecurityException *ex);

/* Load a Certificate Revocation List (CRL) for the provided data (CRL uri) */
DDS_Security_ValidationResult_t load_X509_CRL(const char *data, X509_CRL **crl,
                                              DDS_Security_SecurityException *ex);

/* Validate an identity certificate against the identityCA
 * The provided identity certificate is checked if it is
 * signed by the identity corresponding to the identityCA.
 *
 * Note: Currently only a self signed CA is supported
 *       The function does not yet check OCSP
 *       for expiry of identity certificate.
 */
DDS_Security_ValidationResult_t verify_certificate(X509 *identityCert, X509 *identityCa,
                                                   X509_CRL *crl, OSSL_LIB_CTX *oqs_libctx,
                                                   DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t check_certificate_expiry(const X509 *cert,
                                                         DDS_Security_SecurityException *ex);
AuthenticationChallenge *generate_challenge(DDS_Security_SecurityException *ex);
DDS_Security_ValidationResult_t get_certificate_contents(X509 *cert, unsigned char **data,
                                                         uint32_t *size,
                                                         DDS_Security_SecurityException *ex);
DDS_Security_ValidationResult_t generate_dh_keys(EVP_PKEY **dhkey,
                                                 AuthenticationAlgoKind_t authKind,
                                                 DDS_Security_SecurityException *ex);
DDS_Security_ValidationResult_t dh_public_key_to_oct(EVP_PKEY *pkey, AuthenticationAlgoKind_t algo,
                                                     unsigned char **buffer, uint32_t *length,
                                                     DDS_Security_SecurityException *ex);
DDS_Security_ValidationResult_t dh_oct_to_public_key(EVP_PKEY **data, AuthenticationAlgoKind_t algo,
                                                     const unsigned char *str, uint32_t size,
                                                     DDS_Security_SecurityException *ex);
void free_ca_list_contents(X509Seq *ca_list);
DDS_Security_ValidationResult_t get_trusted_ca_list(const char *trusted_ca_dir, X509Seq *ca_list,
                                                    OSSL_LIB_CTX *oqs_libctx,
                                                    DDS_Security_SecurityException *ex);
char *string_from_data(const unsigned char *data, uint32_t size);
DDS_Security_ValidationResult_t
create_validate_asymmetrical_signature(bool create, EVP_PKEY *pkey, const unsigned char *data,
                                       const size_t dataLen, unsigned char **signature,
                                       size_t *signatureLen, DDS_Security_SecurityException *ex);

/* PQ Crypto */
#if defined(PQ_CRYPTO)
DDS_Security_ValidationResult_t
generate_kem_keys(uint8_t **kem_public_key, uint8_t **kem_secret_key, size_t *length_public_key,
                  size_t *length_secret_key, AuthenticationAlgoKind_t authKind);
DDS_Security_ValidationResult_t
decapsulate_kem_key(uint8_t **kem_secret, size_t *length_secret,
                    const DDS_Security_BinaryProperty_t *kem_ciphertext,
                    const DDS_Security_BinaryProperty_t *kem_public, uint8_t *kem_private,
                    AuthenticationAlgoKind_t authKind);

int load_oqs_provider(OSSL_LIB_CTX **plibctx, const char *modulename, const char *configfile);

DDS_Security_ValidationResult_t pq_public_key_to_oct(EVP_PKEY *pkey,
                                                     AuthenticationAlgoKind_t kagreeAlgoKind,
                                                     unsigned char **buffer, uint32_t *length,
                                                     DDS_Security_SecurityException *ex);
DDS_Security_ValidationResult_t pq_oct_to_public_key(EVP_PKEY **data, const unsigned char *str,
                                                     uint32_t size,
                                                     AuthenticationAlgoKind_t kagreeAlgoKind,
                                                     OSSL_LIB_CTX *libctx,
                                                     DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
pq_kem_encapsulation(EVP_PKEY *evp_public_key, size_t *length_ciphertext, size_t *length_secret,
                     uint8_t **handshake_kem_ciphertext, uint8_t **local_kem_secret,
                     const DDS_Security_BinaryProperty_t *kem_public,
                     AuthenticationAlgoKind_t kagreeAlgoKind, DDS_Security_SecurityException *ex,
                     OSSL_LIB_CTX *libctx);
DDS_Security_ValidationResult_t encapsulate_kem_key(uint8_t **kem_ciphertext, uint8_t **kem_secret,
                                                    size_t *length_ciphertext,
                                                    size_t *length_secret,
                                                    const DDS_Security_BinaryProperty_t *kem_public,
                                                    AuthenticationAlgoKind_t authKind);
DDS_Security_ValidationResult_t
create_pq_signature(EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **binary_properties,
                    const uint32_t n_bprops, unsigned char **kem_signature,
                    size_t *kem_signature_len, DDS_Security_SecurityException *ex,
                    uint8_t **sign_public_key, AuthenticationAlgoKind_t authKind,
                    OSSL_LIB_CTX *libctx);
DDS_Security_BinaryProperty_t *create_pqkey_property(const char *name, EVP_PKEY *pkey,
                                                     AuthenticationAlgoKind_t kagreeAlgoKind,
                                                     DDS_Security_SecurityException *ex);
DDS_Security_ValidationResult_t
pq_kem_decapsulation(EVP_PKEY *evp_public_key, uint8_t **kem_secret, size_t *length_secret,
                     const DDS_Security_BinaryProperty_t *kem_ciphertext,
                     AuthenticationAlgoKind_t authKind, DDS_Security_SecurityException *ex,
                     OSSL_LIB_CTX *libctx);
DDS_Security_ValidationResult_t
validate_pq_signature(EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **bprops,
                      uint32_t n_bprops, const unsigned char *signature, size_t signature_len,
                      DDS_Security_SecurityException *ex, OSSL_LIB_CTX *libctx);

DDS_Security_ValidationResult_t
validate_kem_public_key_in_token(const DDS_Security_BinaryProperty_t *kem_public_prop,
                                 AuthenticationAlgoKind_t expected_kind,
                                 DDS_Security_SecurityException *ex);

DDS_Security_ValidationResult_t
validate_kem_ciphertext_in_token(const DDS_Security_BinaryProperty_t *kem_ciphertext_prop,
                                 AuthenticationAlgoKind_t expected_kind,
                                 DDS_Security_SecurityException *ex);

#endif /* PQ_CRYPTO */

#endif /* AUTH_UTILS_H */
