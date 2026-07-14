/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 * Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M) - Initial PQ integration
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * auth_utils.c - Authentication utility functions implementation
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#include <assert.h>
#include <string.h>

#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/filesystem.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/io.h"
#include "dds/ddsrt/retcode.h"
#include "dds/ddsrt/static_assert.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/time.h"
#include "dds/security/core/dds_security_serialize.h"
#include "dds/security/core/dds_security_utils.h"
#include "dds/security/dds_security_api_defs.h"
#include "dds/security/openssl_support.h"
#include "auth_utils.h"
#include "debug.h"

#define MAX_TRUSTED_CA 100

typedef enum {
    AUTH_CONF_ITEM_PREFIX_UNKNOWN,
    AUTH_CONF_ITEM_PREFIX_FILE,
    AUTH_CONF_ITEM_PREFIX_DATA,
    AUTH_CONF_ITEM_PREFIX_PKCS11
} AuthConfItemPrefix_t;

/* Return a string that contains an openssl error description
 * When a openssl function returns an error this function can be
 * used to retrieve a descriptive error string.
 * Note that the returned string should be freed.
 */
static char *get_openssl_error_message(void) {
    DBG_TRACE("get_openssl_error_message() called\n");
    char *msg, *buf = NULL;
    size_t len;
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        DBG_ERR("BIO_new failed\n");
        return ddsrt_strdup("BIO_new failed");
    }

    ERR_print_errors(bio);
    len = (size_t)BIO_get_mem_data(bio, &buf);
    msg = ddsrt_malloc(len + 1);
    memcpy(msg, buf, len);
    msg[len] = '\0';
    BIO_free(bio);
    return msg;
}

char *get_certificate_subject_name(X509 *cert, DDS_Security_SecurityException *ex) {
    DBG_TRACE("get_certificate_subject_name() called\n");
    X509_NAME *name;
    assert(cert);
    name = X509_get_subject_name(cert);
    if (!name) {
        DBG_ERR("X509_get_subject_name failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "X509_get_subject_name failed : ");
        return NULL;
    }
    char *subject_openssl = X509_NAME_oneline(name, NULL, 0);
    char *subject = ddsrt_strdup(subject_openssl);
    OPENSSL_free(subject_openssl);
    DBG_TRACE("Retrieved subject name\n");
    return subject;
}

dds_time_t get_certificate_expiry(const X509 *cert) {
    DBG_TRACE("get_certificate_expiry() called\n");
    assert(cert);
    ASN1_TIME *asn1 = X509_get_notAfter(cert);
    if (!asn1) {
        DBG_ERR("X509_get_notAfter returned NULL\n");
        return DDS_TIME_INVALID;
    }
    int days, seconds;
    if (ASN1_TIME_diff(&days, &seconds, NULL, asn1) != 1) {
        DBG_ERR("ASN1_TIME_diff failed\n");
        return DDS_TIME_INVALID;
    }
    static const dds_duration_t secs_in_day = 86400;
    const dds_time_t now = dds_time();
    const int64_t max_valid_days_to_wait = (INT64_MAX - now) / DDS_NSECS_IN_SEC / secs_in_day;
    if (days < max_valid_days_to_wait) {
        dds_duration_t delta =
            ((dds_duration_t)seconds + ((dds_duration_t)days * secs_in_day)) * DDS_NSECS_IN_SEC;
        DBG_TRACE("Certificate expires in %d days, %d seconds\n", days, seconds);
        return now + delta;
    }
    DBG_TRACE("Certificate expiry too far, returning DDS_NEVER\n");
    return DDS_NEVER;
}

DDS_Security_ValidationResult_t get_subject_name_DER_encoded(const X509 *cert,
                                                             unsigned char **buffer, size_t *size,
                                                             DDS_Security_SecurityException *ex) {
    DBG_TRACE("get_subject_name_DER_encoded() called\n");
    assert(cert && buffer && size);
    *size = 0;

    X509_NAME *name = X509_get_subject_name((X509 *)cert);
    if (!name) {
        DBG_ERR("X509_get_subject_name failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "X509_get_subject_name failed : ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    int32_t sz = i2d_X509_NAME(name, NULL);
    if (sz <= 0) {
        DBG_ERR("i2d_X509_NAME failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "i2d_X509_NAME failed : ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    unsigned char *tmp = NULL;
    sz = i2d_X509_NAME(name, &tmp);
    if (sz <= 0) {
        DBG_ERR("i2d_X509_NAME second call failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "i2d_X509_NAME failed : ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    *size = (size_t)sz;
    *buffer = ddsrt_malloc(*size);
    memcpy(*buffer, tmp, *size);
    OPENSSL_free(tmp);
    DBG_TRACE("Subject name DER encoded (size=%zu)\n", *size);
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t check_key_type_and_size(EVP_PKEY *key, int isPrivate,
                                                               DDS_Security_SecurityException *ex) {
    const char *sub = isPrivate ? "private key" : "certificate";
    assert(key);
#ifdef PQ_CRYPTO
    DBG_TRACE("PQ mode: skipping key size check\n");
    return DDS_SECURITY_VALIDATION_OK;
#endif

    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA: {
        int bits = EVP_PKEY_bits(key);
        DBG_TRACE("Checking RSA %s (bits=%d)\n", sub, bits);
        if (bits != 2048) {
            DBG_ERR("RSA %s has unsupported key size (%d)\n", sub, bits);
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "RSA %s has unsupported key size (%d)", sub, bits);
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        if (isPrivate) {
            RSA *rsaKey = EVP_PKEY_get1_RSA(key);
            bool fail = (rsaKey && RSA_check_key(rsaKey) != 1);
            RSA_free(rsaKey);
            if (fail) {
                DBG_ERR("RSA private key check failed\n");
                DDS_Security_Exception_set_with_openssl_error(
                    ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                    DDS_SECURITY_VALIDATION_FAILED, "RSA key not correct : ");
                return DDS_SECURITY_VALIDATION_FAILED;
            }
        }
        return DDS_SECURITY_VALIDATION_OK;
    }
    case EVP_PKEY_EC: {
        int bits = EVP_PKEY_bits(key);
        DBG_TRACE("Checking EC %s (bits=%d)\n", sub, bits);
        if (bits != 256) {
            DBG_ERR("EC %s has unsupported key size (%d)\n", sub, bits);
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "EC %s has unsupported key size (%d)", sub, bits);
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(key);
        bool fail = (ecKey && EC_KEY_check_key(ecKey) != 1);
        EC_KEY_free(ecKey);
        if (fail) {
            DBG_ERR("EC key check failed\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED, "EC key not correct : ");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        return DDS_SECURITY_VALIDATION_OK;
    }
    default:
        DBG_ERR("Unsupported key type (id=%d)\n", EVP_PKEY_id(key));
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "%s has not supported type",
                                   sub);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
}

static DDS_Security_ValidationResult_t
check_certificate_type_and_size(X509 *cert, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering check_certificate_type_and_size\n");
    assert(cert);

    DBG_TRACE("Retrieving public key from certificate\n");
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (!pkey) {
#ifdef PQ_CRYPTO
        DBG_WARN("X509_get_pubkey failed, possibly due to PQ certificate. Attempting PQ "
                 "validation...\n");
        // For now, we'll assume PQ certificates are valid if we're in PQ mode
        // TODO: Implement proper PQ certificate validation
        return DDS_SECURITY_VALIDATION_OK;
#else
        DBG_ERR("X509_get_pubkey failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "X509_get_pubkey failed");
        return DDS_SECURITY_VALIDATION_FAILED;
#endif
    }

    DBG_TRACE("Public key retrieved, checking key type and size\n");
    DDS_Security_ValidationResult_t result = check_key_type_and_size(pkey, false, ex);
    if (result == DDS_SECURITY_VALIDATION_OK) {
        DBG_TRACE("Key type and size are acceptable\n");
    } else {
        DBG_ERR("Key type or size check failed\n");
    }
    EVP_PKEY_free(pkey);

    DBG_TRACE("Exiting check_certificate_type_and_size with result=%d\n", result);
    return result;
}

DDS_Security_ValidationResult_t check_certificate_expiry(const X509 *cert,
                                                         DDS_Security_SecurityException *ex) {
    assert(cert);
    if (X509_cmp_current_time(X509_get_notBefore(cert)) == 0) {
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_CODE,
            DDS_SECURITY_VALIDATION_FAILED, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_MESSAGE);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    if (X509_cmp_current_time(X509_get_notAfter(cert)) == 0) {
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_EXPIRED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   DDS_SECURITY_ERR_CERT_EXPIRED_MESSAGE);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t
load_X509_certificate_from_bio(BIO *bio, X509 **x509Cert, OSSL_LIB_CTX *oqs_libctx,
                               DDS_Security_SecurityException *ex) {
    assert(x509Cert);

    if (!(*x509Cert = PEM_read_bio_X509(bio, NULL, NULL, NULL))) {
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to parse certificate: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (get_authentication_algo_kind(*x509Cert) == AUTH_ALGO_KIND_UNKNOWN) {
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_AUTH_ALGO_KIND_UNKNOWN_CODE,
            DDS_SECURITY_VALIDATION_FAILED, DDS_SECURITY_ERR_CERT_AUTH_ALGO_KIND_UNKNOWN_MESSAGE);
        X509_free(*x509Cert);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    return DDS_SECURITY_VALIDATION_OK;
}

static BIO *load_file_into_BIO(const char *filename, DDS_Security_SecurityException *ex) {
    DBG_TRACE("load_file_into_BIO() called (file='%s')\n", filename);
    BIO *bio;
    FILE *fp;
    size_t n;
    char tmp[512];
    int orig_errno = errno;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        DBG_ERR("BIO_new_mem failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "load_file_into_BIO: BIO_new_mem (BIO_s_mem ())");
        return NULL;
    }

    DDSRT_WARNING_MSVC_OFF(4996);
    fp = fopen(filename, "r");
    if (!fp) {
        DBG_ERR("fopen failed for '%s'\n", filename);
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_INVALID_FILE_PATH_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "load_file_into_BIO: " DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE, filename);
        BIO_free(bio);
        return NULL;
    }
    DDSRT_WARNING_MSVC_ON(4996);

    if (fseek(fp, 0, SEEK_END) != 0) {
        DBG_ERR("fseek to end failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "load_file_into_BIO: seek to end failed");
        fclose(fp);
        BIO_free(bio);
        return NULL;
    }
    errno = 0;
    long max = ftell(fp);
    if (max < 0 || errno) {
        DBG_ERR("ftell failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "load_file_into_BIO: ftell failed");
        fclose(fp);
        BIO_free(bio);
        return NULL;
    }
    errno = orig_errno;
    if (fseek(fp, 0, SEEK_SET) != 0) {
        DBG_ERR("fseek to begin failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "load_file_into_BIO: seek to begin failed");
        fclose(fp);
        BIO_free(bio);
        return NULL;
    }

    size_t remain = (size_t)max;
    while ((n = fread(tmp, 1, sizeof(tmp), fp)) > 0 && remain > 0) {
        if (!BIO_write(bio, tmp, (int)n)) {
            DBG_ERR("BIO_write failed\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "load_file_into_BIO: failed to append data to BIO");
            fclose(fp);
            BIO_free(bio);
            return NULL;
        }
        remain -= (n <= remain) ? n : remain;
    }
    if (!feof(fp)) {
        DBG_ERR("fread error\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "load_file_into_BIO: read from failed");
        fclose(fp);
        BIO_free(bio);
        return NULL;
    }
    fclose(fp);
    DBG_TRACE("Loaded file into BIO successfully\n");
    return bio;
}

DDS_Security_ValidationResult_t
load_X509_certificate_from_data(const char *data, int len, X509 **x509Cert,
                                OSSL_LIB_CTX *oqs_libctx, DDS_Security_SecurityException *ex) {
    DBG_TRACE("load_X509_certificate_from_data() called (len=%d)\n", len);
    BIO *bio;

    bio = BIO_new_mem_buf((void *)data, len);
    if (!bio) {
        DBG_ERR("BIO_new_mem_buf failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "BIO_new_mem_buf failed");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    const DDS_Security_ValidationResult_t result =
        load_X509_certificate_from_bio(bio, x509Cert, oqs_libctx, ex);
    BIO_free(bio);
    return result;
}

DDS_Security_ValidationResult_t
load_X509_certificate_from_file(const char *filename, X509 **x509Cert, OSSL_LIB_CTX *oqs_libctx,
                                DDS_Security_SecurityException *ex) {
    DBG_TRACE("load_X509_certificate_from_file() called (file='%s')\n", filename);
    BIO *bio = load_file_into_BIO(filename, ex);
    if (!bio) {
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    const DDS_Security_ValidationResult_t result =
        load_X509_certificate_from_bio(bio, x509Cert, oqs_libctx, ex);
    BIO_free(bio);
    return result;
}

static DDS_Security_ValidationResult_t
load_private_key_from_data(const char *data, const char *password, EVP_PKEY **privateKey,
                           OSSL_LIB_CTX *oqs_libctx, DDS_Security_SecurityException *ex) {
    DBG_TRACE("load_private_key_from_data() called\n");
    BIO *bio = BIO_new_mem_buf((void *)data, -1);
    if (!bio) {
        DBG_ERR("BIO_new_mem_buf failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "BIO_new_mem_buf failed");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    *privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)(password ? password : ""));
    BIO_free(bio);
    if (!*privateKey) {
        DBG_ERR("PEM_read_bio_PrivateKey failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to parse private key: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Loaded private key from data\n");
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t
load_private_key_from_file(const char *filepath, const char *password, EVP_PKEY **privateKey,
                           OSSL_LIB_CTX *oqs_libctx, DDS_Security_SecurityException *ex) {
    DBG_TRACE("load_private_key_from_file() called (file='%s')\n", filepath);
    BIO *bio = load_file_into_BIO(filepath, ex);
    if (!bio) {
        return DDS_SECURITY_VALIDATION_FAILED;
    }

#ifdef PQ_CRYPTO
    *privateKey = PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, NULL, oqs_libctx, NULL);
    if (!*privateKey) {
        DBG_ERR("PEM_read_bio_PrivateKey_ex failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to parse private key: ");
        BIO_free(bio);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Loaded PQ private key from file\n");
#else
    *privateKey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void *)(password ? password : ""));
    if (!*privateKey) {
        DBG_ERR("PEM_read_bio_PrivateKey failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to parse private key: ");
        BIO_free(bio);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Loaded private key from file\n");
#endif

    BIO_free(bio);
    return DDS_SECURITY_VALIDATION_OK;
}

static AuthConfItemPrefix_t get_conf_item_type(const char *str, char **data) {
    const char *f = "file:", *d = "data:,", *p = "pkcs11:";
    size_t sf = strlen(f), sd = strlen(d), sp = strlen(p);
    const char *ptr;
    assert(str);
    assert(data);

    for (ptr = str; *ptr == ' ' || *ptr == '\t'; ptr++)
        /* ignore leading whitespace */;

    if (strncmp(ptr, f, sf) == 0) {
        size_t e = strncmp(ptr + sf, "//", 2) == 0 ? 2 : 0;
        *data = ddsrt_strdup(ptr + sf + e);
        return AUTH_CONF_ITEM_PREFIX_FILE;
    }
    if (strncmp(ptr, d, sd) == 0) {
        *data = ddsrt_strdup(ptr + sd);
        return AUTH_CONF_ITEM_PREFIX_DATA;
    }
    if (strncmp(ptr, p, sp) == 0) {
        *data = ddsrt_strdup(ptr + sp);
        return AUTH_CONF_ITEM_PREFIX_PKCS11;
    }
    return AUTH_CONF_ITEM_PREFIX_UNKNOWN;
}

DDS_Security_ValidationResult_t load_X509_certificate(const char *data, X509 **x509Cert,
                                                      OSSL_LIB_CTX *oqs_libctx,
                                                      DDS_Security_SecurityException *ex) {
    DDS_Security_ValidationResult_t result;
    char *contents = NULL;
    assert(data);
    assert(x509Cert);
    DBG_TRACE("load_X509_certificate() called\n");

    switch (get_conf_item_type(data, &contents)) {
    case AUTH_CONF_ITEM_PREFIX_FILE:
        result = load_X509_certificate_from_file(contents, x509Cert, oqs_libctx, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_DATA:
        result = load_X509_certificate_from_data(contents, (int)strlen(contents), x509Cert,
                                                 oqs_libctx, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_PKCS11:
        DBG_ERR("PKCS11 certificate format not supported\n");
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   (int)result,
                                   "Certificate pkcs11 format currently not supported:\n%s", data);
        break;
    default:
        DBG_ERR("Wrong certificate format\n");
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   (int)result, "Specified certificate has wrong format:\n%s",
                                   data);
        break;
    }
    ddsrt_free(contents);

    if (result == DDS_SECURITY_VALIDATION_OK) {
        DBG_TRACE("Checking certificate type/size and expiry\n");
        if (check_certificate_type_and_size(*x509Cert, ex) != DDS_SECURITY_VALIDATION_OK ||
            check_certificate_expiry(*x509Cert, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Certificate validation failed\n");
            result = DDS_SECURITY_VALIDATION_FAILED;
            X509_free(*x509Cert);
        } else {
            DBG_TRACE("Certificate validated successfully\n");
        }
    }
    return result;
}

DDS_Security_ValidationResult_t load_X509_private_key(const char *data, const char *password,
                                                      EVP_PKEY **privateKey,
                                                      OSSL_LIB_CTX *oqs_libctx,
                                                      DDS_Security_SecurityException *ex) {
    DDS_Security_ValidationResult_t result;
    char *contents = NULL;
    assert(data);
    assert(privateKey);
    DBG_TRACE("load_X509_private_key() called (data='%s')\n", data);

    switch (get_conf_item_type(data, &contents)) {
    case AUTH_CONF_ITEM_PREFIX_FILE:
        DBG_TRACE("Loading private key from file\n");
        result = load_private_key_from_file(contents, password, privateKey, oqs_libctx, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_DATA:
        DBG_TRACE("Loading private key from data\n");
        result = load_private_key_from_data(contents, password, privateKey, oqs_libctx, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_PKCS11:
        DBG_ERR("PKCS11 format not supported\n");
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   (int)result,
                                   "PrivateKey pkcs11 format currently not supported:\n%s", data);
        break;
    default:
        DBG_ERR("Wrong PrivateKey format\n");
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   (int)result, "Specified PrivateKey has wrong format:\n%s", data);
        break;
    }
    ddsrt_free(contents);

    if (result == DDS_SECURITY_VALIDATION_OK) {
        if (check_key_type_and_size(*privateKey, true, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("PrivateKey type/size check failed\n");
            result = DDS_SECURITY_VALIDATION_FAILED;
            EVP_PKEY_free(*privateKey);
        } else {
            DBG_TRACE("PrivateKey loaded and validated\n");
        }
    }
    return result;
}

static DDS_Security_ValidationResult_t load_CRL_from_file(const char *filepath, X509_CRL **crl,
                                                          DDS_Security_SecurityException *ex) {
    BIO *bio;
    assert(filepath);
    assert(crl);
    DBG_TRACE("load_CRL_from_file() called (path='%s')\n", filepath);

    bio = load_file_into_BIO(filepath, ex);
    if (!bio) {
        DBG_ERR("BIO_new for CRL file failed\n");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    *crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (*crl == NULL) {
        DBG_ERR("PEM_read_bio_X509_CRL failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to read CRL: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Loaded CRL from file\n");
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t load_CRL_from_data(const char *data, X509_CRL **crl,
                                                          DDS_Security_SecurityException *ex) {
    BIO *bio;
    assert(data);
    assert(crl);
    DBG_TRACE("load_CRL_from_data() called\n");

    bio = BIO_new_mem_buf((void *)data, -1);
    if (!bio) {
        DBG_ERR("BIO_new_mem_buf failed for CRL data\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "BIO_new_mem_buf failed");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    *crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (*crl == NULL) {
        DBG_ERR("PEM_read_bio_X509_CRL failed for data\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to read CRL: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Loaded CRL from data\n");
    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t load_X509_CRL(const char *data, X509_CRL **crl,
                                              DDS_Security_SecurityException *ex) {
    DDS_Security_ValidationResult_t result;
    char *contents = NULL;
    assert(data);
    assert(crl);
    DBG_TRACE("load_X509_CRL() called\n");

    switch (get_conf_item_type(data, &contents)) {
    case AUTH_CONF_ITEM_PREFIX_FILE:
        result = load_CRL_from_file(contents, crl, ex);
        break;
    case AUTH_CONF_ITEM_PREFIX_DATA:
        result = load_CRL_from_data(contents, crl, ex);
        break;
    default:
        DBG_ERR("Wrong CRL format\n");
        result = DDS_SECURITY_VALIDATION_FAILED;
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   (int)result, "Specified CRL has wrong format:\n%s", data);
        break;
    }
    ddsrt_free(contents);

    if (result == DDS_SECURITY_VALIDATION_OK) {
        DBG_TRACE("CRL loaded successfully\n");
    }
    return result;
}

DDS_Security_ValidationResult_t verify_certificate(X509 *identityCert, X509 *identityCa,
                                                   X509_CRL *crl, OSSL_LIB_CTX *oqs_libctx,
                                                   DDS_Security_SecurityException *ex) {
    X509_STORE_CTX *ctx;
    X509_STORE *store;
    unsigned long verify_flags = 0;
    assert(identityCert);
    assert(identityCa);
    DBG_TRACE("verify_certificate() called\n");

    store = X509_STORE_new();
    if (!store) {
        DBG_ERR("X509_STORE_new failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "X509_STORE_new failed : ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (X509_STORE_add_cert(store, identityCa) != 1) {
        DBG_ERR("X509_STORE_add_cert failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "X509_STORE_add_cert failed : ");
        X509_STORE_free(store);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Added CA to X509 store\n");

    if (crl) {
        if (X509_STORE_add_crl(store, crl) == 0) {
            DBG_ERR("X509_STORE_add_crl failed\n");
            X509_STORE_free(store);
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        verify_flags = X509_V_FLAG_CRL_CHECK;
        DBG_TRACE("Added CRL and set verify_flags\n");
    }

#ifdef PQ_CRYPTO
    DBG_TRACE("Using OQS provider for verification\n");
    ctx = X509_STORE_CTX_new_ex(oqs_libctx, "oqsprovider");
#else
    ctx = X509_STORE_CTX_new();
#endif
    printf("Verifying certificate with verify_flags: %lu\n", verify_flags);
    if (!ctx) {
        DBG_ERR("X509_STORE_CTX_new failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "X509_STORE_CTX_new failed : ");
        X509_STORE_free(store);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (X509_STORE_CTX_init(ctx, store, identityCert, NULL) != 1) {
        DBG_ERR("X509_STORE_CTX_init failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "X509_STORE_CTX_init failed : ");
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

#ifndef PQ_CRYPTO
    X509_STORE_CTX_set_flags(ctx, verify_flags);
    DBG_TRACE("Set X509_STORE_CTX flags\n");

    if (X509_verify_cert(ctx) != 1) {
        const char *msg = X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx));
        char *subject = get_certificate_subject_name(identityCert, ex);
        DBG_ERR("Certificate verification failed: %s\n", msg);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Certificate not valid: error: %s; subject: %s", msg,
                                   subject ? subject : "[not found]");
        ddsrt_free(subject);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Certificate verified successfully\n");
#endif

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return DDS_SECURITY_VALIDATION_OK;
}

AuthenticationChallenge *generate_challenge(DDS_Security_SecurityException *ex) {
    AuthenticationChallenge *result = ddsrt_malloc(sizeof(*result));
    DBG_TRACE("generate_challenge() called\n");
    if (RAND_bytes(result->value, sizeof(result->value)) < 0) {
        DBG_ERR("RAND_bytes failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to generate a 256 bit random number ");
        ddsrt_free(result);
        return NULL;
    }
    DBG_TRACE("Generated new challenge\n");
    return result;
}

DDS_Security_ValidationResult_t get_certificate_contents(X509 *cert, unsigned char **data,
                                                         uint32_t *size,
                                                         DDS_Security_SecurityException *ex) {
    BIO *bio = NULL;
    char *ptr;
    assert(cert);
    DBG_TRACE("get_certificate_contents() called\n");

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        DBG_ERR("BIO_new_mem_buf failed\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "BIO_new_mem_buf failed");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (!PEM_write_bio_X509(bio, cert)) {
        DBG_ERR("PEM_write_bio_X509 failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "PEM_write_bio_X509 failed: ");
        BIO_free(bio);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Wrote certificate to BIO\n");

    size_t sz = BIO_get_mem_data(bio, &ptr);
    *data = ddsrt_malloc(sz + 1);
    memcpy(*data, ptr, sz);
    (*data)[sz] = '\0';
    *size = (uint32_t)sz;
    DBG_TRACE("Extracted certificate contents (size=%u)\n", *size);

    BIO_free(bio);
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t get_rsa_dh_parameters(EVP_PKEY **params,
                                                             DDS_Security_SecurityException *ex) {
    DBG_TRACE("get_rsa_dh_parameters() called\n");
    DH *dh = NULL;
    *params = EVP_PKEY_new();
    if (!*params) {
        DBG_ERR("EVP_PKEY_new failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate DH generation parameters: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    dh = DH_get_2048_256();
    if (!dh) {
        DBG_ERR("DH_get_2048_256 failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "Failed to allocate DH parameter using DH_get_2048_256: ");
        EVP_PKEY_free(*params);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Obtained DH parameters from DH_get_2048_256\n");

    if (EVP_PKEY_set1_DH(*params, dh) <= 0) {
        DBG_ERR("EVP_PKEY_set1_DH failed\n");
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "Failed to set DH generation parameters using EVP_PKEY_set1_DH: ");
        EVP_PKEY_free(*params);
        DH_free(dh);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Assigned DH parameters to EVP_PKEY\n");

    DH_free(dh);
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t get_ec_dh_parameters(EVP_PKEY **params,
                                                            DDS_Security_SecurityException *ex) {
    DBG_TRACE("get_ec_dh_parameters() called\n");
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        DBG_ERR("Failed to allocate DH parameter context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate DH parameter context: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EC parameter context\n");

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        DBG_ERR("Failed to initialize DH generation context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize DH generation context: ");
        EVP_PKEY_CTX_free(pctx);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Initialized parameter generation\n");

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        DBG_ERR("Failed to set EC curve\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "Failed to set DH generation parameter generation method: ");
        EVP_PKEY_CTX_free(pctx);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Set curve NID_X9_62_prime256v1\n");

    if (EVP_PKEY_paramgen(pctx, params) <= 0) {
        DBG_ERR("Failed to generate DH parameters\n");
        char *msg = get_openssl_error_message();
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to generate DH parameters: ");
        ddsrt_free(msg);
        EVP_PKEY_CTX_free(pctx);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Generated EC DH parameters\n");

    EVP_PKEY_CTX_free(pctx);
    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t generate_dh_keys(EVP_PKEY **dhkey,
                                                 AuthenticationAlgoKind_t authKind,
                                                 DDS_Security_SecurityException *ex) {
    DBG_TRACE("generate_dh_keys() called (algo=%d)\n", authKind);
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    *dhkey = NULL;

    switch (authKind) {
    case AUTH_ALGO_KIND_RSA_2048:
        if (get_rsa_dh_parameters(&params, ex) != DDS_SECURITY_VALIDATION_OK)
            goto failed;
        break;
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        if (get_ec_dh_parameters(&params, ex) != DDS_SECURITY_VALIDATION_OK)
            goto failed;
        break;
    default:
        DBG_ERR("Invalid algorithm for DH keys\n");
        assert(0);
        goto failed;
    }
    DBG_TRACE("Obtained DH parameters\n");

    kctx = EVP_PKEY_CTX_new(params, NULL);
    if (!kctx) {
        DBG_ERR("Failed to allocate DH generation context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate DH generation context: ");
        goto failed_params;
    }
    DBG_TRACE("Created key generation context\n");

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        DBG_ERR("Failed to initialize DH generation context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize DH generation context: ");
        goto failed_kctx;
    }
    DBG_TRACE("Initialized keygen\n");

    if (EVP_PKEY_keygen(kctx, dhkey) <= 0) {
        DBG_ERR("Failed to generate DH key pair\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to generate DH key pair: ");
        goto failed_kctx;
    }
    DBG_TRACE("Generated DH key pair\n");

    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);
    return DDS_SECURITY_VALIDATION_OK;

failed_kctx:
    EVP_PKEY_CTX_free(kctx);
failed_params:
    EVP_PKEY_free(params);
failed:
    return DDS_SECURITY_VALIDATION_FAILED;
}

static const BIGNUM *dh_get_public_key(DH *dhkey) {
#ifdef AUTH_INCLUDE_DH_ACCESSORS
    const BIGNUM *pubkey, *privkey;
    DH_get0_key(dhkey, &pubkey, &privkey);
    return pubkey;
#else
    return dhkey->pub_key;
#endif
}

static int dh_set_public_key(DH *dhkey, BIGNUM *pubkey) {
    DBG_TRACE("dh_set_public_key() called\n");
#ifdef AUTH_INCLUDE_DH_ACCESSORS
    return DH_set0_key(dhkey, pubkey, NULL);
#else
    dhkey->pub_key = pubkey;
#endif
    return 1;
}

static DDS_Security_ValidationResult_t
dh_public_key_to_oct_modp(EVP_PKEY *pkey, unsigned char **buffer, uint32_t *length,
                          DDS_Security_SecurityException *ex) {
    DBG_TRACE("dh_public_key_to_oct_modp() called\n");
    DH *dhkey = EVP_PKEY_get1_DH(pkey);
    if (!dhkey) {
        DBG_ERR("Failed to get DH key from PKEY\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Failed to get DH key from PKEY: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Obtained DH key structure\n");

    ASN1_INTEGER *asn1int = BN_to_ASN1_INTEGER(dh_get_public_key(dhkey), NULL);
    if (!asn1int) {
        DBG_ERR("Failed to convert DH key to ASN1 integer\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert DH key to ASN1 integer: ");
        DH_free(dhkey);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Converted DH BIGNUM to ASN1_INTEGER\n");

    int i2dlen = i2d_ASN1_INTEGER(asn1int, NULL);
    if (i2dlen <= 0) {
        DBG_ERR("Failed to determine ASN1 integer length\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert DH key to ASN1 integer: ");
        DH_free(dhkey);
        ASN1_INTEGER_free(asn1int);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("ASN1 integer length: %d\n", i2dlen);

    *length = (uint32_t)i2dlen;
    *buffer = ddsrt_malloc(*length);
    if (!*buffer) {
        DBG_ERR("Memory allocation failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert DH key to ASN1 integer: ");
        DH_free(dhkey);
        ASN1_INTEGER_free(asn1int);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Allocated buffer for ASN1 data (length=%u)\n", *length);

    unsigned char *buffer_arg = *buffer;
    i2d_ASN1_INTEGER(asn1int, &buffer_arg);
    DBG_TRACE("Serialized ASN1 integer into buffer\n");

    ASN1_INTEGER_free(asn1int);
    DH_free(dhkey);
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t
dh_public_key_to_oct_ecdh(EVP_PKEY *pkey, unsigned char **buffer, uint32_t *length,
                          DDS_Security_SecurityException *ex) {
    DBG_TRACE("dh_public_key_to_oct_ecdh() called\n");
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
    if (!eckey) {
        DBG_ERR("Failed to get EC key from PKEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to get EC key from PKEY: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Obtained EC_KEY structure\n");

    const EC_POINT *point = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    if (!point || !group) {
        DBG_ERR("Failed to get EC point or group\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to get public key from ECKEY: ");
        EC_KEY_free(eckey);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    size_t sz = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (sz == 0) {
        DBG_ERR("Failed to determine EC point octet size\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to serialize public EC key: ");
        EC_KEY_free(eckey);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("EC point octet size: %zu\n", sz);

    *buffer = ddsrt_malloc(sz);
    if (!*buffer) {
        DBG_ERR("Failed to allocate buffer for EC point\n");
        EC_KEY_free(eckey);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Allocated buffer for EC point data\n");

    *length = (uint32_t)EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, *buffer, sz,
                                           NULL);
    if (*length == 0) {
        DBG_ERR("Failed to serialize EC point\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to serialize public EC key: ");
        ddsrt_free(*buffer);
        EC_KEY_free(eckey);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Serialized EC point into buffer (length=%u)\n", *length);

    EC_KEY_free(eckey);
    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t dh_public_key_to_oct(EVP_PKEY *pkey, AuthenticationAlgoKind_t algo,
                                                     unsigned char **buffer, uint32_t *length,
                                                     DDS_Security_SecurityException *ex) {
    assert(pkey);
    assert(buffer);
    assert(length);

    switch (algo) {
    case AUTH_ALGO_KIND_RSA_2048:
        return dh_public_key_to_oct_modp(pkey, buffer, length, ex);
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        return dh_public_key_to_oct_ecdh(pkey, buffer, length, ex);
    default:
        DBG_ERR("Invalid key algorithm specified (%d)\n", algo);
        assert(0);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Invalid key algorithm specified");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
}

static DDS_Security_ValidationResult_t
dh_oct_to_public_key_modp(EVP_PKEY **pkey, const unsigned char *keystr, uint32_t size,
                          DDS_Security_SecurityException *ex) {
    DBG_TRACE("dh_oct_to_public_key_modp() called (size=%u)\n", size);
    DH *dhkey = NULL;
    ASN1_INTEGER *asn1int = NULL;
    BIGNUM *pubkey = NULL;

    *pkey = EVP_PKEY_new();
    if (!*pkey) {
        DBG_ERR("Failed to allocate EVP_PKEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert octet sequence to ASN1 integer: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Allocated EVP_PKEY\n");

    const unsigned char *p = keystr;
    asn1int = d2i_ASN1_INTEGER(NULL, &p, (long)size);
    if (!asn1int) {
        DBG_ERR("Failed to convert octet sequence to ASN1 integer\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert octet sequence to ASN1 integer: ");
        goto fail_get_asn1int;
    }
    DBG_TRACE("Converted octets to ASN1_INTEGER\n");

    pubkey = ASN1_INTEGER_to_BN(asn1int, NULL);
    if (!pubkey) {
        DBG_ERR("Failed to convert ASN1 integer to BIGNUM\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert ASN1 integer to BIGNUM: ");
        goto fail_get_pubkey;
    }
    DBG_TRACE("Converted ASN1_INTEGER to BIGNUM\n");

    dhkey = DH_get_2048_256();
    if (!dh_set_public_key(dhkey, pubkey)) {
        DBG_ERR("Failed to set DH public key\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to set DH public key: ");
        goto fail_get_pubkey;
    }
    DBG_TRACE("Set DH public key on DH structure\n");

    if (EVP_PKEY_set1_DH(*pkey, dhkey) == 0) {
        DBG_ERR("Failed to convert DH to EVP_PKEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to convert DH to PKEY: ");
        DH_free(dhkey);
        goto fail_get_pubkey;
    }
    DBG_TRACE("Converted DH to EVP_PKEY\n");

    ASN1_INTEGER_free(asn1int);
    DH_free(dhkey);
    return DDS_SECURITY_VALIDATION_OK;

fail_get_pubkey:
    ASN1_INTEGER_free(asn1int);
fail_get_asn1int:
    EVP_PKEY_free(*pkey);
    return DDS_SECURITY_VALIDATION_FAILED;
}

static DDS_Security_ValidationResult_t
dh_oct_to_public_key_ecdh(EVP_PKEY **pkey, const unsigned char *keystr, uint32_t size,
                          DDS_Security_SecurityException *ex) {
    DBG_TRACE("dh_oct_to_public_key_ecdh() called (size=%u)\n", size);
    EC_KEY *eckey = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        DBG_ERR("Failed to allocate EC group\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate EC group: ");
        goto fail_alloc_group;
    }
    DBG_TRACE("Allocated EC group\n");

    point = EC_POINT_new(group);
    if (!point) {
        DBG_ERR("Failed to allocate EC point\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate EC point: ");
        goto fail_alloc_point;
    }
    DBG_TRACE("Allocated EC point\n");

    if (EC_POINT_oct2point(group, point, keystr, size, NULL) != 1) {
        DBG_ERR("Failed to deserialize EC public key to point\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to deserialize EC public key to EC point: ");
        goto fail_oct2point;
    }
    DBG_TRACE("Converted octets to EC_POINT\n");

    eckey = EC_KEY_new();
    if (!eckey) {
        DBG_ERR("Failed to allocate EC_KEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate EC KEY: ");
        goto fail_alloc_eckey;
    }
    DBG_TRACE("Allocated EC_KEY\n");

    if (EC_KEY_set_group(eckey, group) != 1) {
        DBG_ERR("Failed to set EC group on EC_KEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to set EC group: ");
        goto fail_eckey_set;
    }

    if (EC_KEY_set_public_key(eckey, point) != 1) {
        DBG_ERR("Failed to set EC public key\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to set EC public key: ");
        goto fail_eckey_set;
    }
    DBG_TRACE("Set public key on EC_KEY\n");

    *pkey = EVP_PKEY_new();
    if (!*pkey) {
        DBG_ERR("Failed to allocate EVP_PKEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate EVP key: ");
        goto fail_alloc_pkey;
    }

    if (EVP_PKEY_set1_EC_KEY(*pkey, eckey) != 1) {
        DBG_ERR("Failed to set EVP_PKEY from EC_KEY\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to set EVP key to EC public key: ");
        goto fail_pkey_set_eckey;
    }
    DBG_TRACE("Created EVP_PKEY from EC_KEY\n");

    EC_KEY_free(eckey);
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return DDS_SECURITY_VALIDATION_OK;

fail_pkey_set_eckey:
    EVP_PKEY_free(*pkey);
fail_alloc_pkey:
fail_eckey_set:
    EC_KEY_free(eckey);
fail_alloc_eckey:
fail_oct2point:
    EC_POINT_free(point);
fail_alloc_point:
    EC_GROUP_free(group);
fail_alloc_group:
    return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t dh_oct_to_public_key(EVP_PKEY **data, AuthenticationAlgoKind_t algo,
                                                     const unsigned char *str, uint32_t size,
                                                     DDS_Security_SecurityException *ex) {
    assert(data);
    assert(str);
    switch (algo) {
    case AUTH_ALGO_KIND_RSA_2048:
        return dh_oct_to_public_key_modp(data, str, size, ex);
    case AUTH_ALGO_KIND_EC_PRIME256V1:
        return dh_oct_to_public_key_ecdh(data, str, size, ex);
    default:
        DBG_ERR("Invalid key algorithm specified (%d)\n", algo);
        assert(0);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Invalid key algorithm specified");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
}

char *string_from_data(const unsigned char *data, uint32_t size) {
    char *str = NULL;
    if (size > 0 && data) {
        str = ddsrt_malloc(size + 1);
        memcpy(str, data, size);
        str[size] = '\0';
    }
    return str;
}

void free_ca_list_contents(X509Seq *ca_list) {
    unsigned i;
    if (ca_list->buffer != NULL && ca_list->length > 0) {
        for (i = 0; i < ca_list->length; ++i)
            X509_free(ca_list->buffer[i]);
        ddsrt_free(ca_list->buffer);
    }
    ca_list->buffer = NULL;
    ca_list->length = 0;
}

DDS_Security_ValidationResult_t get_trusted_ca_list(const char *trusted_ca_dir, X509Seq *ca_list,
                                                    OSSL_LIB_CTX *oqs_libctx,
                                                    DDS_Security_SecurityException *ex) {
    DBG_TRACE("get_trusted_ca_list() called (dir='%s')\n", trusted_ca_dir);
    ddsrt_dir_handle_t d_descr;
    struct ddsrt_dirent d_entry;
    struct ddsrt_stat status;
    X509 *ca_buf[MAX_TRUSTED_CA];
    unsigned ca_cnt = 0;
    char *tca_dir_norm = ddsrt_file_normalize(trusted_ca_dir);
    dds_return_t ret = ddsrt_opendir(tca_dir_norm, &d_descr);
    ddsrt_free(tca_dir_norm);
    if (ret != DDS_RETCODE_OK) {
        DBG_ERR("Failed to open directory '%s'\n", trusted_ca_dir);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                   DDS_SECURITY_ERR_INVALID_TRUSTED_CA_DIR_CODE, 0,
                                   DDS_SECURITY_ERR_INVALID_TRUSTED_CA_DIR_MESSAGE);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Opened directory '%s'\n", trusted_ca_dir);
    printf("Loading trusted CA certificates from directory: %s\n", trusted_ca_dir);

    char *fpath, *fname;
    X509 *ca;
    bool failed = false;
    while (!failed && ddsrt_readdir(d_descr, &d_entry) == DDS_RETCODE_OK) {
        ddsrt_asprintf(&fpath, "%s%s%s", trusted_ca_dir, ddsrt_file_sep(), d_entry.d_name);
        if (ddsrt_stat(fpath, &status) == DDS_RETCODE_OK && strcmp(d_entry.d_name, ".") != 0 &&
            strcmp(d_entry.d_name, "..") != 0 && (fname = ddsrt_file_normalize(fpath)) != NULL) {
            if (ca_cnt >= MAX_TRUSTED_CA) {
                DBG_ERR("Exceeded maximum trusted CA count (%u)\n", MAX_TRUSTED_CA);
                DDS_Security_Exception_set(
                    ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_TRUSTED_CA_DIR_MAX_EXCEEDED_CODE,
                    0, DDS_SECURITY_ERR_TRUSTED_CA_DIR_MAX_EXCEEDED_MESSAGE, MAX_TRUSTED_CA);
                failed = true;
            } else if (load_X509_certificate_from_file(fname, &ca, oqs_libctx, ex) ==
                       DDS_SECURITY_VALIDATION_OK) {
                DBG_TRACE("Loaded CA certificate from file '%s'\n", fname);
                ca_buf[ca_cnt++] = ca;
            } else {
                DBG_WARN("Failed to load CA certificate from file '%s'\n", fname);
                DDS_Security_Exception_reset(ex);
            }
            ddsrt_free(fname);
        }
        ddsrt_free(fpath);
    }
    ddsrt_closedir(d_descr);

    if (!failed) {
        free_ca_list_contents(ca_list);
        if (ca_cnt > 0) {
            ca_list->buffer = ddsrt_malloc(ca_cnt * sizeof(X509 *));
            for (unsigned i = 0; i < ca_cnt; ++i)
                ca_list->buffer[i] = ca_buf[i];
        }
        ca_list->length = ca_cnt;
        DBG_TRACE("Total trusted CAs loaded: %u\n", ca_cnt);
    }
    return failed ? DDS_SECURITY_VALIDATION_FAILED : DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t
create_validate_asymmetrical_signature(bool create, EVP_PKEY *pkey, const unsigned char *data,
                                       const size_t dataLen, unsigned char **signature,
                                       size_t *signatureLen, DDS_Security_SecurityException *ex) {
    DBG_TRACE("create_validate_asymmetrical_signature() called (create=%s)\n",
              create ? "true" : "false");
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;

    mdctx = EVP_MD_CTX_create();
    if (!mdctx) {
        DBG_ERR("Failed to create EVP_MD_CTX\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to create digest context: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EVP_MD_CTX\n");

    if ((create ? EVP_DigestSignInit(mdctx, &kctx, EVP_sha256(), NULL, pkey)
                : EVP_DigestVerifyInit(mdctx, &kctx, EVP_sha256(), NULL, pkey)) != 1) {
        DBG_ERR("Failed to initialize digest context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize digest context: ");
        goto err;
    }
    DBG_TRACE("Initialized digest context\n");

    if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(kctx, RSA_PKCS1_PSS_PADDING) < 1) {
            DBG_ERR("Failed to set RSA PSS padding\n");
            DDS_Security_Exception_set_with_openssl_error(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize digest context: ");
            goto err;
        }
        DBG_TRACE("Set RSA PSS padding\n");
    }

    if ((create ? EVP_DigestSignUpdate(mdctx, data, dataLen)
                : EVP_DigestVerifyUpdate(mdctx, data, dataLen)) != 1) {
        DBG_ERR("Failed to update digest context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to update digest context: ");
        goto err;
    }
    DBG_TRACE("Updated digest context with data\n");

    if (create) {
        if (EVP_DigestSignFinal(mdctx, NULL, signatureLen) != 1) {
            DBG_ERR("Failed to finalize digest context length query\n");
            DDS_Security_Exception_set_with_openssl_error(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, "Failed to finalize digest context: ");
            goto err;
        }
        *signature = ddsrt_malloc(*signatureLen);
        if (!*signature) {
            DBG_ERR("Failed to allocate signature buffer\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Failed to allocate signature buffer");
            goto err;
        }
        DBG_TRACE("Allocated signature buffer (length=%zu)\n", *signatureLen);
    }

    if ((create ? EVP_DigestSignFinal(mdctx, *signature, signatureLen)
                : EVP_DigestVerifyFinal(mdctx, *signature, *signatureLen)) != 1) {
        DBG_ERR("Failed to finalize digest operation\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to finalize digest context: ");
        if (create)
            ddsrt_free(*signature);
        goto err;
    }
    DBG_TRACE("Digest operation completed successfully\n");

    EVP_MD_CTX_destroy(mdctx);
    return DDS_SECURITY_VALIDATION_OK;

err:
    EVP_MD_CTX_destroy(mdctx);
    return DDS_SECURITY_VALIDATION_FAILED;
}

/*-----------------------------------------------------------------------------------------------------------------------------------*/

/* PQ KEM FUNCTIONS*/
#ifdef PQ_CRYPTO

int load_oqs_provider(OSSL_LIB_CTX **plibctx, const char *modulename, const char *configfile) {
    DBG_TRACE("load_oqs_provider() called (module='%s')\n", modulename);
    if (*plibctx == NULL) {
        *plibctx = OSSL_LIB_CTX_new();
        if (*plibctx == NULL) {
            DBG_ERR("Failed to create libctx\n");
            fprintf(stderr, "Failed to create libctx\n");
            return 0;
        }
        DBG_TRACE("Created new libctx\n");
    }

    if (OSSL_LIB_CTX_load_config(*plibctx, configfile) == 0) {
        DBG_ERR("Failed to load config file '%s'\n", configfile);
        fprintf(stderr, "Failed to load config file %s\n", configfile);
        OSSL_LIB_CTX_free(*plibctx);
        *plibctx = NULL;
        return 0;
    }
    DBG_TRACE("Loaded config file '%s'\n", configfile);

    if (OSSL_PROVIDER_load(*plibctx, modulename) == NULL) {
        DBG_ERR("Failed to load provider '%s'\n", modulename);
        fprintf(stderr, "Failed to load provider %s\n", modulename);
        OSSL_LIB_CTX_free(*plibctx);
        *plibctx = NULL;
        return 0;
    }
    DBG_TRACE("Loaded provider '%s'\n", modulename);
    return 1;
}

static DDS_Security_ValidationResult_t
pq_public_key_to_oct_kem(EVP_PKEY *pkey, unsigned char **buffer, uint32_t *length,
                         DDS_Security_SecurityException *ex) {
    DBG_TRACE("pq_public_key_to_oct_kem() called\n");
    size_t len = 0;

    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) <= 0) {
        DBG_ERR("Failed to get public key length\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to get public key length");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Public key raw length: %zu\n", len);

    *buffer = malloc(len);
    if (*buffer == NULL) {
        DBG_ERR("Failed to allocate memory for public key\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate memory for public key");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Allocated buffer for public key\n");

    if (EVP_PKEY_get_raw_public_key(pkey, *buffer, &len) <= 0) {
        DBG_ERR("Failed to get public key bytes\n");
        ERR_print_errors_fp(stderr);
        free(*buffer);
        *buffer = NULL;
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    *length = (uint32_t)len;
    DBG_TRACE("Copied raw public key to buffer (length=%u)\n", *length);

    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t pq_public_key_to_oct(EVP_PKEY *pkey,
                                                     AuthenticationAlgoKind_t kagreeAlgoKind,
                                                     unsigned char **buffer, uint32_t *length,
                                                     DDS_Security_SecurityException *ex) {
    DBG_TRACE("pq_public_key_to_oct() called (kagreeAlgoKind=%d)\n", kagreeAlgoKind);
    assert(pkey);
    assert(buffer);
    assert(length);

    return pq_public_key_to_oct_kem(pkey, buffer, length, ex);
}

static DDS_Security_ValidationResult_t
pq_oct_to_public_key_kem(EVP_PKEY **pkey, const unsigned char *keystr, uint32_t size,
                         AuthenticationAlgoKind_t kagreeAlgoKind, OSSL_LIB_CTX *libctx,
                         DDS_Security_SecurityException *ex) {
    DBG_TRACE("pq_oct_to_public_key_kem() called (size=%u, algo=%d)\n", size, kagreeAlgoKind);

    // Get the OpenSSL algorithm name from the algorithm kind
    const char *kemalg_name = get_kem_openssl_name_by_kind(kagreeAlgoKind);
    if (!kemalg_name) {
        // Fallback to default algorithm
        kemalg_name = get_default_kem_openssl_name();
        if (!kemalg_name) {
            DBG_ERR("No OpenSSL name found for KEM algorithm kind: %d\n", kagreeAlgoKind);
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Unsupported KEM algorithm kind for public key conversion");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_WARN("Using default KEM algorithm %s instead of kind %d\n", kemalg_name,
                 kagreeAlgoKind);
    }

    DBG_INFO("Using KEM algorithm: %s (kind: %d)\n", kemalg_name, kagreeAlgoKind);
    EVP_PKEY_CTX *pctx = NULL;

    /* Create a new context for the specified KEM algorithm */
    pctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name, NULL);
    if (pctx == NULL) {
        DBG_ERR("Failed to create EVP_PKEY_CTX for KEM algorithm %s\n", kemalg_name);
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to create EVP_PKEY_CTX for KEM algorithm");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EVP_PKEY_CTX for %s\n", kemalg_name);

    /* Allocate a new EVP_PKEY structure using raw public key */
    *pkey = EVP_PKEY_new_raw_public_key_ex(libctx, kemalg_name, NULL, keystr, size);
    if (*pkey == NULL) {
        DBG_ERR("Failed to set public key from raw data for %s\n", kemalg_name);
        unsigned long err_code;
        while ((err_code = ERR_get_error()) != 0) {
            char *err_str = ERR_error_string(err_code, NULL);
            DBG_ERR("OpenSSL error: %s\n", err_str);
        }
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to set public key from raw data");
        EVP_PKEY_CTX_free(pctx);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EVP_PKEY from raw public key for %s\n", kemalg_name);

    EVP_PKEY_CTX_free(pctx);
    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t pq_oct_to_public_key(EVP_PKEY **data, const unsigned char *str,
                                                     uint32_t size,
                                                     AuthenticationAlgoKind_t kagreeAlgoKind,
                                                     OSSL_LIB_CTX *libctx,
                                                     DDS_Security_SecurityException *ex) {
    DBG_TRACE("pq_oct_to_public_key() called (size=%u)\n", size);
    assert(data);
    assert(str);

    return pq_oct_to_public_key_kem(data, str, size, kagreeAlgoKind, libctx, ex);
}

DDS_Security_ValidationResult_t
create_validate_pq_signature(bool create, EVP_PKEY *pkey, const unsigned char *data,
                             const size_t dataLen, unsigned char **signature, size_t *signatureLen,
                             DDS_Security_SecurityException *ex, OSSL_LIB_CTX *libctx) {
    EVP_MD_CTX *mdctx = NULL;
    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_FAILED;

    DBG_TRACE("create_validate_pq_signature() called (create=%s, dataLen=%zu)\n",
              create ? "true" : "false", dataLen);

    if (!OSSL_PROVIDER_available(libctx, "oqsprovider")) {
        DBG_ERR("OQS provider is not available\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "OQS provider is not available.");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("OQS provider available\n");

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        DBG_ERR("Failed to create EVP_MD_CTX\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to create digest context: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EVP_MD_CTX\n");

    if (create) {
        DBG_TRACE("Initializing for signing\n");

        if (EVP_DigestSignInit_ex(mdctx, NULL, NULL, libctx, NULL, pkey, NULL) != 1) {
            DBG_ERR("EVP_DigestSignInit_ex failed\n");
            DDS_Security_Exception_set_with_openssl_error(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize digest signing: ");
            goto err;
        }
        DBG_TRACE("DigestSignInit successful\n");

        if (EVP_DigestSign(mdctx, NULL, signatureLen, data, dataLen) != 1) {
            DBG_ERR("Failed to determine signature length\n");
            DDS_Security_Exception_set_with_openssl_error(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, "Failed to determine signature length: ");
            goto err;
        }
        DBG_TRACE("Determined signature length: %zu\n", *signatureLen);

        *signature = ddsrt_malloc(*signatureLen);
        if (!*signature) {
            DBG_ERR("Failed to allocate signature buffer\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Failed to allocate signature buffer");
            goto err;
        }
        DBG_TRACE("Allocated signature buffer\n");

        if (EVP_DigestSign(mdctx, *signature, signatureLen, data, dataLen) != 1) {
            DBG_ERR("DigestSign failed to create signature\n");
            DDS_Security_Exception_set_with_openssl_error(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, "Failed to create signature: ");
            ddsrt_free(*signature);
            *signature = NULL;
            goto err;
        }
        DBG_TRACE("Signature created successfully (length=%zu)\n", *signatureLen);
    } else {
        DBG_TRACE("Initializing for verification\n");

        if (EVP_DigestVerifyInit_ex(mdctx, NULL, NULL, libctx, NULL, pkey, NULL) != 1) {
            DBG_ERR("EVP_DigestVerifyInit_ex failed\n");
            DDS_Security_Exception_set_with_openssl_error(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize digest verification: ");
            goto err;
        }
        DBG_TRACE("DigestVerifyInit successful\n");

        int verify_result = EVP_DigestVerify(mdctx, *signature, *signatureLen, data, dataLen);
        if (verify_result != 1) {
            if (verify_result == 0) {
                DBG_ERR("Signature verification failed - invalid signature\n");
                DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                           DDS_SECURITY_ERR_UNDEFINED_CODE,
                                           DDS_SECURITY_VALIDATION_FAILED,
                                           "Signature verification failed - invalid signature");
            } else {
                DBG_ERR("DigestVerify failed\n");
                DDS_Security_Exception_set_with_openssl_error(
                    ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                    DDS_SECURITY_VALIDATION_FAILED, "Failed to verify signature: ");
            }
            goto err;
        }
        DBG_TRACE("Signature verified successfully\n");
    }

    result = DDS_SECURITY_VALIDATION_OK;
    DBG_INFO("ML-DSA operation successful\n");

err:
    if (mdctx) {
        EVP_MD_CTX_free(mdctx);
    }
    return result;
}

DDS_Security_BinaryProperty_t *create_pqkey_property(const char *name, EVP_PKEY *pkey,
                                                     AuthenticationAlgoKind_t kagreeAlgoKind,
                                                     DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering create_pqkey_property (name='%s', kagreeAlgoKind=%d)\n", name,
              kagreeAlgoKind);
    DDS_Security_BinaryProperty_t *prop;
    unsigned char *data;
    uint32_t len;

    if (pq_public_key_to_oct(pkey, kagreeAlgoKind, &data, &len, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("pq_public_key_to_oct failed\n");
        return NULL;
    }
    DBG_TRACE("Converted public key to octets (length=%u)\n", len);

    prop = DDS_Security_BinaryProperty_alloc();
    if (!prop) {
        DBG_ERR("Failed to allocate BinaryProperty\n");
        ddsrt_free(data);
        return NULL;
    }
    DDS_Security_BinaryProperty_set_by_ref(prop, name, data, len);
    DBG_TRACE("Created PQ key property '%s'\n", name);
    return prop;
}

static DDS_Security_ValidationResult_t create_pq_validate_signature_impl(
    bool create, EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **bprops,
    const uint32_t n_bprops, unsigned char **signature, size_t *signature_len,
    DDS_Security_SecurityException *ex, OSSL_LIB_CTX *libctx) {
    DBG_TRACE("Entering create_pq_validate_signature_impl (create=%d, n_bprops=%u)\n", create,
              n_bprops);
    unsigned char *buffer;
    size_t size;
    DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);

    DDS_Security_Serialize_BinaryPropertyArray(serializer, bprops, n_bprops);
    DDS_Security_Serializer_buffer(serializer, &buffer, &size);
    DBG_TRACE("Serialized %u binary properties into buffer (size=%zu)\n", n_bprops, size);

    DDS_Security_ValidationResult_t result = create_validate_pq_signature(
        create, pkey, buffer, size, signature, signature_len, ex, libctx);
    if (result != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("create_validate_pq_signature returned failure\n");
    } else {
        DBG_TRACE("PQ signature %s successfully (length=%zu)\n", create ? "created" : "validated",
                  *signature_len);
    }

    ddsrt_free(buffer);
    DDS_Security_Serializer_free(serializer);
    return result;
}

DDS_Security_ValidationResult_t
pq_kem_encapsulation(EVP_PKEY *evp_public_key, size_t *length_ciphertext, size_t *length_secret,
                     uint8_t **handshake_kem_ciphertext, uint8_t **local_kem_secret,
                     const DDS_Security_BinaryProperty_t *kem_public,
                     AuthenticationAlgoKind_t kagreeAlgoKind, DDS_Security_SecurityException *ex,
                     OSSL_LIB_CTX *libctx) {
    DBG_TRACE("Entering pq_kem_encapsulation (kagreeAlgoKind=%d)\n", kagreeAlgoKind);
    int ret = DDS_SECURITY_VALIDATION_OK;
    unsigned char *ct = NULL;
    unsigned char *ss = NULL;
    size_t ctlen = 0, sslen = 0;
    EVP_PKEY_CTX *pctx = NULL;

    if (evp_public_key == NULL) {
        DBG_ERR("Public key is NULL\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "Public key is NULL");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Public key provided\n");

    pctx = EVP_PKEY_CTX_new_from_pkey(NULL, evp_public_key, NULL);
    if (pctx == NULL) {
        DBG_ERR("Failed to create EVP_PKEY_CTX\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to create EVP_PKEY_CTX");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EVP_PKEY_CTX\n");

    if (EVP_PKEY_encapsulate_init(pctx, NULL) <= 0 ||
        EVP_PKEY_encapsulate(pctx, NULL, &ctlen, NULL, &sslen) <= 0 || ctlen == 0 || sslen == 0) {
        DBG_ERR("Failed to initialize or determine lengths for encapsulation\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "Failed to initialize or determine lengths for encapsulation");
        goto err;
    }
    DBG_TRACE("Determined encapsulation lengths: ctlen=%zu, sslen=%zu\n", ctlen, sslen);

    ct = OPENSSL_malloc(ctlen);
    ss = OPENSSL_malloc(sslen);
    if (ct == NULL || ss == NULL) {
        DBG_ERR("Memory allocation failed for encapsulation buffers\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Failed to allocate memory for encapsulation");
        goto err;
    }
    DBG_TRACE("Allocated buffers for ct and ss\n");

    if (EVP_PKEY_encapsulate(pctx, ct, &ctlen, ss, &sslen) <= 0) {
        DBG_ERR("Failed to perform encapsulation\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to perform encapsulation");
        goto err;
    }
    DBG_TRACE("Encapsulation performed successfully\n");

    *handshake_kem_ciphertext = OPENSSL_malloc(ctlen);
    if (*handshake_kem_ciphertext == NULL) {
        DBG_ERR("Memory allocation failed for handshake_kem_ciphertext\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Failed to allocate memory for KEM ciphertext");
        goto err;
    }
    memcpy(*handshake_kem_ciphertext, ct, ctlen);
    *length_ciphertext = ctlen;
    DBG_TRACE("Copied ciphertext (length=%zu)\n", ctlen);

    *local_kem_secret = OPENSSL_malloc(sslen);
    if (*local_kem_secret == NULL) {
        DBG_ERR("Memory allocation failed for local_kem_secret\n");
        OPENSSL_free(*handshake_kem_ciphertext);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Failed to allocate memory for KEM secret");
        goto err;
    }
    memcpy(*local_kem_secret, ss, sslen);
    *length_secret = sslen;
    DBG_TRACE("Copied secret (length=%zu)\n", sslen);

    EVP_PKEY_CTX_free(pctx);
    OPENSSL_clear_free(ss, sslen);
    OPENSSL_free(ct);
    DBG_TRACE("Encapsulation successful\n");
    return ret;

err:
    if (ss != NULL) {
        OPENSSL_clear_free(ss, sslen);
    }
    if (ct != NULL) {
        OPENSSL_free(ct);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    DBG_ERR("pq_kem_encapsulation failed\n");
    return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t
pq_kem_decapsulation(EVP_PKEY *evp_private_key, uint8_t **kem_secret, size_t *length_secret,
                     const DDS_Security_BinaryProperty_t *kem_ciphertext,
                     AuthenticationAlgoKind_t authKind, DDS_Security_SecurityException *ex,
                     OSSL_LIB_CTX *libctx) {
    DBG_TRACE("Entering pq_kem_decapsulation (authKind=%d)\n", authKind);
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ss = NULL;
    size_t sslen = 0;

    if (evp_private_key == NULL) {
        DBG_ERR("evp_private_key is NULL\n");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Private key provided\n");

    if (!OSSL_PROVIDER_available(libctx, "default")) {
        DBG_ERR("Default provider is not available\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Default provider is not available.");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("OQS provider available\n");

    pctx = EVP_PKEY_CTX_new_from_pkey(libctx, evp_private_key, NULL);
    if (pctx == NULL) {
        DBG_ERR("Failed to create EVP_PKEY_CTX for decapsulation\n");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created EVP_PKEY_CTX for decapsulation\n");

    if (EVP_PKEY_decapsulate_init(pctx, NULL) <= 0 ||
        EVP_PKEY_decapsulate(pctx, NULL, &sslen, kem_ciphertext->value._buffer,
                             kem_ciphertext->value._length) <= 0 ||
        sslen == 0) {
        DBG_ERR("Failed to initialize or determine lengths for decapsulation\n");
        goto err;
    }
    DBG_TRACE("Determined decapsulation length: sslen=%zu\n", sslen);

    ss = OPENSSL_malloc(sslen);
    if (ss == NULL) {
        DBG_ERR("Memory allocation failed for shared secret\n");
        goto err;
    }
    DBG_TRACE("Allocated buffer for shared secret\n");

    if (EVP_PKEY_decapsulate(pctx, ss, &sslen, kem_ciphertext->value._buffer,
                             kem_ciphertext->value._length) <= 0) {
        DBG_ERR("Failed to perform decapsulation\n");
        goto err;
    }
    DBG_TRACE("Decapsulation performed successfully\n");

    *kem_secret = OPENSSL_malloc(sslen);
    if (*kem_secret == NULL) {
        DBG_ERR("Memory allocation failed for kem_secret\n");
        OPENSSL_clear_free(ss, sslen);
        goto err;
    }
    memcpy(*kem_secret, ss, sslen);
    *length_secret = sslen;
    DBG_TRACE("Copied shared secret (length=%zu)\n", sslen);

    EVP_PKEY_CTX_free(pctx);
    OPENSSL_clear_free(ss, sslen);
    DBG_TRACE("Decapsulation successful\n");
    return DDS_SECURITY_VALIDATION_OK;

err:
    if (ss != NULL) {
        OPENSSL_clear_free(ss, sslen);
    }
    if (pctx != NULL) {
        EVP_PKEY_CTX_free(pctx);
    }
    DBG_ERR("pq_kem_decapsulation failed\n");
    return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_ValidationResult_t
validate_pq_signature(EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **bprops,
                      const uint32_t n_bprops, const unsigned char *signature, size_t signature_len,
                      DDS_Security_SecurityException *ex, OSSL_LIB_CTX *libctx) {
    DBG_TRACE("Entering validate_pq_signature (n_bprops=%u, signature_len=%zu)\n", n_bprops,
              signature_len);
    unsigned char *s = (unsigned char *)signature;
    size_t s_len = signature_len;
    DDS_Security_ValidationResult_t result =
        create_pq_validate_signature_impl(false, pkey, bprops, n_bprops, &s, &s_len, ex, libctx);
    if (result != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("validate_pq_signature failed\n");
    } else {
        DBG_TRACE("validate_pq_signature succeeded\n");
    }
    return result;
}

#endif /* PQ_CRYPTO */

#ifdef PQ_CRYPTO

DDS_Security_ValidationResult_t encapsulate_kem_key(uint8_t **kem_ciphertext, uint8_t **kem_secret,
                                                    size_t *length_ciphertext,
                                                    size_t *length_secret,
                                                    const DDS_Security_BinaryProperty_t *kem_public,
                                                    AuthenticationAlgoKind_t authKind) {
    DBG_TRACE("Entering encapsulate_kem_key (authKind=%d)\n", authKind);
    OQS_STATUS rc = OQS_ERROR;
    *kem_ciphertext = NULL;
    *kem_secret = NULL;

    switch (authKind) {
    case AUTH_ALGO_KIND_ML_KEM_768:
        *length_ciphertext = OQS_KEM_ml_kem_768_length_ciphertext;
        *length_secret = OQS_KEM_ml_kem_768_length_shared_secret;
        *kem_ciphertext = malloc(*length_ciphertext);
        *kem_secret = malloc(*length_secret);
        if (*kem_ciphertext == NULL || *kem_secret == NULL) {
            DBG_ERR("Memory allocation failed in encapsulate_kem_key\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Allocated kem_ciphertext (%zu) and kem_secret (%zu)\n", *length_ciphertext,
                  *length_secret);
        rc = OQS_KEM_ml_kem_768_encaps(*kem_ciphertext, *kem_secret, kem_public->value._buffer);
        break;
    default:
        assert(0);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (rc != OQS_SUCCESS) {
        DBG_ERR("OQS_KEM_ml_kem_768_encaps failed\n");
        memset(*kem_secret, 0, *length_secret);
        free(*kem_secret);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    DBG_TRACE("encapsulate_kem_key succeeded\n");
    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t
decapsulate_kem_key(uint8_t **kem_secret, size_t *length_secret,
                    const DDS_Security_BinaryProperty_t *kem_ciphertext,
                    const DDS_Security_BinaryProperty_t *kem_public, uint8_t *kem_private,
                    AuthenticationAlgoKind_t authKind) {
    DBG_TRACE("Entering decapsulate_kem_key (authKind=%d)\n", authKind);
    *kem_secret = NULL;
    OQS_STATUS rc = OQS_ERROR;

    switch (authKind) {
    case AUTH_ALGO_KIND_ML_KEM_768:
        *length_secret = OQS_KEM_ml_kem_768_length_shared_secret;
        *kem_secret = malloc(*length_secret);
        if (*kem_secret == NULL) {
            DBG_ERR("Memory allocation failed for kem_secret\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Allocated kem_secret (%zu)\n", *length_secret);
        rc = OQS_KEM_ml_kem_768_decaps(*kem_secret, kem_ciphertext->value._buffer, kem_private);
        break;
    default:
        assert(0);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (rc != OQS_SUCCESS) {
        DBG_ERR("OQS_KEM_ml_kem_768_decaps failed\n");
        memset(*kem_secret, 0, *length_secret);
        free(*kem_secret);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    DBG_TRACE("decapsulate_kem_key succeeded\n");
    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t
create_pq_signature(EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **bprops,
                    const uint32_t n_bprops, unsigned char **signature, size_t *signature_len,
                    DDS_Security_SecurityException *ex, uint8_t **sign_public_key,
                    AuthenticationAlgoKind_t authKind, OSSL_LIB_CTX *libctx) {
    DBG_TRACE("Entering create_pq_signature (authKind=%d, n_bprops=%u)\n", authKind, n_bprops);
    int ret = create_pq_validate_signature_impl(true, pkey, bprops, n_bprops, signature,
                                                signature_len, ex, libctx);
    if (ret != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("create_pq_validate_signature_impl failed\n");
    } else {
        DBG_TRACE("Signature created successfully (length=%zu)\n", *signature_len);
    }
    return ret;
}

DDS_Security_ValidationResult_t
validate_kem_public_key_in_token(const DDS_Security_BinaryProperty_t *kem_public_prop,
                                 AuthenticationAlgoKind_t expected_kind,
                                 DDS_Security_SecurityException *ex) {

    if (!kem_public_prop || !kem_public_prop->value._buffer) {
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "KEM public key property is NULL or empty");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    size_t expected_size = get_kem_public_key_size(expected_kind);
    if (expected_size == 0) {
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "Unknown KEM algorithm kind: %d",
                                   expected_kind);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (kem_public_prop->value._length != expected_size) {
        const char *algo_name = get_authentication_algo(expected_kind);
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Invalid %s public key size: %u (expected %zu)",
            algo_name ? algo_name : "KEM", kem_public_prop->value._length, expected_size);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t
validate_kem_ciphertext_in_token(const DDS_Security_BinaryProperty_t *kem_ciphertext_prop,
                                 AuthenticationAlgoKind_t expected_kind,
                                 DDS_Security_SecurityException *ex) {

    if (!kem_ciphertext_prop || !kem_ciphertext_prop->value._buffer) {
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "KEM ciphertext property is NULL or empty");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    size_t expected_size = get_kem_ciphertext_size(expected_kind);
    if (expected_size == 0) {
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED, "Unknown KEM algorithm kind: %d",
                                   expected_kind);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (kem_ciphertext_prop->value._length != expected_size) {
        const char *algo_name = get_authentication_algo(expected_kind);
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Invalid %s ciphertext size: %u (expected %zu)",
            algo_name ? algo_name : "KEM", kem_ciphertext_prop->value._length, expected_size);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    return DDS_SECURITY_VALIDATION_OK;
}

#endif

uint8_t *serialize_binary_properties(const DDS_Security_BinaryProperty_t **binary_properties,
                                     int n_bprops, size_t *message_len) {
    DBG_TRACE("Entering serialize_binary_properties (n_bprops=%d)\n", n_bprops);
    unsigned char *buffer;
    size_t size;
    DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);

    DDS_Security_Serialize_BinaryPropertyArray(serializer, binary_properties, n_bprops);
    DDS_Security_Serializer_buffer(serializer, &buffer, &size);
    DBG_TRACE("Serialized %d properties into buffer (size=%zu)\n", n_bprops, size);

    *message_len = size;
    uint8_t *message = malloc(size);
    if (!message) {
        DBG_ERR("Memory allocation failed for serialized message\n");
        ddsrt_free(buffer);
        DDS_Security_Serializer_free(serializer);
        return NULL;
    }

    memcpy(message, buffer, size);
    ddsrt_free(buffer);
    DDS_Security_Serializer_free(serializer);

    DBG_TRACE("serialize_binary_properties returning message_len=%zu\n", *message_len);
    return message;
}