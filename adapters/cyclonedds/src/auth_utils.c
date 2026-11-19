// Copyright(c) 2006 to 2021 ZettaScale Technology and others
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
// v. 1.0 which is available at
// http://www.eclipse.org/org/documents/edl-v10.php.
//
// SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 * Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M) - Initial PQ integration
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * auth_utils.c - Authentication utility functions implementation
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security through OpenSSL providers. Based on CycloneDDS
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
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#define MAX_TRUSTED_CA 100

typedef enum {
  AUTH_CONF_ITEM_PREFIX_UNKNOWN,
  AUTH_CONF_ITEM_PREFIX_FILE,
  AUTH_CONF_ITEM_PREFIX_DATA,
  AUTH_CONF_ITEM_PREFIX_PKCS11
} AuthConfItemPrefix_t;

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
  if (get_key_algo_kind(key) != AUTH_ALGO_KIND_UNKNOWN) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    int valid = 0;
    if (ctx) {
      valid = isPrivate ? EVP_PKEY_private_check(ctx) : EVP_PKEY_public_check(ctx);
      EVP_PKEY_CTX_free(ctx);
    }
    if (valid != 1) {
      DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                 DDS_SECURITY_VALIDATION_FAILED, "Invalid %s key", sub);
      return DDS_SECURITY_VALIDATION_FAILED;
    }
    return DDS_SECURITY_VALIDATION_OK;
  }
  DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                             DDS_SECURITY_VALIDATION_FAILED,
                             "%s must use an ML-DSA or ECDSA P-256 key", sub);
  return DDS_SECURITY_VALIDATION_FAILED;
}

static DDS_Security_ValidationResult_t
check_certificate_type_and_size(X509 *cert, DDS_Security_SecurityException *ex) {
  DBG_TRACE("Entering check_certificate_type_and_size\n");
  assert(cert);

  DBG_TRACE("Retrieving public key from certificate\n");
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if (!pkey) {
    DBG_ERR("X509_get_pubkey failed\n");
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED, "X509_get_pubkey failed");
    return DDS_SECURITY_VALIDATION_FAILED;
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
  int comparison;
  assert(cert);
  comparison = X509_cmp_current_time(X509_get0_notBefore(cert));
  if (comparison == 0) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               "Certificate has an invalid notBefore value");
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  if (comparison > 0) {
    DDS_Security_Exception_set(
        ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_CODE,
        DDS_SECURITY_VALIDATION_FAILED, DDS_SECURITY_ERR_CERT_STARTDATE_IN_FUTURE_MESSAGE);
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  comparison = X509_cmp_current_time(X509_get0_notAfter(cert));
  if (comparison == 0) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               "Certificate has an invalid notAfter value");
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  if (comparison < 0) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CERT_EXPIRED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               DDS_SECURITY_ERR_CERT_EXPIRED_MESSAGE);
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t
load_X509_certificate_from_bio(BIO *bio, X509 **x509Cert, DDS_Security_SecurityException *ex) {
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
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_INVALID_FILE_PATH_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               "load_file_into_BIO: " DDS_SECURITY_ERR_INVALID_FILE_PATH_MESSAGE,
                               filename);
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
                               DDS_SECURITY_VALIDATION_FAILED, "load_file_into_BIO: ftell failed");
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
  while (!(feof(fp) || ferror(fp)) && (n = fread(tmp, 1, sizeof(tmp), fp)) > 0 && remain > 0) {
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
  if (!feof(fp) || ferror(fp)) {
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
                                DDS_Security_SecurityException *ex) {
  DBG_TRACE("load_X509_certificate_from_data() called (len=%d)\n", len);
  BIO *bio;

  bio = BIO_new_mem_buf((void *)data, len);
  if (!bio) {
    DBG_ERR("BIO_new_mem_buf failed\n");
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED, "BIO_new_mem_buf failed");
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  const DDS_Security_ValidationResult_t result = load_X509_certificate_from_bio(bio, x509Cert, ex);
  BIO_free(bio);
  return result;
}

DDS_Security_ValidationResult_t
load_X509_certificate_from_file(const char *filename, X509 **x509Cert,
                                DDS_Security_SecurityException *ex) {
  DBG_TRACE("load_X509_certificate_from_file() called (file='%s')\n", filename);
  BIO *bio = load_file_into_BIO(filename, ex);
  if (!bio) {
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  const DDS_Security_ValidationResult_t result = load_X509_certificate_from_bio(bio, x509Cert, ex);
  BIO_free(bio);
  return result;
}

static DDS_Security_ValidationResult_t
load_private_key_from_data(const char *data, const char *password, EVP_PKEY **privateKey,
                           DDS_Security_SecurityException *ex) {
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
                           DDS_Security_SecurityException *ex) {
  DBG_TRACE("load_private_key_from_file() called (file='%s')\n", filepath);
  BIO *bio = load_file_into_BIO(filepath, ex);
  if (!bio) {
    return DDS_SECURITY_VALIDATION_FAILED;
  }

  *privateKey =
      PEM_read_bio_PrivateKey_ex(bio, NULL, NULL, (void *)(password ? password : ""), NULL, NULL);
  if (!*privateKey) {
    DBG_ERR("PEM_read_bio_PrivateKey_ex failed\n");
    DDS_Security_Exception_set_with_openssl_error(
        ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
        DDS_SECURITY_VALIDATION_FAILED, "Failed to parse private key: ");
    BIO_free(bio);
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  DBG_TRACE("Loaded PQ private key from file\n");

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
                                                      DDS_Security_SecurityException *ex) {
  DDS_Security_ValidationResult_t result;
  char *contents = NULL;
  assert(data);
  assert(x509Cert);
  DBG_TRACE("load_X509_certificate() called\n");

  switch (get_conf_item_type(data, &contents)) {
  case AUTH_CONF_ITEM_PREFIX_FILE:
    result = load_X509_certificate_from_file(contents, x509Cert, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_DATA:
    result = load_X509_certificate_from_data(contents, (int)strlen(contents), x509Cert, ex);
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
                               (int)result, "Specified certificate has wrong format:\n%s", data);
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
                                                      DDS_Security_SecurityException *ex) {
  DDS_Security_ValidationResult_t result;
  char *contents = NULL;
  assert(data);
  assert(privateKey);
  DBG_TRACE("load_X509_private_key() called\n");

  switch (get_conf_item_type(data, &contents)) {
  case AUTH_CONF_ITEM_PREFIX_FILE:
    DBG_TRACE("Loading private key from file\n");
    result = load_private_key_from_file(contents, password, privateKey, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_DATA:
    DBG_TRACE("Loading private key from data\n");
    result = load_private_key_from_data(contents, password, privateKey, ex);
    break;
  case AUTH_CONF_ITEM_PREFIX_PKCS11:
    DBG_ERR("PKCS11 format not supported\n");
    result = DDS_SECURITY_VALIDATION_FAILED;
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               (int)result, "PrivateKey pkcs11 format currently not supported");
    break;
  default:
    DBG_ERR("Wrong PrivateKey format\n");
    result = DDS_SECURITY_VALIDATION_FAILED;
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               (int)result, "Specified PrivateKey has wrong format");
    break;
  }
  free_secret_string(contents);

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
                                                   X509_CRL *crl,
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

  ctx = X509_STORE_CTX_new();
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
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_TRUSTED_CA_DIR_MAX_EXCEEDED_CODE, 0,
            DDS_SECURITY_ERR_TRUSTED_CA_DIR_MAX_EXCEEDED_MESSAGE, MAX_TRUSTED_CA);
        failed = true;
      } else if (load_X509_certificate_from_file(fname, &ca, ex) == DDS_SECURITY_VALIDATION_OK) {
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

/*-----------------------------------------------------------------------------------------------------------------------------------*/

/* ML-DSA signs the transcript itself (pure ML-DSA); ECDSA signs its
 * SHA-256 digest and gives a DER signature, as the built-in plugin does. */

static DDS_Security_ValidationResult_t
create_validate_signature(bool create, EVP_PKEY *key, const unsigned char *data, size_t data_size,
                          unsigned char **signature, size_t *signature_size,
                          DDS_Security_SecurityException *ex) {
  EVP_MD_CTX *context = NULL;
  DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_FAILED;
  const char *digest =
      get_key_algo_kind(key) == AUTH_ALGO_KIND_ECDSA_P256 ? OSSL_DIGEST_NAME_SHA2_256 : NULL;

  if (!key || !data || !signature || !signature_size ||
      (!create && (!*signature || *signature_size == 0))) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               "Invalid signature operation parameters");
    return DDS_SECURITY_VALIDATION_FAILED;
  }

  context = EVP_MD_CTX_new();
  if (!context) {
    goto openssl_error;
  }

  if (create) {
    if (EVP_DigestSignInit_ex(context, NULL, digest, NULL, NULL, key, NULL) != 1 ||
        EVP_DigestSign(context, NULL, signature_size, data, data_size) != 1) {
      goto openssl_error;
    }
    *signature = ddsrt_malloc(*signature_size);
    if (!*signature) {
      DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                 DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate signature");
      goto cleanup;
    }
    if (EVP_DigestSign(context, *signature, signature_size, data, data_size) != 1) {
      ddsrt_free(*signature);
      *signature = NULL;
      goto openssl_error;
    }
  } else {
    const int verified = EVP_DigestVerifyInit_ex(context, NULL, digest, NULL, NULL, key, NULL);
    if (verified != 1 ||
        EVP_DigestVerify(context, *signature, *signature_size, data, data_size) != 1) {
      DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                 DDS_SECURITY_VALIDATION_FAILED, "Signature verification failed");
      goto cleanup;
    }
  }

  result = DDS_SECURITY_VALIDATION_OK;
  goto cleanup;

openssl_error:
  DDS_Security_Exception_set_with_openssl_error(
      ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE, DDS_SECURITY_VALIDATION_FAILED,
      "Signature operation failed: ");

cleanup:
  EVP_MD_CTX_free(context);
  return result;
}

static DDS_Security_ValidationResult_t
create_validate_signature_properties(bool create, EVP_PKEY *key,
                                     const DDS_Security_BinaryProperty_t **properties,
                                     uint32_t property_count, unsigned char **signature,
                                     size_t *signature_size, DDS_Security_SecurityException *ex) {
  DDS_Security_Serializer serializer;
  unsigned char *buffer = NULL;
  size_t size = 0;
  DDS_Security_ValidationResult_t result;

  if (!properties || property_count == 0) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED, "Signed transcript is empty");
    return DDS_SECURITY_VALIDATION_FAILED;
  }

  serializer = DDS_Security_Serializer_new(4096, 4096);
  if (!serializer) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               "Failed to allocate transcript serializer");
    return DDS_SECURITY_VALIDATION_FAILED;
  }

  DDS_Security_Serialize_BinaryPropertyArray(serializer, properties, property_count);
  DDS_Security_Serializer_buffer(serializer, &buffer, &size);
  result = create_validate_signature(create, key, buffer, size, signature, signature_size, ex);
  ddsrt_free(buffer);
  DDS_Security_Serializer_free(serializer);
  return result;
}

DDS_Security_ValidationResult_t create_signature(EVP_PKEY *key,
                                                 const DDS_Security_BinaryProperty_t **properties,
                                                 uint32_t property_count, unsigned char **signature,
                                                 size_t *signature_size,
                                                 DDS_Security_SecurityException *ex) {
  return create_validate_signature_properties(true, key, properties, property_count, signature,
                                              signature_size, ex);
}

DDS_Security_ValidationResult_t
validate_signature(EVP_PKEY *key, const DDS_Security_BinaryProperty_t **properties,
                   uint32_t property_count, const unsigned char *signature, size_t signature_size,
                   DDS_Security_SecurityException *ex) {
  unsigned char *mutable_signature = (unsigned char *)signature;
  return create_validate_signature_properties(false, key, properties, property_count,
                                              &mutable_signature, &signature_size, ex);
}

static DDS_Security_ValidationResult_t
validate_kem_property(const DDS_Security_BinaryProperty_t *property,
                      AuthenticationAlgoKind_t expected_kind, bool public_key,
                      DDS_Security_SecurityException *ex) {
  const size_t expected_size =
      public_key ? get_kem_public_key_size(expected_kind) : get_kem_ciphertext_size(expected_kind);
  const char *description = public_key ? "public key" : "ciphertext";

  if (!property || !property->value._buffer || property->value._length == 0) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED, "ML-KEM %s is missing", description);
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  if (expected_size == 0 || property->value._length != expected_size) {
    DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                               DDS_SECURITY_VALIDATION_FAILED,
                               "Invalid %s %s size: %u (expected %zu)",
                               get_authentication_algo(expected_kind), description,
                               property->value._length, expected_size);
    return DDS_SECURITY_VALIDATION_FAILED;
  }
  return DDS_SECURITY_VALIDATION_OK;
}

DDS_Security_ValidationResult_t
validate_kem_public_key_in_token(const DDS_Security_BinaryProperty_t *property,
                                 AuthenticationAlgoKind_t expected_kind,
                                 DDS_Security_SecurityException *ex) {
  return validate_kem_property(property, expected_kind, true, ex);
}

DDS_Security_ValidationResult_t
validate_kem_ciphertext_in_token(const DDS_Security_BinaryProperty_t *property,
                                 AuthenticationAlgoKind_t expected_kind,
                                 DDS_Security_SecurityException *ex) {
  return validate_kem_property(property, expected_kind, false, ex);
}

void free_secret(void *secret, size_t size) {
  if (secret) {
    OPENSSL_cleanse(secret, size);
    ddsrt_free(secret);
  }
}

void free_secret_string(char *secret) {
  if (secret)
    free_secret(secret, strlen(secret));
}
