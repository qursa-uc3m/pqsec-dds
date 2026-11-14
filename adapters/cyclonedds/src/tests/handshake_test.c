/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * Drives two plugin instances through the handshake by calling the
 * Authentication SPI directly, as the upstream CycloneDDS plugin tests do.
 * Identities are generated in memory and passed as data: URIs.
 */

#include "authentication.h"
#include "pq_kem.h"

#include <dds/ddsi/ddsi_domaingv.h>
#include <dds/ddsrt/heap.h>
#include <dds/ddsrt/string.h>
#include <dds/security/core/dds_security_serialize.h>
#include <dds/security/core/dds_security_shared_secret.h>
#include <dds/security/core/dds_security_utils.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <string.h>

typedef struct {
  char *ca;
  char *certificate;
  char *private_key;
} identity;

typedef struct {
  dds_security_authentication *auth;
  DDS_Security_IdentityHandle local;
  DDS_Security_IdentityHandle remote;
  DDS_Security_GUID_t guid;
  DDS_Security_IdentityToken identity_token;
  DDS_Security_AuthRequestMessageToken auth_request;
  DDS_Security_OctetSeq participant_data;
  DDS_Security_HandshakeHandle handshake;
} participant;

typedef struct {
  participant a, b;
  participant *initiator, *replier;
  DDS_Security_HandshakeMessageToken request, reply, final;
} exchange;

static struct ddsi_domaingv gv;
static DDS_Security_SecurityException ex;
static long next_serial = 1;
static identity mldsa, other_ca, ec_ca, ec_participant;

static bool check(bool condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "%s%s%s\n", message, ex.message ? ": " : "", ex.message ? ex.message : "");
  }
  DDS_Security_Exception_reset(&ex);
  return condition;
}

static char *to_data_uri(X509 *certificate, EVP_PKEY *key) {
  BIO *bio = BIO_new(BIO_s_mem());
  char *pem, *uri;
  long size;

  if (certificate) {
    PEM_write_bio_X509(bio, certificate);
  } else {
    PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL);
  }
  size = BIO_get_mem_data(bio, &pem);
  uri = ddsrt_malloc((size_t)size + 7);
  memcpy(uri, "data:,", 6);
  memcpy(uri + 6, pem, (size_t)size);
  uri[size + 6] = '\0';
  BIO_free(bio);
  return uri;
}

static X509 *make_certificate(EVP_PKEY *key, const char *name, X509 *issuer, EVP_PKEY *issuer_key) {
  X509 *certificate = X509_new();
  X509_NAME *subject = X509_get_subject_name(certificate);
  EVP_PKEY *signer = issuer_key ? issuer_key : key;

  X509_set_version(certificate, X509_VERSION_3);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), next_serial++);
  X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 24 * 3600);
  X509_set_pubkey(certificate, key);
  X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char *)name, -1, -1, 0);
  X509_set_issuer_name(certificate, issuer ? X509_get_subject_name(issuer) : subject);
  if (!issuer) {
    X509_EXTENSION *extension =
        X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "critical,CA:TRUE");
    X509_add_ext(certificate, extension, -1);
    X509_EXTENSION_free(extension);
  }
  X509_sign(certificate, signer, EVP_PKEY_is_a(signer, "EC") ? EVP_sha256() : NULL);
  return certificate;
}

static EVP_PKEY *make_key(const char *algorithm) {
  return strcmp(algorithm, "EC") == 0 ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")
                                      : EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
}

/* A CA and one participant certificate issued by it. */
static void make_identity(identity *id, const char *ca_algorithm, const char *algorithm) {
  EVP_PKEY *ca_key = make_key(ca_algorithm), *key = make_key(algorithm);
  X509 *ca = make_certificate(ca_key, "PQSec Test CA", NULL, NULL);
  X509 *certificate = make_certificate(key, "PQSec Test Participant", ca, ca_key);
  id->ca = to_data_uri(ca, NULL);
  id->certificate = to_data_uri(certificate, NULL);
  id->private_key = to_data_uri(NULL, key);
  X509_free(certificate);
  X509_free(ca);
  EVP_PKEY_free(key);
  EVP_PKEY_free(ca_key);
}

static void free_identity(identity *id) {
  ddsrt_free(id->ca);
  ddsrt_free(id->certificate);
  ddsrt_free(id->private_key);
}

static void serialize_participant_data(participant *p) {
  DDS_Security_ParticipantBuiltinTopicData *data = DDS_Security_ParticipantBuiltinTopicData_alloc();
  DDS_Security_Serializer serializer = DDS_Security_Serializer_new(1024, 1024);
  unsigned char *buffer;
  size_t size;

  memcpy(data->key, &p->guid, sizeof data->key);
  for (size_t i = 0; i < 3; ++i) {
    data->key[i] = ddsrt_fromBE4u(data->key[i]);
  }
  data->identity_token.class_id = ddsrt_strdup("");
  data->permissions_token.class_id = ddsrt_strdup("");
  DDS_Security_Serialize_ParticipantBuiltinTopicData(serializer, data);
  DDS_Security_Serializer_buffer(serializer, &buffer, &size);
  p->participant_data._buffer = buffer;
  p->participant_data._length = p->participant_data._maximum = (uint32_t)size;
  DDS_Security_Serializer_free(serializer);
  DDS_Security_ParticipantBuiltinTopicData_free(data);
}

static bool start(participant *p, unsigned char id, const identity *identity) {
  DDS_Security_Qos qos;
  DDS_Security_GUID_t candidate;
  void *context = NULL;

  memset(p, 0, sizeof *p);
  memset(&candidate, 0, sizeof candidate);
  for (size_t i = 0; i < sizeof candidate.prefix; ++i) {
    candidate.prefix[i] = (unsigned char)(i + id);
  }
  candidate.entityId.entityKind = 0xc1;

  memset(&qos, 0, sizeof qos);
  qos.property.value._length = qos.property.value._maximum = 3;
  qos.property.value._buffer = DDS_Security_PropertySeq_allocbuf(3);
  qos.property.value._buffer[0].name = ddsrt_strdup(DDS_SEC_PROP_AUTH_IDENTITY_CA);
  qos.property.value._buffer[0].value = ddsrt_strdup(identity->ca);
  qos.property.value._buffer[1].name = ddsrt_strdup(DDS_SEC_PROP_AUTH_IDENTITY_CERT);
  qos.property.value._buffer[1].value = ddsrt_strdup(identity->certificate);
  qos.property.value._buffer[2].name = ddsrt_strdup(DDS_SEC_PROP_AUTH_PRIV_KEY);
  qos.property.value._buffer[2].value = ddsrt_strdup(identity->private_key);

  const bool ok =
      init_authentication(NULL, &context, &gv) == 0 &&
      (p->auth = context, validate_local_identity(p->auth, &p->local, &p->guid, 0, &qos, &candidate,
                                                  &ex) == DDS_SECURITY_VALIDATION_OK) &&
      get_identity_token(p->auth, &p->identity_token, p->local, &ex);
  DDS_Security_PropertySeq_deinit(&qos.property.value);
  if (ok) {
    serialize_participant_data(p);
  }
  return ok;
}

static void stop(participant *p) {
  DDS_Security_DataHolder_deinit(&p->identity_token);
  DDS_Security_DataHolder_deinit(&p->auth_request);
  DDS_Security_OctetSeq_deinit(&p->participant_data);
  if (p->auth) {
    finalize_authentication(p->auth);
  }
}

static bool introduce(exchange *e) {
  DDS_Security_AuthRequestMessageToken unused = DDS_SECURITY_TOKEN_INIT;
  const DDS_Security_ValidationResult_t a_role =
      validate_remote_identity(e->a.auth, &e->a.remote, &e->a.auth_request, NULL, e->a.local,
                               &e->b.identity_token, &e->b.guid, &ex);
  const DDS_Security_ValidationResult_t b_role =
      validate_remote_identity(e->b.auth, &e->b.remote, &e->b.auth_request, NULL, e->b.local,
                               &e->a.identity_token, &e->a.guid, &ex);
  if (!check(a_role != b_role && a_role != DDS_SECURITY_VALIDATION_FAILED &&
                 b_role != DDS_SECURITY_VALIDATION_FAILED,
             "participants did not choose complementary roles")) {
    return false;
  }
  /* Exchange the AuthRequest tokens, so both sides know the future challenges. */
  if (validate_remote_identity(e->a.auth, &e->a.remote, &unused, &e->b.auth_request, e->a.local,
                               &e->b.identity_token, &e->b.guid,
                               &ex) == DDS_SECURITY_VALIDATION_FAILED ||
      validate_remote_identity(e->b.auth, &e->b.remote, &unused, &e->a.auth_request, e->b.local,
                               &e->a.identity_token, &e->a.guid,
                               &ex) == DDS_SECURITY_VALIDATION_FAILED) {
    return check(false, "AuthRequest exchange failed");
  }
  e->initiator = a_role == DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_REQUEST ? &e->a : &e->b;
  e->replier = e->initiator == &e->a ? &e->b : &e->a;
  return true;
}

static bool request(exchange *e) {
  DDS_Security_DataHolder_deinit(&e->request);
  return check(begin_handshake_request(e->initiator->auth, &e->initiator->handshake, &e->request,
                                       e->initiator->local, e->initiator->remote,
                                       &e->initiator->participant_data,
                                       &ex) == DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_MESSAGE,
               "begin_handshake_request failed");
}

static bool reply(exchange *e) {
  DDS_Security_DataHolder_deinit(&e->reply);
  return check(begin_handshake_reply(e->replier->auth, &e->replier->handshake, &e->reply,
                                     &e->request, e->replier->remote, e->replier->local,
                                     &e->replier->participant_data,
                                     &ex) == DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_MESSAGE,
               "begin_handshake_reply failed");
}

static DDS_Security_ValidationResult_t process_reply(exchange *e) {
  DDS_Security_DataHolder_deinit(&e->final);
  return process_handshake(e->initiator->auth, &e->final, &e->reply, e->initiator->handshake, &ex);
}

static bool prepare(exchange *e) {
  memset(e, 0, sizeof *e);
  return start(&e->a, 1, &mldsa) && start(&e->b, 2, &mldsa) && introduce(e) && request(e);
}

static void finish(exchange *e) {
  DDS_Security_DataHolder_deinit(&e->request);
  DDS_Security_DataHolder_deinit(&e->reply);
  DDS_Security_DataHolder_deinit(&e->final);
  stop(&e->a);
  stop(&e->b);
}

static DDS_Security_OctetSeq *property(DDS_Security_DataHolder *token, const char *name) {
  for (uint32_t i = 0; i < token->binary_properties._length; ++i) {
    if (strcmp(token->binary_properties._buffer[i].name, name) == 0) {
      return &token->binary_properties._buffer[i].value;
    }
  }
  return NULL;
}

static void replace(DDS_Security_OctetSeq *value, const void *data, size_t size) {
  ddsrt_free(value->_buffer);
  value->_buffer = ddsrt_memdup(data, size);
  value->_length = value->_maximum = (uint32_t)size;
}

static bool complete(exchange *e) {
  DDS_Security_HandshakeMessageToken unused = DDS_SECURITY_TOKEN_INIT;
  DDS_Security_SharedSecretHandle first, second;
  const DDS_Security_SharedSecretHandleImpl *s1, *s2;

  if (!check(process_reply(e) == DDS_SECURITY_VALIDATION_OK_FINAL_MESSAGE,
             "reply processing failed") ||
      !check(process_handshake(e->replier->auth, &unused, &e->final, e->replier->handshake, &ex) ==
                 DDS_SECURITY_VALIDATION_OK,
             "final processing failed")) {
    return false;
  }
  first = get_shared_secret(e->initiator->auth, e->initiator->handshake, &ex);
  second = get_shared_secret(e->replier->auth, e->replier->handshake, &ex);
  s1 = (const DDS_Security_SharedSecretHandleImpl *)(uintptr_t)first;
  s2 = (const DDS_Security_SharedSecretHandleImpl *)(uintptr_t)second;
  return check(s1 && s2 && s1->shared_secret_size == PQSEC_SHARED_SECRET_SIZE &&
                   s2->shared_secret_size == PQSEC_SHARED_SECRET_SIZE &&
                   memcmp(s1->shared_secret, s2->shared_secret, PQSEC_SHARED_SECRET_SIZE) == 0,
               "shared secrets differ");
}

static bool happy_path_test(void) {
  exchange e;
  const bool ok = prepare(&e) && reply(&e) && complete(&e);
  finish(&e);
  return ok;
}

/* An attacker replaces the initiator's KEM public key with its own.  The
 * replier cannot notice, so the initiator must. */
static bool substituted_public_key_test(void) {
  exchange e;
  pqsec_kem_keypair *attacker = NULL;
  bool ok = prepare(&e) && pqsec_kem_keypair_generate(get_default_kem_algorithm_kind(), &attacker);
  DDS_Security_OctetSeq *public_key = ok ? property(&e.request, "pqsec-dds.kem_public") : NULL;
  if (public_key) {
    replace(public_key, attacker->public_key, attacker->public_key_size);
  }
  ok = public_key && reply(&e) &&
       check(process_reply(&e) == DDS_SECURITY_VALIDATION_FAILED,
             "reply to a substituted KEM public key was accepted");
  pqsec_kem_keypair_free(attacker);
  finish(&e);
  return ok;
}

/* An attacker replaces the ciphertext with a valid one of its own. */
static bool substituted_ciphertext_test(void) {
  exchange e;
  uint8_t *ciphertext = NULL, *secret = NULL;
  size_t ciphertext_size = 0, secret_size = 0;
  bool ok = prepare(&e) && reply(&e);
  DDS_Security_OctetSeq *public_key = ok ? property(&e.request, "pqsec-dds.kem_public") : NULL;
  DDS_Security_OctetSeq *reply_ciphertext =
      ok ? property(&e.reply, "pqsec-dds.kem_ciphertext") : NULL;
  ok = public_key && reply_ciphertext &&
       pqsec_kem_encapsulate(get_default_kem_algorithm_kind(), public_key->_buffer,
                             public_key->_length, &ciphertext, &ciphertext_size, &secret,
                             &secret_size);
  if (ok) {
    replace(reply_ciphertext, ciphertext, ciphertext_size);
  }
  ok = ok && check(process_reply(&e) == DDS_SECURITY_VALIDATION_FAILED,
                   "substituted KEM ciphertext was accepted");
  pqsec_kem_buffer_free(ciphertext);
  pqsec_kem_secret_free(secret, secret_size);
  finish(&e);
  return ok;
}

/* c.perm is checked by nothing but the credential hash, so a change to it is
 * only caught if the hash is signed.  gv.handshake_include_optional is false,
 * which is the CycloneDDS default. */
static bool credential_binding_test(void) {
  exchange e;
  static const char forged[] = "<permissions>forged</permissions>";
  bool ok = prepare(&e) && reply(&e);
  DDS_Security_OctetSeq *permissions = ok ? property(&e.reply, "c.perm") : NULL;
  if (permissions) {
    replace(permissions, forged, sizeof forged);
  }
  ok = permissions && check(process_reply(&e) == DDS_SECURITY_VALIDATION_FAILED,
                            "reply with altered permissions was accepted");
  finish(&e);
  return ok;
}

static bool tampered_final_test(void) {
  exchange e;
  DDS_Security_HandshakeMessageToken unused = DDS_SECURITY_TOKEN_INIT;
  bool ok = prepare(&e) && reply(&e) &&
            check(process_reply(&e) == DDS_SECURITY_VALIDATION_OK_FINAL_MESSAGE,
                  "reply processing failed");
  DDS_Security_OctetSeq *signature = ok ? property(&e.final, "signature") : NULL;
  if (signature) {
    signature->_buffer[0] ^= 1;
  }
  ok = signature &&
       check(process_handshake(e.replier->auth, &unused, &e.final, e.replier->handshake, &ex) ==
                 DDS_SECURITY_VALIDATION_FAILED,
             "tampered final signature was accepted");
  finish(&e);
  return ok;
}

/* An identical Request gets the same ciphertext.  A Request with a new key
 * gets a fresh one, and the handshake still completes. */
static bool retransmission_test(void) {
  exchange e;
  DDS_Security_OctetSeq first = DDS_SECURITY_SEQUENCE_INIT;
  bool ok = prepare(&e) && reply(&e);
  if (ok) {
    DDS_Security_OctetSeq_copy(&first, property(&e.reply, "pqsec-dds.kem_ciphertext"));
  }
  ok = ok && reply(&e);
  const DDS_Security_OctetSeq *second = ok ? property(&e.reply, "pqsec-dds.kem_ciphertext") : NULL;
  ok = second &&
       check(second->_length == first._length &&
                 memcmp(second->_buffer, first._buffer, first._length) == 0,
             "retransmitted request got a different ciphertext") &&
       request(&e) && reply(&e);
  const DDS_Security_OctetSeq *third = ok ? property(&e.reply, "pqsec-dds.kem_ciphertext") : NULL;
  ok = third &&
       check(third->_length != first._length ||
                 memcmp(third->_buffer, first._buffer, first._length) != 0,
             "request with a new key got the old ciphertext") &&
       complete(&e);
  DDS_Security_OctetSeq_deinit(&first);
  finish(&e);
  return ok;
}

static bool classical_identity_test(void) {
  participant p;
  bool ok = check(!start(&p, 1, &ec_ca), "identity CA with a classical key was accepted");
  stop(&p);
  ok = ok && check(!start(&p, 1, &ec_participant),
                   "identity certificate with a classical key was accepted");
  stop(&p);
  return ok;
}

static bool different_ca_test(void) {
  exchange e;
  memset(&e, 0, sizeof e);
  bool ok =
      start(&e.a, 1, &mldsa) && start(&e.b, 2, &other_ca) && introduce(&e) && request(&e) &&
      check(begin_handshake_reply(e.replier->auth, &e.replier->handshake, &e.reply, &e.request,
                                  e.replier->remote, e.replier->local, &e.replier->participant_data,
                                  &ex) == DDS_SECURITY_VALIDATION_FAILED,
            "certificate from a different CA was accepted");
  finish(&e);
  return ok;
}

int main(void) {
  memset(&gv, 0, sizeof gv);
  make_identity(&mldsa, "ML-DSA-65", "ML-DSA-65");
  make_identity(&other_ca, "ML-DSA-65", "ML-DSA-65");
  make_identity(&ec_ca, "EC", "ML-DSA-65");
  make_identity(&ec_participant, "ML-DSA-65", "EC");

  const bool ok = happy_path_test() && substituted_public_key_test() &&
                  substituted_ciphertext_test() && credential_binding_test() &&
                  tampered_final_test() && retransmission_test() && classical_identity_test() &&
                  different_ca_test();

  free_identity(&mldsa);
  free_identity(&other_ca);
  free_identity(&ec_ca);
  free_identity(&ec_participant);
  return ok ? 0 : 1;
}
