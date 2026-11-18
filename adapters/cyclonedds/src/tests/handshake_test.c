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
static identity mldsa, other_ca, ec_ca, ec_participant, ecdsa, ecdsa_peer, mldsa_peer, p384_ca,
    p384_participant;

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
  return strcmp(algorithm, "EC") == 0        ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")
         : strcmp(algorithm, "EC-P384") == 0 ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384")
                                             : EVP_PKEY_Q_keygen(NULL, NULL, algorithm);
}

static void issue(identity *id, X509 *ca, EVP_PKEY *ca_key, const char *algorithm) {
  EVP_PKEY *key = make_key(algorithm);
  X509 *certificate = make_certificate(key, "PQSec Test Participant", ca, ca_key);
  id->ca = to_data_uri(ca, NULL);
  id->certificate = to_data_uri(certificate, NULL);
  id->private_key = to_data_uri(NULL, key);
  X509_free(certificate);
  EVP_PKEY_free(key);
}

/* A CA and one participant certificate issued by it, or two (b may be NULL). */
static void make_identities(identity *a, identity *b, const char *ca_algorithm,
                            const char *algorithm_a, const char *algorithm_b) {
  EVP_PKEY *ca_key = make_key(ca_algorithm);
  X509 *ca = make_certificate(ca_key, "PQSec Test CA", NULL, NULL);
  issue(a, ca, ca_key, algorithm_a);
  if (b) {
    issue(b, ca, ca_key, algorithm_b);
  }
  X509_free(ca);
  EVP_PKEY_free(ca_key);
}

static void make_identity(identity *id, const char *ca_algorithm, const char *algorithm) {
  make_identities(id, NULL, ca_algorithm, algorithm, NULL);
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

/* kem is the value of dds.sec.auth.key_establishment_algorithm, or NULL. */
static bool start(participant *p, unsigned char id, const identity *identity, const char *kem) {
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
  qos.property.value._length = qos.property.value._maximum = kem ? 4 : 3;
  qos.property.value._buffer = DDS_Security_PropertySeq_allocbuf(4);
  qos.property.value._buffer[0].name = ddsrt_strdup(DDS_SEC_PROP_AUTH_IDENTITY_CA);
  qos.property.value._buffer[0].value = ddsrt_strdup(identity->ca);
  qos.property.value._buffer[1].name = ddsrt_strdup(DDS_SEC_PROP_AUTH_IDENTITY_CERT);
  qos.property.value._buffer[1].value = ddsrt_strdup(identity->certificate);
  qos.property.value._buffer[2].name = ddsrt_strdup(DDS_SEC_PROP_AUTH_PRIV_KEY);
  qos.property.value._buffer[2].value = ddsrt_strdup(identity->private_key);
  if (kem) {
    qos.property.value._buffer[3].name = ddsrt_strdup("dds.sec.auth.key_establishment_algorithm");
    qos.property.value._buffer[3].value = ddsrt_strdup(kem);
  }

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

static bool prepare_between(exchange *e, const identity *a, const identity *b, const char *kem_a,
                            const char *kem_b) {
  memset(e, 0, sizeof *e);
  return start(&e->a, 1, a, kem_a) && start(&e->b, 2, b, kem_b) && introduce(e) && request(e);
}

static bool prepare_with(exchange *e, const char *kem_a, const char *kem_b) {
  return prepare_between(e, &mldsa, &mldsa, kem_a, kem_b);
}

static bool prepare(exchange *e) {
  return prepare_with(e, NULL, NULL);
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

static void set_string(DDS_Security_OctetSeq *value, const char *text) {
  replace(value, text, strlen(text) + 1);
}

static void add(DDS_Security_DataHolder *token, const char *name,
                const DDS_Security_OctetSeq *value) {
  const uint32_t length = token->binary_properties._length;
  DDS_Security_BinaryProperty_t *properties = DDS_Security_BinaryPropertySeq_allocbuf(length + 1);
  memcpy(properties, token->binary_properties._buffer, length * sizeof *properties);
  DDS_Security_BinaryProperty_set_by_value(&properties[length], name, value->_buffer,
                                           value->_length);
  ddsrt_free(token->binary_properties._buffer);
  token->binary_properties._buffer = properties;
  token->binary_properties._length = token->binary_properties._maximum = length + 1;
}

static DDS_Security_ValidationResult_t process_final(exchange *e,
                                                     const DDS_Security_HandshakeMessageToken *m) {
  DDS_Security_HandshakeMessageToken unused = DDS_SECURITY_TOKEN_INIT;
  const DDS_Security_ValidationResult_t result =
      process_handshake(e->replier->auth, &unused, m, e->replier->handshake, &ex);
  DDS_Security_DataHolder_deinit(&unused);
  return result;
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

static bool happy_path_test(const char *kem) {
  exchange e;
  const bool ok = prepare_with(&e, kem, kem) && reply(&e) && complete(&e);
  finish(&e);
  return ok;
}

/* The replier uses the algorithm the initiator chose, not its own setting. */
static bool initiator_chooses_test(void) {
  exchange e;
  bool ok = prepare_with(&e, "ML-KEM-1024", "ML-KEM-768") && reply(&e) && complete(&e);
  const DDS_Security_OctetSeq *requested = ok ? property(&e.request, "c.kagree_algo") : NULL;
  const DDS_Security_OctetSeq *replied = ok ? property(&e.reply, "c.kagree_algo") : NULL;
  ok = requested && replied &&
       check(requested->_length == replied->_length &&
                 memcmp(requested->_buffer, replied->_buffer, requested->_length) == 0,
             "replier did not use the initiator's algorithm");
  finish(&e);
  return ok;
}

/* A request from a classical PKI-DH participant, under its 1.2 or 1.1 name. */
static bool classical_request_test(void) {
  static const char *const names[] = {"ECDHE-CEUM+P256", "ECDH+prime256v1-CEUM", ""};
  bool ok = true;
  for (size_t i = 0; ok && i < sizeof names / sizeof names[0]; ++i) {
    exchange e;
    ok = prepare(&e);
    DDS_Security_OctetSeq *algorithm = ok ? property(&e.request, "c.kagree_algo") : NULL;
    if (algorithm) {
      set_string(algorithm, names[i]);
    }
    ok = algorithm && check(begin_handshake_reply(e.replier->auth, &e.replier->handshake, &e.reply,
                                                  &e.request, e.replier->remote, e.replier->local,
                                                  &e.replier->participant_data,
                                                  &ex) == DDS_SECURITY_VALIDATION_FAILED,
                            "request with a classical key establishment algorithm was accepted");
    finish(&e);
  }
  return ok;
}

static bool reply_algorithm_test(void) {
  exchange e;
  bool ok = prepare_with(&e, "ML-KEM-768", "ML-KEM-768") && reply(&e);
  DDS_Security_OctetSeq *algorithm = ok ? property(&e.reply, "c.kagree_algo") : NULL;
  if (algorithm) {
    set_string(algorithm, "ML-KEM-1024");
  }
  ok = algorithm && check(process_reply(&e) == DDS_SECURITY_VALIDATION_FAILED,
                          "reply naming another algorithm than the request was accepted");
  finish(&e);
  return ok;
}

/* Echoed values are optional. One that differs from the local value is refused;
 * one that matches is accepted. */
static bool reply_echo_test(void) {
  exchange e;
  DDS_Security_HandshakeMessageToken genuine = DDS_SECURITY_TOKEN_INIT;
  DDS_Security_OctetSeq other = DDS_SECURITY_SEQUENCE_INIT;
  bool ok = prepare(&e) && reply(&e);
  const DDS_Security_OctetSeq *dh1 = ok ? property(&e.request, "dh1") : NULL;
  if (dh1) {
    DDS_Security_DataHolder_copy(&genuine, &e.reply);
    DDS_Security_OctetSeq_copy(&other, dh1);
    other._buffer[0] ^= 1;
    add(&e.reply, "dh1", &other);
  }
  ok = dh1 && check(process_reply(&e) == DDS_SECURITY_VALIDATION_FAILED,
                    "reply echoing a different dh1 was accepted");
  if (ok) {
    DDS_Security_DataHolder_deinit(&e.reply);
    DDS_Security_DataHolder_copy(&e.reply, &genuine);
    add(&e.reply, "dh1", dh1);
    ok = check(process_reply(&e) == DDS_SECURITY_VALIDATION_OK_FINAL_MESSAGE,
               "reply echoing the right dh1 was refused");
  }
  DDS_Security_OctetSeq_deinit(&other);
  DDS_Security_DataHolder_deinit(&genuine);
  finish(&e);
  return ok;
}

static bool final_mismatch_test(void) {
  exchange e;
  DDS_Security_HandshakeMessageToken altered = DDS_SECURITY_TOKEN_INIT;
  DDS_Security_OctetSeq other = DDS_SECURITY_SEQUENCE_INIT;
  bool ok = prepare(&e) && reply(&e) &&
            check(process_reply(&e) == DDS_SECURITY_VALIDATION_OK_FINAL_MESSAGE,
                  "reply processing failed");

  if (ok) {
    DDS_Security_DataHolder_copy(&altered, &e.final);
    DDS_Security_OctetSeq *challenge1 = property(&altered, "challenge1");
    ok = challenge1 && challenge1->_length == 32;
    if (ok) {
      challenge1->_buffer[0] ^= 1;
      ok = check(process_final(&e, &altered) == DDS_SECURITY_VALIDATION_FAILED,
                 "final with a different challenge1 was accepted");
    }
    DDS_Security_DataHolder_deinit(&altered);
  }
  if (ok) {
    DDS_Security_DataHolder_copy(&altered, &e.final);
    DDS_Security_OctetSeq *challenge2 = property(&altered, "challenge2");
    ok = challenge2 != NULL;
    if (ok) {
      challenge2->_length = 0;
      ok = check(process_final(&e, &altered) == DDS_SECURITY_VALIDATION_FAILED,
                 "final without challenge2 was accepted");
    }
    DDS_Security_DataHolder_deinit(&altered);
  }
  if (ok) {
    DDS_Security_DataHolder_copy(&altered, &e.final);
    DDS_Security_OctetSeq_copy(&other, property(&e.reply, "dh2"));
    other._buffer[0] ^= 1;
    add(&altered, "dh2", &other);
    ok = check(process_final(&e, &altered) == DDS_SECURITY_VALIDATION_FAILED,
               "final echoing a different dh2 was accepted");
    DDS_Security_DataHolder_deinit(&altered);
  }
  ok = ok && check(process_final(&e, &e.final) == DDS_SECURITY_VALIDATION_OK,
                   "a refused final blocked the genuine one");
  DDS_Security_OctetSeq_deinit(&other);
  finish(&e);
  return ok;
}

/* An attacker replaces the initiator's dh1 with its own key.  The replier
 * cannot notice, so the initiator must. */
static bool substituted_public_key_test(void) {
  exchange e;
  pqsec_kem_keypair *attacker = NULL;
  bool ok = prepare(&e) && pqsec_kem_keypair_generate(get_default_kem_algorithm_kind(), &attacker);
  DDS_Security_OctetSeq *public_key = ok ? property(&e.request, "dh1") : NULL;
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

/* An attacker replaces dh2 with a valid ciphertext of its own. */
static bool substituted_ciphertext_test(void) {
  exchange e;
  uint8_t *ciphertext = NULL, *secret = NULL;
  size_t ciphertext_size = 0, secret_size = 0;
  bool ok = prepare(&e) && reply(&e);
  DDS_Security_OctetSeq *public_key = ok ? property(&e.request, "dh1") : NULL;
  DDS_Security_OctetSeq *reply_ciphertext = ok ? property(&e.reply, "dh2") : NULL;
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
    DDS_Security_OctetSeq_copy(&first, property(&e.reply, "dh2"));
  }
  ok = ok && reply(&e);
  const DDS_Security_OctetSeq *second = ok ? property(&e.reply, "dh2") : NULL;
  ok = second &&
       check(second->_length == first._length &&
                 memcmp(second->_buffer, first._buffer, first._length) == 0,
             "retransmitted request got a different ciphertext") &&
       request(&e) && reply(&e);
  const DDS_Security_OctetSeq *third = ok ? property(&e.reply, "dh2") : NULL;
  ok = third &&
       check(third->_length != first._length ||
                 memcmp(third->_buffer, first._buffer, first._length) != 0,
             "request with a new key got the old ciphertext") &&
       complete(&e);
  DDS_Security_OctetSeq_deinit(&first);
  finish(&e);
  return ok;
}

/* ECDSA P-256 identities, alone or mixed with ML-DSA, complete a handshake
 * whose key establishment is still a KEM. */
static bool identity_test(const identity *a, const identity *b, const char *description) {
  exchange e;
  const bool ok = check(prepare_between(&e, a, b, "X25519MLKEM768", "X25519MLKEM768") &&
                            reply(&e) && complete(&e),
                        description);
  finish(&e);
  return ok;
}

/* Other implementations know the algorithm by its 1.1 name only. */
static bool ecdsa_wire_name_test(void) {
  static const char name[] = "ECDSA-SHA256";
  exchange e;
  const bool ok = prepare_between(&e, &ecdsa, &ecdsa, NULL, NULL);
  const DDS_Security_OctetSeq *sent = ok ? property(&e.request, "c.dsign_algo") : NULL;
  const bool named =
      check(sent && sent->_length == sizeof name && memcmp(sent->_buffer, name, sizeof name) == 0,
            "ECDSA identity not sent as ECDSA-SHA256");
  finish(&e);
  return named;
}

static bool ecdsa_identity_tests(void) {
  return ecdsa_wire_name_test() &&
         identity_test(&ecdsa, &ecdsa, "ECDSA identities did not authenticate") &&
         identity_test(&ec_ca, &ec_ca, "ML-DSA identity under an ECDSA CA did not authenticate") &&
         identity_test(&ec_participant, &ec_participant,
                       "ECDSA identity under an ML-DSA CA did not authenticate") &&
         identity_test(&ecdsa_peer, &mldsa_peer,
                       "ECDSA and ML-DSA participants did not authenticate each other") &&
         identity_test(&mldsa_peer, &ecdsa_peer,
                       "ML-DSA and ECDSA participants did not authenticate each other");
}

/* Other curves and classical key establishment stay out. */
static bool rejected_identity_test(void) {
  participant p;
  bool ok = check(!start(&p, 1, &p384_ca, NULL), "identity CA with a P-384 key was accepted");
  stop(&p);
  ok = ok && check(!start(&p, 1, &p384_participant, NULL),
                   "identity certificate with a P-384 key was accepted");
  stop(&p);
  ok = ok && check(!start(&p, 1, &mldsa, "ECDHE-CEUM+P256"),
                   "a classical key establishment algorithm was configured");
  stop(&p);
  return ok;
}

static bool different_ca_test(void) {
  exchange e;
  memset(&e, 0, sizeof e);
  bool ok =
      start(&e.a, 1, &mldsa, NULL) && start(&e.b, 2, &other_ca, NULL) && introduce(&e) &&
      request(&e) &&
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
  make_identity(&ecdsa, "EC", "EC");
  make_identities(&ecdsa_peer, &mldsa_peer, "EC", "EC", "ML-DSA-65");
  make_identity(&p384_ca, "EC-P384", "ML-DSA-65");
  make_identity(&p384_participant, "ML-DSA-65", "EC-P384");

  const bool ok = happy_path_test("ML-KEM-768") && happy_path_test("ML-KEM-1024") &&
                  happy_path_test("X25519MLKEM768") && happy_path_test("AUTO") &&
                  happy_path_test(NULL) && substituted_public_key_test() &&
                  substituted_ciphertext_test() && credential_binding_test() &&
                  tampered_final_test() && retransmission_test() && initiator_chooses_test() &&
                  classical_request_test() && reply_algorithm_test() && reply_echo_test() &&
                  final_mismatch_test() && ecdsa_identity_tests() && rejected_identity_test() &&
                  different_ca_test();

  free_identity(&mldsa);
  free_identity(&other_ca);
  free_identity(&ec_ca);
  free_identity(&ec_participant);
  free_identity(&ecdsa);
  free_identity(&ecdsa_peer);
  free_identity(&mldsa_peer);
  free_identity(&p384_ca);
  free_identity(&p384_participant);
  return ok ? 0 : 1;
}
