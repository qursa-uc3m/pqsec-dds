/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 * Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M) - Initial PQ integration
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * authentication.c - Main authentication plugin implementation
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ac_tokens.h"
#include "auth_algs.h"
#include "auth_tokens.h"
#include "auth_utils.h"
#include "authentication.h"
#include "dds/ddsi/ddsi_domaingv.h"
#include "dds/ddsrt/atomics.h"
#include "dds/ddsrt/heap.h"
#include "dds/ddsrt/hopscotch.h"
#include "dds/ddsrt/static_assert.h"
#include "dds/ddsrt/string.h"
#include "dds/ddsrt/sync.h"
#include "dds/security/core/dds_security_serialize.h"
#include "dds/security/core/dds_security_timed_cb.h"
#include "dds/security/core/dds_security_utils.h"
#include "dds/security/core/shared_secret.h"
#include "dds/security/dds_security_api.h"
#include "dds/security/dds_security_api_types.h"
#include "dds/security/openssl_support.h"
#include "debug.h"

#ifdef MEASURE_HANDSHAKE_TIME
#include "bench_hook.h"
FILE *target_csv;
struct timespec start, end;
#endif

/* HASH OPTIONAL: 1=Include optional fields / 0=Just mandatory fields*/
#define HASH_OPTIONAL 1

#ifndef EVP_PKEY_id
#define EVP_PKEY_id(k) ((k)->type)
#endif

#define HANDSHAKE_SIGNATURE_CONTENT_SIZE 6
// #else
//  Mandatory values included
#define PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE 4
// Optional values included
#define PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE_OPT 6
// #endif
#define ADJUSTED_GUID_PREFIX_FLAG 0x80

typedef unsigned char HashValue_t[SHA256_DIGEST_LENGTH];

// security objects
typedef enum {
    SECURITY_OBJECT_KIND_UNKNOWN,
    SECURITY_OBJECT_KIND_LOCAL_IDENTITY,
    SECURITY_OBJECT_KIND_REMOTE_IDENTITY,
    SECURITY_OBJECT_KIND_IDENTITY_RELATION,
    SECURITY_OBJECT_KIND_HANDSHAKE
} SecurityObjectKind_t;

typedef enum { CREATEDREQUEST, CREATEDREPLY } CreatedHandshakeStep_t;

typedef struct SecurityObject SecurityObject;
typedef void (*SecurityObjectDestructor)(SecurityObject *obj);

struct SecurityObject {
    int64_t handle;
    SecurityObjectKind_t kind;
    SecurityObjectDestructor destructor;
};

#ifndef NDEBUG
#define CHECK_OBJECT_KIND(o, k) assert(security_object_valid((SecurityObject *)(o), k))
#else
#define CHECK_OBJECT_KIND(o, k)
#endif

#define SECURITY_OBJECT(o) ((SecurityObject *)(o))
#define SECURITY_OBJECT_HANDLE(o) (SECURITY_OBJECT(o)->handle)
#define IDENTITY_HANDLE(o) ((DDS_Security_IdentityHandle)SECURITY_OBJECT_HANDLE(o))
#define HANDSHAKE_HANDLE(o) ((DDS_Security_HandshakeHandle)SECURITY_OBJECT_HANDLE(o))

#define SECURITY_OBJECT_VALID(o, k) security_object_valid((SecurityObject *)(o), k)

typedef struct LocalIdentityInfo {
    SecurityObject _parent;
    DDS_Security_DomainId domainId;
    DDS_Security_GUID_t candidateGUID;
    DDS_Security_GUID_t adjustedGUID;
    X509 *identityCert;
    X509 *identityCA;
    EVP_PKEY *privateKey;
    X509_CRL *crl;
    DDS_Security_OctetSeq pdata;
    AuthenticationAlgoKind_t dsignAlgoKind;
    AuthenticationAlgoKind_t kagreeAlgoKind;
    char *permissionsDocument;
    dds_security_time_event_handle_t timer;
} LocalIdentityInfo;

typedef struct RemoteIdentityInfo {
    SecurityObject _parent;
    DDS_Security_GUID_t guid;
    X509 *identityCert;
    AuthenticationAlgoKind_t dsignAlgoKind;
    AuthenticationAlgoKind_t kagreeAlgoKind;
    DDS_Security_IdentityToken *remoteIdentityToken;
    DDS_Security_OctetSeq pdata;
    char *permissionsDocument;
    struct ddsrt_hh *linkHash; // contains the IdentityRelation objects
    dds_security_time_event_handle_t timer;
} RemoteIdentityInfo;

/* This structure contains the relation between a local and a remote identity
 * The handle for this object is the same as the handle of the associated
 * local identity object. The IdentityRelation object will be stored with the
 * remote identity.
 */
typedef struct IdentityRelation {
    SecurityObject _parent;
    LocalIdentityInfo *localIdentity;
    RemoteIdentityInfo *remoteIdentity;
    AuthenticationChallenge *lchallenge;
    AuthenticationChallenge *rchallenge;
} IdentityRelation;

typedef struct HandshakeInfo {
    SecurityObject _parent;
    IdentityRelation *relation;
    HashValue_t hash_c1;
    HashValue_t hash_c2;
#ifdef PQ_CRYPTO
    EVP_PKEY *kem_keypair; // KEM key pair (private + public key)
    EVP_PKEY *kem_pk;      // Remote party's KEM public key
    uint8_t *kem_ct;       // KEM ciphertext (encapsulation output)
    size_t kem_ct_len;     // Length of KEM ciphertext
    uint8_t *kem_ss;       // KEM shared secret (ss = shared secret)
    size_t kem_ss_len;     // Shared secret length
#else
    EVP_PKEY *ldh;
    EVP_PKEY *rdh;
#endif
    DDS_Security_SharedSecretHandleImpl *shared_secret_handle_impl;
    CreatedHandshakeStep_t created_in;
} HandshakeInfo;

typedef struct dds_security_authentication_impl {
    dds_security_authentication base;
    ddsrt_mutex_t lock;
    struct ddsrt_hh *objectHash;
    struct ddsrt_hh *remoteGuidHash;
    struct dds_security_timed_dispatcher *dispatcher;
    const dds_security_authentication_listener *listener;
    X509Seq trustedCAList;
    bool include_optional;
#ifdef PQ_CRYPTO
    OSSL_LIB_CTX *oqs_libctx;
    bool oqs_provider_available;
#endif
} dds_security_authentication_impl;

/* data type for timer dispatcher */
typedef struct {
    dds_security_authentication_impl *auth;
    DDS_Security_IdentityHandle hdl;
} validity_cb_info;

#ifdef PQ_CRYPTO

#ifdef PQ_CRYPTO
static DDS_Security_ValidationResult_t generate_pq_kem_keys(EVP_PKEY **kemkey,
                                                            AuthenticationAlgoKind_t kagreeAlgoKind,
                                                            DDS_Security_SecurityException *ex,
                                                            OSSL_LIB_CTX *libctx);
#endif

static const char *get_oqs_provider_name(void) {
    const char *provider_name = getenv("OQS_PROVIDER_NAME");
    if (provider_name) {
        DBG_TRACE("Using OQS_PROVIDER_NAME from environment: '%s'\n", provider_name);
        return provider_name;
    }
    DBG_TRACE("OQS_PROVIDER_NAME not set, defaulting to 'oqsprovider'\n");
    return "oqsprovider";
}

static const char *get_oqs_config_file(void) {
    const char *config_file = getenv("OPENSSL_CONF");
    if (config_file) {
        DBG_TRACE("Using OPENSSL_CONF from environment: '%s'\n", config_file);
        return config_file;
    }
    DBG_TRACE("OPENSSL_CONF not set, returning NULL\n");
    return NULL;
}

static bool load_oqs_provider_to_context(OSSL_LIB_CTX **libctx, const char *modulename,
                                         const char *config_file) {
    char *modules_dir;

    DBG_INFO("Loading provider '%s'\n", modulename);

    /* Debug environment variables */
    modules_dir = getenv("OPENSSL_MODULES");
    DBG_TRACE("OPENSSL_CONF=%s\n", config_file ? config_file : "not set");
    DBG_TRACE("OPENSSL_MODULES=%s\n", modules_dir ? modules_dir : "not set");

    if (!*libctx) {
        *libctx = OSSL_LIB_CTX_new();
        if (!*libctx) {
            DBG_ERR("Failed to create OpenSSL library context\n");
            return false;
        }
        DBG_TRACE("Created new OpenSSL library context\n");
    }

    /* Load the default provider */
    if (!OSSL_PROVIDER_load(*libctx, "default")) {
        DBG_ERR("Failed to load default provider\n");
        return false;
    }
    DBG_TRACE("Default provider loaded\n");

    if (!OSSL_PROVIDER_load(*libctx, "legacy")) {
        DBG_ERR("Failed to load legacy provider\n");
        return false;
    }
    DBG_TRACE("Legacy provider loaded\n");

    /* Try to load the requested provider */
    if (!OSSL_PROVIDER_load(*libctx, modulename)) {
        DBG_ERR("Failed to load provider '%s'\n", modulename);
        return false;
    }
    DBG_TRACE("Provider '%s' loaded, verifying availability\n", modulename);

    /* Verify provider is available */
    if (!OSSL_PROVIDER_available(*libctx, modulename)) {
        DBG_ERR("Provider '%s' is not available after loading\n", modulename);
        return false;
    }

    DBG_INFO("Provider '%s' loaded successfully\n", modulename);
    return true;
}

static OSSL_LIB_CTX *get_oqs_context(const dds_security_authentication_impl *auth) {
    if (!auth) {
        DBG_WARN("get_oqs_context: null authentication instance\n");
        return NULL;
    }
    if (auth->oqs_provider_available) {
        DBG_TRACE("get_oqs_context: returning existing OQS library context\n");
        return auth->oqs_libctx;
    }
    DBG_TRACE("get_oqs_context: OQS provider not available, returning NULL\n");
    return NULL;
}
#endif

static bool security_object_valid(SecurityObject *obj, SecurityObjectKind_t kind) {
    if (!obj) {
        DBG_ERR("security_object_valid: obj is NULL\n");
        return false;
    }
    if (obj->kind != kind) {
        DBG_ERR("security_object_valid: kind mismatch (expected %d, got %d)\n", kind, obj->kind);
        return false;
    }
    if (kind == SECURITY_OBJECT_KIND_IDENTITY_RELATION) {
        IdentityRelation *relation = (IdentityRelation *)obj;
        if (!relation->localIdentity || !relation->remoteIdentity ||
            (ddsrt_address)obj->handle != (ddsrt_address)relation->localIdentity) {
            DBG_ERR("security_object_valid: invalid IdentityRelation fields\n");
            return false;
        }
    } else if ((ddsrt_address)obj->handle != (ddsrt_address)obj) {
        DBG_ERR("security_object_valid: handle does not match object address\n");
        return false;
    }

    DBG_TRACE("security_object_valid: object is valid (kind=%d)\n", kind);
    return true;
}

static uint32_t security_object_hash(const void *obj) {
    const SecurityObject *object = obj;
    const uint64_t c = UINT64_C(16292676669999574021);
    const uint32_t x = (uint32_t)object->handle;
    return (uint32_t)((x * c) >> 32);
}

static int security_object_equal(const void *ha, const void *hb) {
    const SecurityObject *la = ha;
    const SecurityObject *lb = hb;
    return la->handle == lb->handle;
}

static SecurityObject *security_object_find(const struct ddsrt_hh *hh, int64_t handle) {
    struct SecurityObject template;
    template.handle = handle;
    return (SecurityObject *)ddsrt_hh_lookup(hh, &template);
}

static void security_object_init(SecurityObject *obj, SecurityObjectKind_t kind,
                                 SecurityObjectDestructor destructor) {
    assert(obj);
    obj->kind = kind;
    obj->handle = (int64_t)(ddsrt_address)obj;
    obj->destructor = destructor;
}

static void security_object_deinit(SecurityObject *obj) {
    assert(obj);
    obj->handle = DDS_SECURITY_HANDLE_NIL;
    obj->kind = SECURITY_OBJECT_KIND_UNKNOWN;
    obj->destructor = NULL;
}

static void security_object_free(SecurityObject *obj) {
    assert(obj);
    if (obj && obj->destructor)
        obj->destructor(obj);
}

static void local_identity_info_free(SecurityObject *obj) {
    LocalIdentityInfo *identity = (LocalIdentityInfo *)obj;
    CHECK_OBJECT_KIND(obj, SECURITY_OBJECT_KIND_LOCAL_IDENTITY);
    if (identity) {
        if (identity->identityCert)
            X509_free(identity->identityCert);
        if (identity->identityCA)
            X509_free(identity->identityCA);

        // Free the main private key (always present)
        if (identity->privateKey)
            EVP_PKEY_free(identity->privateKey);

        if (identity->crl)
            X509_CRL_free(identity->crl);
        ddsrt_free(identity->pdata._buffer);
        ddsrt_free(identity->permissionsDocument);
        security_object_deinit((SecurityObject *)identity);
        ddsrt_free(identity);
    }
}

static LocalIdentityInfo *
local_identity_info_new(DDS_Security_DomainId domainId, X509 *identityCert, X509 *identityCa,
                        EVP_PKEY *privateKey, X509_CRL *crl,
                        const DDS_Security_GUID_t *candidate_participant_guid,
                        const DDS_Security_GUID_t *adjusted_participant_guid) {
    DBG_TRACE("Entering local_identity_info_new\n");

    LocalIdentityInfo *identity = NULL;
    assert(identityCert);
    assert(identityCa);
    assert(privateKey);
    assert(candidate_participant_guid);
    assert(adjusted_participant_guid);
    assert(sizeof(DDS_Security_IdentityHandle) == 8);

    identity = ddsrt_malloc(sizeof(*identity));
    if (!identity) {
        DBG_ERR("Failed to allocate LocalIdentityInfo\n");
        return NULL;
    }
    memset(identity, 0, sizeof(*identity));
    DBG_TRACE("Allocated LocalIdentityInfo at %p\n", (void *)identity);

    security_object_init((SecurityObject *)identity, SECURITY_OBJECT_KIND_LOCAL_IDENTITY,
                         local_identity_info_free);
    DBG_TRACE("Initialized security object for LocalIdentityInfo\n");

    identity->domainId = domainId;
    identity->identityCert = identityCert;
    identity->identityCA = identityCa;
    identity->privateKey = privateKey;
    identity->crl = crl;
    identity->permissionsDocument = NULL;

    /* Set algorithm kinds based on certificate */
    identity->dsignAlgoKind = get_authentication_algo_kind(identityCert);
    DBG_TRACE("Determined signature algorithm kind: %d\n", identity->dsignAlgoKind);

#ifdef PQ_CRYPTO
    identity->kagreeAlgoKind =
        get_default_kem_algorithm_kind(); /* Use compile-time selected algorithm */
    DBG_INFO("PQ_CRYPTO: Using %s for signatures, %s for key exchange\n",
             get_authentication_algo(identity->dsignAlgoKind),
             get_authentication_algo(identity->kagreeAlgoKind));
#else
    identity->kagreeAlgoKind = AUTH_ALGO_KIND_EC_PRIME256V1; /* Classical DH */
    DBG_INFO("Classical mode: Using EC_PRIME256V1 for key exchange\n");
#endif

    memcpy(&identity->candidateGUID, candidate_participant_guid, sizeof(DDS_Security_GUID_t));
    memcpy(&identity->adjustedGUID, adjusted_participant_guid, sizeof(DDS_Security_GUID_t));
    DBG_TRACE("Copied candidate and adjusted GUIDs\n");

    return identity;
}

static uint32_t remote_guid_hash(const void *obj) {
    const RemoteIdentityInfo *identity = obj;
    uint32_t tmp[4];
    memcpy(tmp, &identity->guid, sizeof(tmp));
    return (tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3]);
}

static int remote_guid_equal(const void *ha, const void *hb) {
    const RemoteIdentityInfo *la = ha;
    const RemoteIdentityInfo *lb = hb;
    return memcmp(&la->guid, &lb->guid, sizeof(la->guid)) == 0;
}

static RemoteIdentityInfo *find_remote_identity_by_guid(const struct ddsrt_hh *hh,
                                                        const DDS_Security_GUID_t *guid) {
    struct RemoteIdentityInfo template;
    memcpy(&template.guid, guid, sizeof(*guid));
    return (RemoteIdentityInfo *)ddsrt_hh_lookup(hh, &template);
}

static void remote_identity_info_free(SecurityObject *obj) {
    RemoteIdentityInfo *identity = (RemoteIdentityInfo *)obj;
    CHECK_OBJECT_KIND(obj, SECURITY_OBJECT_KIND_REMOTE_IDENTITY);
    if (identity) {
        if (identity->identityCert)
            X509_free(identity->identityCert);
        DDS_Security_DataHolder_free(identity->remoteIdentityToken);
        ddsrt_hh_free(identity->linkHash);
        ddsrt_free(identity->pdata._buffer);
        ddsrt_free(identity->permissionsDocument);
        security_object_deinit((SecurityObject *)identity);
        ddsrt_free(identity);
    }
}

static RemoteIdentityInfo *
remote_identity_info_new(const DDS_Security_GUID_t *guid,
                         const DDS_Security_IdentityToken *remote_identity_token) {
    assert(guid);
    assert(remote_identity_token);

    RemoteIdentityInfo *identity = ddsrt_malloc(sizeof(*identity));
    memset(identity, 0, sizeof(*identity));
    security_object_init((SecurityObject *)identity, SECURITY_OBJECT_KIND_REMOTE_IDENTITY,
                         remote_identity_info_free);
    memcpy(&identity->guid, guid, sizeof(DDS_Security_GUID_t));
    identity->remoteIdentityToken = DDS_Security_DataHolder_alloc();
    DDS_Security_DataHolder_copy(identity->remoteIdentityToken, remote_identity_token);
    identity->identityCert = NULL;
    identity->dsignAlgoKind = AUTH_ALGO_KIND_UNKNOWN;
    identity->kagreeAlgoKind = AUTH_ALGO_KIND_UNKNOWN;
    identity->permissionsDocument = ddsrt_strdup("");
    identity->linkHash = ddsrt_hh_new(32, security_object_hash, security_object_equal);
    return identity;
}

static void identity_relation_free(SecurityObject *obj) {
    IdentityRelation *relation = (IdentityRelation *)obj;
    CHECK_OBJECT_KIND(obj, SECURITY_OBJECT_KIND_IDENTITY_RELATION);
    if (relation) {
        ddsrt_free(relation->lchallenge);
        ddsrt_free(relation->rchallenge);
        security_object_deinit((SecurityObject *)relation);
        ddsrt_free(relation);
    }
}

/* The IdentityRelation provides the association between a local and a remote
 * identity. This object manages the challenges which are created for
 * each association between a local and a remote identity.
 * The lchallenge is the challenge associated with the local identity and
 * may be set when a future challenge is communicated with the
 * auth_request_message_token. The rchallenge is the challenge received from the
 * remote identity it may be set when an auth_request_message_token is received
 * from the remote identity,
 */
static IdentityRelation *identity_relation_new(LocalIdentityInfo *localIdentity,
                                               RemoteIdentityInfo *remoteIdentity,
                                               AuthenticationChallenge *lchallenge,
                                               AuthenticationChallenge *rchallenge) {
    IdentityRelation *relation;
    assert(localIdentity);
    assert(remoteIdentity);
    relation = ddsrt_malloc(sizeof(*relation));
    memset(relation, 0, sizeof(*relation));
    security_object_init((SecurityObject *)relation, SECURITY_OBJECT_KIND_IDENTITY_RELATION,
                         identity_relation_free);
    relation->_parent.handle = SECURITY_OBJECT_HANDLE(localIdentity);
    relation->localIdentity = localIdentity;
    relation->remoteIdentity = remoteIdentity;
    relation->lchallenge = lchallenge;
    relation->rchallenge = rchallenge;
    return relation;
}

static void handshake_info_free(SecurityObject *obj) {
    CHECK_OBJECT_KIND(obj, SECURITY_OBJECT_KIND_HANDSHAKE);
    HandshakeInfo *handshake = (HandshakeInfo *)obj;
    if (handshake) {
        // Always free EVP_PKEY objects (both classical and PQ use these)
#ifdef PQ_CRYPTO
        if (handshake->kem_keypair)
            EVP_PKEY_free(handshake->kem_keypair);
        if (handshake->kem_pk)
            EVP_PKEY_free(handshake->kem_pk);
        if (handshake->kem_ct) {
            ddsrt_free(handshake->kem_ct);
            handshake->kem_ct = NULL;
        }
        if (handshake->kem_ss) {
            ddsrt_free(handshake->kem_ss);
            handshake->kem_ss = NULL;
        }
#else
        if (handshake->ldh)
            EVP_PKEY_free(handshake->ldh);
        if (handshake->rdh)
            EVP_PKEY_free(handshake->rdh);
#endif
        if (handshake->shared_secret_handle_impl) {
            ddsrt_free(handshake->shared_secret_handle_impl->shared_secret);
            ddsrt_free(handshake->shared_secret_handle_impl);
        }
        security_object_deinit((SecurityObject *)handshake);
        ddsrt_free(handshake);
    }
}

static HandshakeInfo *handshake_info_new(LocalIdentityInfo *localIdentity,
                                         RemoteIdentityInfo *remoteIdentity,
                                         IdentityRelation *relation) {
    assert(localIdentity);
    assert(remoteIdentity);
    DDSRT_UNUSED_ARG(localIdentity);
    DDSRT_UNUSED_ARG(remoteIdentity);
    HandshakeInfo *handshake = ddsrt_malloc(sizeof(*handshake));
    memset(handshake, 0, sizeof(*handshake));
    security_object_init((SecurityObject *)handshake, SECURITY_OBJECT_KIND_HANDSHAKE,
                         handshake_info_free);

    handshake->relation = relation;
    handshake->shared_secret_handle_impl = NULL;
    return handshake;
}

static IdentityRelation *find_identity_relation(const RemoteIdentityInfo *remote, int64_t lid) {
    return (IdentityRelation *)security_object_find(remote->linkHash, lid);
}

static void remove_identity_relation(RemoteIdentityInfo *remote, IdentityRelation *relation) {
    (void)ddsrt_hh_remove(remote->linkHash, relation);
    security_object_free((SecurityObject *)relation);
}

static HandshakeInfo *find_handshake(const dds_security_authentication_impl *auth, int64_t localId,
                                     int64_t remoteId) {
    struct ddsrt_hh_iter it;
    SecurityObject *obj;
    for (obj = ddsrt_hh_iter_first(auth->objectHash, &it); obj; obj = ddsrt_hh_iter_next(&it)) {
        if (obj->kind == SECURITY_OBJECT_KIND_HANDSHAKE) {
            IdentityRelation *relation = ((HandshakeInfo *)obj)->relation;
            assert(relation);
            if (SECURITY_OBJECT_HANDLE(relation->localIdentity) == localId &&
                SECURITY_OBJECT_HANDLE(relation->remoteIdentity) == remoteId)
                return (HandshakeInfo *)obj;
        }
    }
    return NULL;
}

static bool str_octseq_equal(const char *str, const DDS_Security_OctetSeq *binstr) {
    size_t i;
    for (i = 0; str[i] && i < binstr->_length; i++)
        if ((unsigned char)str[i] != binstr->_buffer[i])
            return false;
    /* allow zero-termination in binstr, but disallow anything other than a
     * single \0 */
    return (str[i] == 0 &&
            (i == binstr->_length || (i + 1 == binstr->_length && binstr->_buffer[i] == 0)));
}

static void free_binary_properties(DDS_Security_BinaryProperty_t *seq, uint32_t length) {
    assert(seq);
    for (uint32_t i = 0; i < length; i++) {
        ddsrt_free(seq[i].name);
        ddsrt_free(seq[i].value._buffer);
    }
    ddsrt_free(seq);
}

static void get_hash_binary_property_seq(const DDS_Security_BinaryPropertySeq *seq,
                                         unsigned char hash[SHA256_DIGEST_LENGTH]) {
    unsigned char *buffer;
    size_t size;
    DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);
    DDS_Security_Serialize_BinaryPropertySeq(serializer, seq);
    DDS_Security_Serializer_buffer(serializer, &buffer, &size);
    SHA256(buffer, size, hash);
    ddsrt_free(buffer);
    DDS_Security_Serializer_free(serializer);
}

static DDS_Security_ValidationResult_t
create_validate_signature_impl(bool create, EVP_PKEY *pkey,
                               const DDS_Security_BinaryProperty_t **bprops,
                               const uint32_t n_bprops, unsigned char **signature,
                               size_t *signature_len, DDS_Security_SecurityException *ex) {
    DDS_Security_ValidationResult_t result;
    unsigned char *buffer;
    size_t size;
    DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);
    DDS_Security_Serialize_BinaryPropertyArray(serializer, bprops, n_bprops);
    DDS_Security_Serializer_buffer(serializer, &buffer, &size);
    result = create_validate_asymmetrical_signature(create, pkey, buffer, size, signature,
                                                    signature_len, ex);
    ddsrt_free(buffer);
    DDS_Security_Serializer_free(serializer);
    return result;
}

static DDS_Security_ValidationResult_t
create_signature(EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **bprops,
                 const uint32_t n_bprops, unsigned char **signature, size_t *signature_len,
                 DDS_Security_SecurityException *ex) {
    return create_validate_signature_impl(true, pkey, bprops, n_bprops, signature, signature_len,
                                          ex);
}

static DDS_Security_ValidationResult_t
validate_signature(EVP_PKEY *pkey, const DDS_Security_BinaryProperty_t **bprops,
                   const uint32_t n_bprops, const unsigned char *signature, size_t signature_len,
                   DDS_Security_SecurityException *ex) {
    unsigned char *s = (unsigned char *)signature;
    size_t s_len = signature_len;
    return create_validate_signature_impl(false, pkey, bprops, n_bprops, &s, &s_len, ex);
}

static DDS_Security_ValidationResult_t
compute_hash_value(HashValue_t value, const DDS_Security_BinaryProperty_t **properties,
                   const uint32_t properties_length, DDS_Security_SecurityException *ex) {
    DDSRT_UNUSED_ARG(ex);
    unsigned char *buffer;
    size_t size;
    DDS_Security_Serializer serializer = DDS_Security_Serializer_new(4096, 4096);
    DDS_Security_Serialize_BinaryPropertyArray(serializer, properties, properties_length);
    DDS_Security_Serializer_buffer(serializer, &buffer, &size);
    SHA256(buffer, size, value);
    ddsrt_free(buffer);
    DDS_Security_Serializer_free(serializer);
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_BinaryProperty_t *hash_value_to_binary_property(const char *name,
                                                                    HashValue_t hash) {
    DDS_Security_BinaryProperty_t *bp = DDS_Security_BinaryProperty_alloc();
    DDS_Security_BinaryProperty_set_by_value(bp, name, hash, sizeof(HashValue_t));
    return bp;
}

static SecurityObject *get_identity_info(dds_security_authentication_impl *auth,
                                         DDS_Security_IdentityHandle handle) {
    SecurityObject *obj;

    ddsrt_mutex_lock(&auth->lock);
    if ((obj = security_object_find(auth->objectHash, handle)) != NULL) {
        if ((obj->kind != SECURITY_OBJECT_KIND_LOCAL_IDENTITY) &&
            (obj->kind != SECURITY_OBJECT_KIND_REMOTE_IDENTITY))
            obj = NULL;
    }
    ddsrt_mutex_unlock(&auth->lock);
    return obj;
}

static void validity_callback(dds_security_time_event_handle_t timer, dds_time_t trigger_time,
                              dds_security_timed_cb_kind_t kind, void *arg) {
    DDSRT_UNUSED_ARG(timer);
    DDSRT_UNUSED_ARG(trigger_time);

    assert(arg);
    validity_cb_info *info = arg;
    if (kind == DDS_SECURITY_TIMED_CB_KIND_TIMEOUT) {
        assert(info->auth->listener);
        SecurityObject *obj = get_identity_info(info->auth, info->hdl);
        if (obj) {
            const dds_security_authentication_listener *auth_listener =
                (dds_security_authentication_listener *)info->auth->listener;
            if (auth_listener->on_revoke_identity)
                auth_listener->on_revoke_identity((dds_security_authentication *)info->auth,
                                                  info->hdl);
            if (obj->kind == SECURITY_OBJECT_KIND_LOCAL_IDENTITY)
                ((LocalIdentityInfo *)obj)->timer = 0;
            else
                ((RemoteIdentityInfo *)obj)->timer = 0;
        }
    }
    ddsrt_free(arg);
}

static dds_security_time_event_handle_t
add_validity_end_trigger(dds_security_authentication_impl *auth,
                         const DDS_Security_IdentityHandle identity_handle, dds_time_t end) {
    validity_cb_info *arg = ddsrt_malloc(sizeof(validity_cb_info));
    arg->auth = auth;
    arg->hdl = identity_handle;
    return dds_security_timed_dispatcher_add(auth->dispatcher, validity_callback, end, (void *)arg);
}

static DDS_Security_ValidationResult_t
get_adjusted_participant_guid(X509 *cert, const DDS_Security_GUID_t *candidate,
                              DDS_Security_GUID_t *adjusted, DDS_Security_SecurityException *ex) {
    unsigned char high[SHA256_DIGEST_LENGTH], low[SHA256_DIGEST_LENGTH];
    unsigned char *subject = NULL;
    size_t size = 0;

    assert(cert);
    assert(candidate);
    assert(adjusted);

    if (get_subject_name_DER_encoded(cert, &subject, &size, ex) != DDS_SECURITY_VALIDATION_OK)
        return DDS_SECURITY_VALIDATION_FAILED;

    DDS_Security_octet hb = ADJUSTED_GUID_PREFIX_FLAG;
    SHA256(subject, size, high);
    SHA256(&candidate->prefix[0], sizeof(DDS_Security_GuidPrefix_t), low);
    adjusted->entityId = candidate->entityId;
    for (int i = 0; i < 6; i++) {
        adjusted->prefix[i] = hb | high[i] >> 1;
        hb = (DDS_Security_octet)(high[i] << 7);
    }
    for (int i = 0; i < 6; i++)
        adjusted->prefix[i + 6] = low[i];
    ddsrt_free(subject);
    return DDS_SECURITY_VALIDATION_OK;
}
#undef ADJUSTED_GUID_PREFIX_FLAG

DDS_Security_ValidationResult_t validate_local_identity(
    dds_security_authentication *instance, DDS_Security_IdentityHandle *local_identity_handle,
    DDS_Security_GUID_t *adjusted_participant_guid, const DDS_Security_DomainId domain_id,
    const DDS_Security_Qos *participant_qos, const DDS_Security_GUID_t *candidate_participant_guid,
    DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_local_identity\n");

    if (!instance || !local_identity_handle || !adjusted_participant_guid || !participant_qos ||
        !candidate_participant_guid) {
        DBG_ERR("Invalid parameter provided to validate_local_identity\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "validate_local_identity: Invalid parameter provided");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    dds_security_authentication_impl *implementation = (dds_security_authentication_impl *)instance;
    LocalIdentityInfo *identity;
    char *identityCertPEM, *identityCaPEM, *privateKeyPEM, *password, *trusted_ca_dir, *crlPEM;
    X509 *identityCert, *identityCA;
    X509_CRL *crl = NULL;
    EVP_PKEY *privateKey;
    dds_time_t certExpiry = DDS_TIME_INVALID;

#ifdef PQ_CRYPTO
    /* PQ crypto specific variables */
    OSSL_LIB_CTX *oqs_ctx = get_oqs_context(implementation);
#else
    OSSL_LIB_CTX *oqs_ctx = NULL;
#endif

    /* Load standard identity certificate properties */
    if (!(identityCertPEM = DDS_Security_Property_get_value(&participant_qos->property.value,
                                                            DDS_SEC_PROP_AUTH_IDENTITY_CERT))) {
        DBG_ERR("Missing property '%s' in validate_local_identity\n",
                DDS_SEC_PROP_AUTH_IDENTITY_CERT);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "validate_local_identity: missing property '%s'",
                                   DDS_SEC_PROP_AUTH_IDENTITY_CERT);
        goto err_no_identity_cert;
    }

    if (!(identityCaPEM = DDS_Security_Property_get_value(&participant_qos->property.value,
                                                          DDS_SEC_PROP_AUTH_IDENTITY_CA))) {
        DBG_ERR("Missing property '%s' in validate_local_identity\n",
                DDS_SEC_PROP_AUTH_IDENTITY_CA);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "validate_local_identity: missing property '%s'",
                                   DDS_SEC_PROP_AUTH_IDENTITY_CA);
        goto err_no_identity_ca;
    }

    if (!(privateKeyPEM = DDS_Security_Property_get_value(&participant_qos->property.value,
                                                          DDS_SEC_PROP_AUTH_PRIV_KEY))) {
        DBG_ERR("Missing property '%s' in validate_local_identity\n", DDS_SEC_PROP_AUTH_PRIV_KEY);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "validate_local_identity: missing property '%s'",
                                   DDS_SEC_PROP_AUTH_PRIV_KEY);
        goto err_no_private_key;
    }

    password = DDS_Security_Property_get_value(&participant_qos->property.value,
                                               DDS_SEC_PROP_AUTH_PASSWORD);

    trusted_ca_dir = DDS_Security_Property_get_value(&participant_qos->property.value,
                                                     DDS_SEC_PROP_ACCESS_TRUSTED_CA_DIR);
    if (trusted_ca_dir && strlen(trusted_ca_dir) > 0) {
        if (get_trusted_ca_list(trusted_ca_dir, &(implementation->trustedCAList), oqs_ctx, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Failed to load trusted CA list from directory '%s'\n", trusted_ca_dir);
            goto err_inv_trusted_ca_dir;
        }
        DBG_TRACE("Loaded trusted CA list from directory '%s'\n", trusted_ca_dir);
    }

    crlPEM = DDS_Security_Property_get_value(&participant_qos->property.value,
                                             ORG_ECLIPSE_CYCLONEDDS_SEC_AUTH_CRL);

    DBG_TRACE("Loading identity CA certificate\n");
    if (load_X509_certificate(identityCaPEM, &identityCA, oqs_ctx, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to load identity CA certificate in "
                "validate_local_identity\n");
        goto err_inv_identity_ca;
    }
    DBG_TRACE("Loaded identity CA certificate\n");

    /* check for CA if listed in trusted CA files */
    if (implementation->trustedCAList.length > 0) {
        if (crlPEM) {
            DBG_ERR("Cannot specify both CRL and trusted_ca_list\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Cannot specify both CRL and trusted_ca_list");
            goto err_identity_ca_not_trusted;
        }
        const EVP_MD *digest = EVP_get_digestbyname("sha1");
        uint32_t size;
        unsigned char hash_buffer[20], hash_buffer_trusted[20];
        DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_FAILED;

        X509_digest(identityCA, digest, hash_buffer, &size);
        for (unsigned i = 0; i < implementation->trustedCAList.length; ++i) {
            X509_digest(implementation->trustedCAList.buffer[i], digest, hash_buffer_trusted,
                        &size);
            if (memcmp(hash_buffer_trusted, hash_buffer, 20) == 0) {
                result = DDS_SECURITY_VALIDATION_OK;
                break;
            }
        }
        if (result != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Identity CA is not trusted\n");
            DDS_Security_Exception_set(
                ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_CA_NOT_TRUSTED_CODE,
                DDS_SECURITY_VALIDATION_FAILED, DDS_SECURITY_ERR_CA_NOT_TRUSTED_MESSAGE);
            goto err_identity_ca_not_trusted;
        }
        DBG_TRACE("Identity CA is trusted\n");
    }

    DBG_TRACE("Loading identity certificate\n");
    if (load_X509_certificate(identityCertPEM, &identityCert, oqs_ctx, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to load identity certificate in validate_local_identity\n");
        goto err_inv_identity_cert;
    }
    DBG_TRACE("Loaded identity certificate\n");

    DBG_TRACE("Loading private key\n");
    if (load_X509_private_key(privateKeyPEM, password, &privateKey, oqs_ctx, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to load private key in validate_local_identity\n");
        goto err_inv_private_key;
    }
    DBG_TRACE("Loaded private key\n");

    if (crlPEM && strlen(crlPEM) > 0) {
        DBG_TRACE("Loading CRL\n");
        if (load_X509_CRL(crlPEM, &crl, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Failed to load CRL in validate_local_identity\n");
            goto err_inv_crl;
        }
        DBG_TRACE("Loaded CRL\n");
    }

    DBG_TRACE("Verifying certificate\n");
    if (verify_certificate(identityCert, identityCA, crl, oqs_ctx, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Certificate verification failed in validate_local_identity\n");
        goto err_verification_failed;
    }
    DBG_TRACE("Certificate verified\n");

    if ((certExpiry = get_certificate_expiry(identityCert)) == DDS_TIME_INVALID) {
        DBG_ERR("Certificate expiry date is invalid\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Expiry date of the certificate is invalid");
        goto err_verification_failed;
    }
    DBG_TRACE("Certificate expiry: %ld\n", certExpiry);

    DBG_TRACE("Obtaining adjusted participant GUID\n");
    if (get_adjusted_participant_guid(identityCert, candidate_participant_guid,
                                      adjusted_participant_guid,
                                      ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to get adjusted participant GUID\n");
        goto err_adj_guid_failed;
    }
    DBG_TRACE("Adjusted participant GUID obtained\n");

    /* Clean up string allocations */
    ddsrt_free(crlPEM);
    ddsrt_free(password);
    ddsrt_free(privateKeyPEM);
    ddsrt_free(identityCaPEM);
    ddsrt_free(identityCertPEM);
    ddsrt_free(trusted_ca_dir);

    /* Create identity with traditional certificates only */
    identity = local_identity_info_new(domain_id, identityCert, identityCA, privateKey, crl,
                                       candidate_participant_guid, adjusted_participant_guid);

    *local_identity_handle = IDENTITY_HANDLE(identity);
    DBG_TRACE("Assigned local_identity_handle = 0x%lx\n", (unsigned long)*local_identity_handle);

    if (certExpiry != DDS_NEVER)
        identity->timer =
            add_validity_end_trigger(implementation, *local_identity_handle, certExpiry);

    ddsrt_mutex_lock(&implementation->lock);
    DBG_TRACE("Registering local identity object in hash table\n");
    (void)ddsrt_hh_add(implementation->objectHash, identity);
    ddsrt_mutex_unlock(&implementation->lock);

    return DDS_SECURITY_VALIDATION_OK;

err_adj_guid_failed:
    DBG_ERR("Error obtaining adjusted participant GUID\n");
err_verification_failed:
    if (crl) {
        X509_CRL_free(crl);
        DBG_TRACE("Freed CRL after verification failure\n");
    }
err_inv_crl:
    EVP_PKEY_free(privateKey);
    DBG_TRACE("Freed private key after CRL failure\n");
err_inv_private_key:
    X509_free(identityCert);
    DBG_TRACE("Freed identity certificate after private key failure\n");
err_inv_identity_cert:
err_identity_ca_not_trusted:
    X509_free(identityCA);
    DBG_TRACE("Freed identity CA after trust failure\n");
err_inv_identity_ca:
    ddsrt_free(crlPEM);
err_inv_trusted_ca_dir:
    ddsrt_free(password);
    ddsrt_free(privateKeyPEM);
    ddsrt_free(trusted_ca_dir);
err_no_private_key:
    ddsrt_free(identityCaPEM);
err_no_identity_ca:
    ddsrt_free(identityCertPEM);
err_no_identity_cert:
    return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_boolean get_identity_token(dds_security_authentication *instance,
                                        DDS_Security_IdentityToken *identity_token,
                                        const DDS_Security_IdentityHandle handle,
                                        DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering get_identity_token (handle=0x%lx)\n", (unsigned long)handle);

    if (!instance || !identity_token) {
        DBG_ERR("Invalid parameter provided to get_identity_token\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "get_identity_token: Invalid parameter provided");
        return false;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    SecurityObject *obj;
    LocalIdentityInfo *identity;
    char *snCert, *snCA;
    memset(identity_token, 0, sizeof(*identity_token));

    ddsrt_mutex_lock(&impl->lock);

    obj = security_object_find(impl->objectHash, handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_LOCAL_IDENTITY)) {
        DBG_ERR("Invalid handle provided to get_identity_token\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "get_identity_token: Invalid handle provided");
        goto err_inv_handle;
    }
    identity = (LocalIdentityInfo *)obj;

    if (!(snCert = get_certificate_subject_name(identity->identityCert, ex))) {
        DBG_ERR("Failed to get subject name from identity certificate\n");
        goto err_sn_cert;
    }
    if (!(snCA = get_certificate_subject_name(identity->identityCA, ex))) {
        DBG_ERR("Failed to get subject name from CA certificate\n");
        goto err_sn_ca;
    }

    identity_token->class_id = ddsrt_strdup(DDS_SECURITY_AUTH_TOKEN_CLASS_ID);
    identity_token->properties._length = 4;
    identity_token->properties._buffer = DDS_Security_PropertySeq_allocbuf(4);

    identity_token->properties._buffer[0].name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_CERT_SN);
    identity_token->properties._buffer[0].value = snCert;

    identity_token->properties._buffer[1].name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_CERT_ALGO);
    identity_token->properties._buffer[1].value =
        ddsrt_strdup(get_authentication_algo(get_authentication_algo_kind(identity->identityCert)));

    identity_token->properties._buffer[2].name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_CA_SN);
    identity_token->properties._buffer[2].value = snCA;

    identity_token->properties._buffer[3].name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_CA_ALGO);
    identity_token->properties._buffer[3].value =
        ddsrt_strdup(get_authentication_algo(get_authentication_algo_kind(identity->identityCA)));

    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Successfully populated identity_token\n");
    return true;

err_sn_ca:
    ddsrt_free(snCert);
err_sn_cert:
err_inv_handle:
    ddsrt_mutex_unlock(&impl->lock);
    return false;
}

DDS_Security_boolean get_identity_status_token(
    dds_security_authentication *instance, DDS_Security_IdentityStatusToken *identity_status_token,
    const DDS_Security_IdentityHandle handle, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering get_identity_status_token (handle=0x%lx)\n", (unsigned long)handle);
    DDSRT_UNUSED_ARG(identity_status_token);
    DDSRT_UNUSED_ARG(handle);
    DDSRT_UNUSED_ARG(ex);
    DDSRT_UNUSED_ARG(instance);
    return true;
}

DDS_Security_boolean set_permissions_credential_and_token(
    dds_security_authentication *instance, const DDS_Security_IdentityHandle handle,
    const DDS_Security_PermissionsCredentialToken *permissions_credential,
    const DDS_Security_PermissionsToken *permissions_token, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering set_permissions_credential_and_token (handle=0x%lx)\n",
              (unsigned long)handle);

    if (!instance || handle == DDS_SECURITY_HANDLE_NIL || !permissions_credential ||
        !permissions_token) {
        DBG_ERR("Invalid parameter provided to "
                "set_permissions_credential_and_token\n");
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "set_permissions_credential_and_token: Invalid parameter provided");
        return false;
    }

    if (!permissions_credential->class_id ||
        strcmp(permissions_credential->class_id, DDS_ACTOKEN_PERMISSIONS_CREDENTIAL_CLASS_ID) !=
            0) {
        DBG_ERR("Invalid permissions_credential class_id\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "set_permissions_credential_and_token: "
                                   "Invalid credential class_id");
        return false;
    }

    if (permissions_credential->properties._length == 0 ||
        permissions_credential->properties._buffer[0].name == NULL ||
        strcmp(permissions_credential->properties._buffer[0].name, DDS_ACTOKEN_PROP_PERM_CERT) !=
            0) {
        DBG_ERR("Invalid permissions_credential properties\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "set_permissions_credential_and_token: "
                                   "Invalid credential properties");
        return false;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    LocalIdentityInfo *identity;

    ddsrt_mutex_lock(&impl->lock);
    identity = (LocalIdentityInfo *)security_object_find(impl->objectHash, handle);
    if (!identity ||
        !SECURITY_OBJECT_VALID((SecurityObject *)identity, SECURITY_OBJECT_KIND_LOCAL_IDENTITY)) {
        DBG_ERR("Invalid handle provided to "
                "set_permissions_credential_and_token\n");
        ddsrt_mutex_unlock(&impl->lock);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "set_permissions_credential_and_token: Invalid handle provided");
        return false;
    }

    identity->permissionsDocument =
        ddsrt_strdup(permissions_credential->properties._buffer[0].value
                         ? permissions_credential->properties._buffer[0].value
                         : "");
    DBG_TRACE("Stored permissionsDocument for identity (handle=0x%lx)\n", (unsigned long)handle);

    ddsrt_mutex_unlock(&impl->lock);
    return true;
}

static DDS_Security_ValidationResult_t
validate_remote_identity_token(const LocalIdentityInfo *localIdent,
                               const DDS_Security_IdentityToken *token,
                               DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_remote_identity_token\n");
    DDSRT_UNUSED_ARG(localIdent);

    if (!token->class_id) {
        DBG_ERR("remote identity token: class_id is empty\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "remote identity token: class_id is empty");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    const size_t class_id_base_len = strlen(DDS_SECURITY_AUTH_TOKEN_CLASS_ID_BASE);
    if (strncmp(DDS_SECURITY_AUTH_TOKEN_CLASS_ID_BASE, token->class_id, class_id_base_len) != 0) {
        DBG_ERR("remote identity token: class_id='%s' not supported\n", token->class_id);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "remote identity token: class_id='%s' not supported",
                                   token->class_id);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    const char *received_version_str = token->class_id + class_id_base_len;
    unsigned major = 0, minor = 0;
    int postfix_pos = 0;
    DDSRT_WARNING_MSVC_OFF(4996);
    if (sscanf(received_version_str, "%u.%u%n", &major, &minor, &postfix_pos) != 2 ||
        (received_version_str[postfix_pos] != 0 && received_version_str[postfix_pos] != '+')) {
        DBG_ERR("remote identity token: class_id has wrong format '%s'\n", token->class_id);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "remote identity token: class_id has wrong format");
        DDSRT_WARNING_MSVC_ON(4996);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DDSRT_WARNING_MSVC_ON(4996);

    if (major != DDS_SECURITY_AUTH_VERSION_MAJOR || minor > DDS_SECURITY_AUTH_VERSION_MINOR) {
        DBG_ERR("remote identity token: version %u.%u not supported\n", major, minor);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "remote identity token: version %u.%u not supported", major,
                                   minor);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    DBG_TRACE("validate_remote_identity_token succeeded (version %u.%u)\n", major, minor);
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t
validate_auth_request_token(const DDS_Security_IdentityToken *token,
                            AuthenticationChallenge **challenge,
                            DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_auth_request_token\n");
    uint32_t index;
    int found = 0;
    assert(token);

    if (!token->class_id) {
        DBG_ERR("AuthRequestMessageToken invalid: missing class_id\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "AuthRequestMessageToken invalid: missing class_id");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (strncmp(token->class_id, DDS_SECURITY_AUTH_REQUEST_TOKEN_CLASS_ID,
                strlen(DDS_SECURITY_AUTH_REQUEST_TOKEN_CLASS_ID)) != 0) {
        DBG_ERR("AuthRequestMessageToken invalid: class_id '%s' is invalid\n", token->class_id);
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "AuthRequestMessageToken invalid: class_id '%s' is invalid",
                                   token->class_id);
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (!token->binary_properties._buffer) {
        DBG_ERR("AuthRequestMessageToken invalid: properties are missing\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "AuthRequestMessageToken invalid: properties are missing");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    for (index = 0; index < token->binary_properties._length; index++) {
        size_t len = strlen(DDS_AUTHTOKEN_PROP_FUTURE_CHALLENGE);
        if (token->binary_properties._buffer[index].name &&
            strncmp(token->binary_properties._buffer[index].name,
                    DDS_AUTHTOKEN_PROP_FUTURE_CHALLENGE, len) == 0) {
            DBG_TRACE("Found future_challenge at index %u\n", index);
            found = 1;
            break;
        }
    }

    if (!found) {
        DBG_ERR("AuthRequestMessageToken invalid: future_challenge not found\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "AuthRequestMessageToken invalid: future_challenge not found");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (token->binary_properties._buffer[index].value._length != sizeof(AuthenticationChallenge) ||
        !token->binary_properties._buffer[index].value._buffer) {
        DBG_ERR("AuthRequestMessageToken invalid: future_challenge invalid size\n");
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "AuthRequestMessageToken invalid: future_challenge invalid size");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    if (challenge) {
        *challenge = ddsrt_malloc(sizeof(AuthenticationChallenge));
        if (!*challenge) {
            DBG_ERR("Failed to allocate memory for AuthenticationChallenge\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "AuthRequestMessageToken invalid: memory allocation failed");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        memcpy(*challenge, &token->binary_properties._buffer[index].value._buffer[0],
               sizeof(AuthenticationChallenge));
        DBG_TRACE("Copied future_challenge into challenge structure\n");
    }

    DBG_TRACE("validate_auth_request_token succeeded\n");
    return DDS_SECURITY_VALIDATION_OK;
}

static void fill_auth_request_token(DDS_Security_AuthRequestMessageToken *token,
                                    AuthenticationChallenge *challenge) {
    DBG_TRACE("Entering fill_auth_request_token\n");
    uint32_t len = sizeof(challenge->value);

    DDS_Security_DataHolder_deinit(token);
    token->class_id = ddsrt_strdup(DDS_SECURITY_AUTH_REQUEST_TOKEN_CLASS_ID);
    DBG_TRACE("Set token class_id to '%s'\n", DDS_SECURITY_AUTH_REQUEST_TOKEN_CLASS_ID);

    token->binary_properties._length = 1;
    token->binary_properties._buffer = DDS_Security_BinaryPropertySeq_allocbuf(1);
    DBG_TRACE("Allocated binary_properties buffer for 1 property\n");

    token->binary_properties._buffer->name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_FUTURE_CHALLENGE);
    DBG_TRACE("Property name set to '%s'\n", DDS_AUTHTOKEN_PROP_FUTURE_CHALLENGE);

    token->binary_properties._buffer->value._length = len;
    token->binary_properties._buffer->value._buffer = ddsrt_malloc(len);
    memcpy(token->binary_properties._buffer->value._buffer, challenge->value, len);
    token->binary_properties._buffer->propagate = true;
    DBG_TRACE("Copied challenge value into token (length=%u)\n", len);

    DBG_TRACE("fill_auth_request_token completed\n");
}

DDS_Security_ValidationResult_t validate_remote_identity(
    dds_security_authentication *instance, DDS_Security_IdentityHandle *remote_identity_handle,
    DDS_Security_AuthRequestMessageToken *local_auth_request_token,
    const DDS_Security_AuthRequestMessageToken *remote_auth_request_token,
    const DDS_Security_IdentityHandle local_identity_handle,
    const DDS_Security_IdentityToken *remote_identity_token,
    const DDS_Security_GUID_t *remote_participant_guid, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_remote_identity (local_handle=0x%lx)\n",
              (unsigned long)local_identity_handle);

    if (!instance || !remote_identity_handle || !local_auth_request_token ||
        !remote_identity_token || !remote_participant_guid) {
        DBG_ERR("Invalid parameter provided to validate_remote_identity\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "validate_remote_identity: Invalid parameter provided");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    SecurityObject *obj;
    LocalIdentityInfo *localIdent;
    RemoteIdentityInfo *remoteIdent;
    IdentityRelation *relation;
    AuthenticationChallenge *lchallenge = NULL, *rchallenge = NULL;

    ddsrt_mutex_lock(&impl->lock);
    DBG_TRACE("Acquired lock for validate_remote_identity\n");

    obj = security_object_find(impl->objectHash, local_identity_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_LOCAL_IDENTITY)) {
        DBG_ERR("Invalid local_identity_handle in validate_remote_identity\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "validate_remote_identity: Invalid handle provided");
        goto err_inv_handle;
    }
    localIdent = (LocalIdentityInfo *)obj;
    DBG_TRACE("Found local identity (handle=0x%lx)\n", (unsigned long)local_identity_handle);

    if (validate_remote_identity_token(localIdent, remote_identity_token, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Remote identity token validation failed\n");
        goto err_remote_identity_token;
    }
    DBG_TRACE("Remote identity token validated successfully\n");

    /* When the remote_auth_request_token is not null, check if its contents are
     * valid */
    if (remote_auth_request_token) {
        DBG_TRACE("Validating remote auth request token\n");
        if (validate_auth_request_token(remote_auth_request_token, &rchallenge, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Auth request token validation failed\n");
            goto err_inv_auth_req_token;
        }
        DBG_TRACE("Remote auth request token validated, extracted rchallenge\n");
    }

    if ((lchallenge = generate_challenge(ex)) == NULL) {
        DBG_ERR("Failed to allocate local challenge\n");
        goto err_alloc_challenge;
    }
    DBG_TRACE("Generated local challenge\n");

    /* Check if the remote identity has already been validated by a previous
     * validation request. */
    remoteIdent = find_remote_identity_by_guid(impl->remoteGuidHash, remote_participant_guid);
    if (!remoteIdent) {
        DBG_TRACE("Remote identity not found, creating new RemoteIdentityInfo\n");
        remoteIdent = remote_identity_info_new(remote_participant_guid, remote_identity_token);
        (void)ddsrt_hh_add(impl->objectHash, remoteIdent);
        (void)ddsrt_hh_add(impl->remoteGuidHash, remoteIdent);
        DBG_TRACE("Added new RemoteIdentityInfo to objectHash and remoteGuidHash\n");

        relation = identity_relation_new(localIdent, remoteIdent, lchallenge, rchallenge);
        (void)ddsrt_hh_add(remoteIdent->linkHash, relation);
        DBG_TRACE("Created new IdentityRelation and added to "
                  "remoteIdent->linkHash\n");
    } else {
        DBG_TRACE("Found existing RemoteIdentityInfo (GUID match)\n");
        /* Check if the token matches the existing one */
        if (!DDS_Security_DataHolder_equal(remoteIdent->remoteIdentityToken,
                                           remote_identity_token)) {
            DBG_ERR("Remote identity token does not match previously received "
                    "one\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "validate_remote_identity: remote_identity_token does not "
                                       "match with previously received one");
            goto err_inv_duplicate;
        }
        DBG_TRACE("Remote identity token matches previously stored token\n");

        relation = find_identity_relation(remoteIdent, SECURITY_OBJECT_HANDLE(localIdent));
        if (!relation) {
            DBG_TRACE("No existing relation, creating new identity relation\n");
            relation = identity_relation_new(localIdent, remoteIdent, lchallenge, rchallenge);
            int r = ddsrt_hh_add(remoteIdent->linkHash, relation);
            assert(r);
            (void)r;
            DBG_TRACE("Added new IdentityRelation to remoteIdent->linkHash\n");
        } else {
            DBG_TRACE("Found existing relation between local and remote identity\n");
            if (remote_auth_request_token) {
                assert(rchallenge);
                ddsrt_free(relation->rchallenge);
                relation->rchallenge = rchallenge;
                DBG_TRACE("Replaced rchallenge in existing relation\n");
            }
            ddsrt_free(lchallenge);
            DBG_TRACE("Freed newly generated local challenge\n");
        }
    }

    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked impl->lock after validate_remote_identity\n");

    if (!remote_auth_request_token) {
        fill_auth_request_token(local_auth_request_token, relation->lchallenge);
        DBG_TRACE("Filled local auth request token for handshake\n");
    } else {
        DDS_Security_set_token_nil(local_auth_request_token);
        DBG_TRACE("Set local_auth_request_token to NIL\n");
    }

    *remote_identity_handle = IDENTITY_HANDLE(remoteIdent);
    DBG_TRACE("Assigned remote_identity_handle = 0x%lx\n", (unsigned long)*remote_identity_handle);

    /* Add debug logging for GUID comparison */
    DBG_TRACE("Comparing GUIDs for handshake direction\n");
    DBG_TRACE("Local adjusted GUID: ");
    for (int i = 0; i < 16; i++) {
        DBG_TRACE("%02x", ((uint8_t *)&localIdent->adjustedGUID)[i]);
    }
    DBG_TRACE("\nRemote GUID: ");
    for (int i = 0; i < 16; i++) {
        DBG_TRACE("%02x", ((uint8_t *)&remoteIdent->guid)[i]);
    }
    DBG_TRACE("\n");

    int guid_comparison =
        memcmp(&localIdent->adjustedGUID, &remoteIdent->guid, sizeof(DDS_Security_GUID_t));
    DBG_TRACE("GUID comparison result: %d (<0 means REQUEST, >=0 means REPLY)\n", guid_comparison);

    DDS_Security_ValidationResult_t result =
        guid_comparison < 0 ? DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_REQUEST
                            : DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_MESSAGE;

    DBG_TRACE("Returning result: %s\n",
              (result == DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_REQUEST)
                  ? "PENDING_HANDSHAKE_REQUEST"
                  : "PENDING_HANDSHAKE_MESSAGE");

    return result;

err_inv_duplicate:
    ddsrt_free(lchallenge);
    DBG_TRACE("Freed lchallenge after duplicate token error\n");
err_alloc_challenge:
    ddsrt_free(rchallenge);
    DBG_TRACE("Freed rchallenge after allocation error\n");
err_inv_auth_req_token:
err_remote_identity_token:
err_inv_handle:
    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked impl->lock in error path\n");
    return DDS_SECURITY_VALIDATION_FAILED;
}

#ifdef PQ_CRYPTO
/* Helper function to generate ML-KEM keys specifically */
static DDS_Security_ValidationResult_t generate_pq_kem_keys(EVP_PKEY **kemkey,
                                                            AuthenticationAlgoKind_t kagreeAlgoKind,
                                                            DDS_Security_SecurityException *ex,
                                                            OSSL_LIB_CTX *libctx) {
    DBG_CRYPTO("Entering generate_pq_kem_keys (kind: %d)\n", kagreeAlgoKind);
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *key = NULL;
    *kemkey = NULL;

    // Get the OpenSSL algorithm name from the algorithm kind
    const char *kemalg_name = get_kem_openssl_name_by_kind(kagreeAlgoKind);
    if (!kemalg_name) {
        // Fallback to default algorithm
        kemalg_name = get_default_kem_openssl_name();
        if (!kemalg_name) {
            DBG_ERR("No OpenSSL name found for KEM algorithm kind: %d\n", kagreeAlgoKind);
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Unsupported KEM algorithm kind");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_WARN("Using default KEM algorithm %s instead of kind %d\n", kemalg_name,
                 kagreeAlgoKind);
    }

    DBG_INFO("Using KEM algorithm: %s (kind: %d)\n", kemalg_name, kagreeAlgoKind);

    if (!OSSL_PROVIDER_available(libctx, "default")) {
        DBG_ERR("Default provider is not available\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Default provider is not available.");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Default provider available\n");

    if ((kctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name, NULL)) == NULL) {
        DBG_ERR("Failed to allocate KEM generation context for %s\n", kemalg_name);
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to allocate KEM generation context: ");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Allocated KEM generation context for '%s'\n", kemalg_name);

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        DBG_ERR("Failed to initialize KEM generation context\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to initialize KEM generation context: ");
        EVP_PKEY_CTX_free(kctx);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Initialized KEM generation context\n");

    if (EVP_PKEY_generate(kctx, &key) <= 0) {
        DBG_ERR("Failed to generate KEM key pair for %s\n", kemalg_name);
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED, "Failed to generate KEM key pair: ");
        EVP_PKEY_CTX_free(kctx);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("%s key generated successfully\n", kemalg_name);

    *kemkey = key;
    EVP_PKEY_CTX_free(kctx);
    DBG_CRYPTO("Exiting generate_pq_kem_keys with success\n");
    return DDS_SECURITY_VALIDATION_OK;
}
#endif /* PQ_CRYPTO */

DDS_Security_ValidationResult_t
begin_handshake_request(dds_security_authentication *instance,
                        DDS_Security_HandshakeHandle *handshake_handle,
                        DDS_Security_HandshakeMessageToken *handshake_message,
                        const DDS_Security_IdentityHandle initiator_identity_handle,
                        const DDS_Security_IdentityHandle replier_identity_handle,
                        const DDS_Security_OctetSeq *serialized_local_participant_data,
                        DDS_Security_SecurityException *ex) {
    DBG_HANDSHAKE("begin_handshake_request called (initiator=0x%lx, replier=0x%lx)\n",
                  (unsigned long)initiator_identity_handle, (unsigned long)replier_identity_handle);

    if (!instance || !handshake_handle || !handshake_message ||
        !serialized_local_participant_data) {
        DBG_ERR("Invalid parameter provided to begin_handshake_request\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_request: Invalid parameter provided");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
#ifdef PQ_CRYPTO
    OSSL_LIB_CTX *oqs_ctx = get_oqs_context(impl);
#endif
    if (HASH_OPTIONAL) {
        impl->include_optional = 1;
    }
    HandshakeInfo *handshake = NULL;
    IdentityRelation *relation = NULL;
    SecurityObject *obj;
    LocalIdentityInfo *localIdent;
    RemoteIdentityInfo *remoteIdent;
    /* DH/PQ */
    EVP_PKEY *dhkey;
    unsigned char *certData, *dhPubKeyData = NULL;
    uint32_t certDataSize, dhPubKeyDataSize;
#ifdef PQ_CRYPTO
    int provider = 0;
#endif                                                  /* PQ_CRYPTO */
    uint32_t tokcount = impl->include_optional ? 8 : 7; // DH and PQ KEM send same number of values
    int created = 0;

    ddsrt_mutex_lock(&impl->lock);

    obj = security_object_find(impl->objectHash, initiator_identity_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_LOCAL_IDENTITY)) {
        DBG_ERR("Invalid initiator_identity_handle provided\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_request: Invalid "
                                   "initiator_identity_handle provided");
        goto err_inv_handle;
    }
    localIdent = (LocalIdentityInfo *)obj;

    obj = security_object_find(impl->objectHash, replier_identity_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_REMOTE_IDENTITY)) {
        DBG_ERR("Invalid replier_identity_handle provided\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_request: Invalid "
                                   "replier_identity_handle provided");
        goto err_inv_handle;
    }
    remoteIdent = (RemoteIdentityInfo *)obj;

    if (get_certificate_contents(localIdent->identityCert, &certData, &certDataSize, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to get certificate contents for local identity\n");
        goto err_alloc_cid;
    }

    if (!(handshake = find_handshake(impl, SECURITY_OBJECT_HANDLE(localIdent),
                                     SECURITY_OBJECT_HANDLE(remoteIdent)))) {
        relation = find_identity_relation(remoteIdent, SECURITY_OBJECT_HANDLE(localIdent));
        assert(relation);
        handshake = handshake_info_new(localIdent, remoteIdent, relation);
        handshake->created_in = CREATEDREQUEST;

        (void)ddsrt_hh_add(impl->objectHash, handshake);
        DBG_HANDSHAKE("Created and added handshake to hash table - handle: "
                      "0x%lx (REQUEST)\n",
                      (unsigned long)HANDSHAKE_HANDLE(handshake));
        created = 1;
    } else {
        relation = handshake->relation;
        assert(relation);
        DBG_TRACE("Reusing existing handshake (handle: 0x%lx)\n",
                  (unsigned long)HANDSHAKE_HANDLE(handshake));
    }

#ifdef MEASURE_HANDSHAKE_TIME
    if (handshake->created_in == CREATEDREQUEST) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        shm_write(start);
    }
#endif /* MEASURE_HANDSHAKE_TIME */

#ifdef PQ_CRYPTO /* PQ key generation using OpenSSL+OQS provider */
    /* We always generate fresh ephemeral KEM keys */

    if (handshake->kem_keypair) {
        EVP_PKEY_free(handshake->kem_keypair);
        handshake->kem_keypair = NULL;
        DBG_CRYPTO("Freed existing KEM keypair to generate fresh one\n");
    }

    DBG_CRYPTO("PQ - Generating fresh ephemeral %s key pair\n",
               get_authentication_algo(localIdent->kagreeAlgoKind));
    if (generate_pq_kem_keys(&handshake->kem_keypair, localIdent->kagreeAlgoKind, ex, oqs_ctx) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to generate PQ KEM keys\n");
        goto err_gen_dh_keys;
    }

    DBG_CRYPTO("Generated fresh ML-KEM key, checking properties...\n");
    const char *key_type = EVP_PKEY_get0_type_name(handshake->kem_keypair);
    DBG_CRYPTO("Key type: %s\n", key_type ? key_type : "NULL");

    /* Extract public key using the KEM keypair */
    if (pq_public_key_to_oct(handshake->kem_keypair, localIdent->kagreeAlgoKind, &dhPubKeyData,
                             &dhPubKeyDataSize, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to extract PQ public key\n");
        goto err_get_public_key;
    }

    DBG_CRYPTO("Extracted public key data, size: %u bytes\n", dhPubKeyDataSize);
    size_t expected_pk_size = get_kem_public_key_size(localIdent->kagreeAlgoKind);
    DBG_CRYPTO("Extracted public key data, size: %u bytes\n", dhPubKeyDataSize);
    DBG_CRYPTO("Expected %s public key size: %zu bytes\n",
               get_authentication_algo(localIdent->kagreeAlgoKind), expected_pk_size);

    if (dhPubKeyDataSize != expected_pk_size) {
        DBG_ERR("Public key size mismatch! Got %u, expected %zu for %s\n", dhPubKeyDataSize,
                expected_pk_size, get_authentication_algo(localIdent->kagreeAlgoKind));
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "Generated %s public key has incorrect size: %u (expected %zu)",
                                   get_authentication_algo(localIdent->kagreeAlgoKind),
                                   dhPubKeyDataSize, expected_pk_size);
        goto err_get_public_key;
    }

    DBG_CRYPTO("✓ Public key size validation passed for %s\n",
               get_authentication_algo(localIdent->kagreeAlgoKind));
#else  /* Classical DH key generation */
    if (!handshake->ldh) {
        if (generate_dh_keys(&dhkey, localIdent->kagreeAlgoKind, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Failed to generate DH keypair\n");
            goto err_gen_dh_keys;
        }
        handshake->ldh = dhkey;
        DBG_CRYPTO("Generated classical DH keypair\n");
    }
    if (dh_public_key_to_oct(handshake->ldh, localIdent->kagreeAlgoKind, &dhPubKeyData,
                             &dhPubKeyDataSize, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to extract DH public key\n");
        goto err_get_public_key;
    }
    DBG_CRYPTO("Extracted DH public key data, size: %u bytes\n", dhPubKeyDataSize);
#endif /* PQ_CRYPTO */

    if (localIdent->pdata._length == 0) {
        DDS_Security_OctetSeq_copy(&localIdent->pdata, serialized_local_participant_data);
        DBG_TRACE("Copied serialized local participant data\n");
    }

    DDS_Security_BinaryProperty_t *tokens = DDS_Security_BinaryPropertySeq_allocbuf(tokcount);
    uint32_t tokidx = 0;

    DDS_Security_BinaryProperty_set_by_ref(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_ID, certData,
                                           certDataSize);
    DDS_Security_BinaryProperty_set_by_string(
        &tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_PERM,
        localIdent->permissionsDocument ? localIdent->permissionsDocument : "");
    DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_PDATA,
                                             serialized_local_participant_data->_buffer,
                                             serialized_local_participant_data->_length);
    DDS_Security_BinaryProperty_set_by_string(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_DSIGN_ALGO,
                                              get_dsign_algo(localIdent->dsignAlgoKind));
    DDS_Security_BinaryProperty_set_by_string(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_KAGREE_ALGO,
                                              get_kagree_algo(localIdent->kagreeAlgoKind));

    /* Todo: including hash_c1 is optional (conform spec); add a configuration
     * option to leave it out */
    {
        DDS_Security_BinaryPropertySeq bseq = {._length = 5, ._buffer = tokens};
        get_hash_binary_property_seq(&bseq, handshake->hash_c1);
        if (impl->include_optional) {
            DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_HASH_C1,
                                                     handshake->hash_c1, sizeof(HashValue_t));
            DBG_TRACE("Included optional HASH_C1 property\n");
        }
    }

#ifndef PQ_CRYPTO
    /* Set the DH public key associated with the local participant in dh1
     * property */
    assert(dhPubKeyData);
    assert(dhPubKeyDataSize < 1200); // TODO: check this size for classical DH
    DDS_Security_BinaryProperty_set_by_ref(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_DH1, dhPubKeyData,
                                           dhPubKeyDataSize);
    DBG_TRACE("Set DH1 property with %u bytes of data\n", dhPubKeyDataSize);
#else
    /* Set the KEM public key in KEM_PUBLIC property for PQ */
    assert(dhPubKeyData);
    assert(dhPubKeyDataSize > 0); // PQ public keys are typically larger
    DDS_Security_BinaryProperty_set_by_ref(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_KEM_PUBLIC,
                                           dhPubKeyData, dhPubKeyDataSize);
    DBG_TRACE("Set KEM_PUBLIC property with %u bytes of data\n", dhPubKeyDataSize);
#endif

    /* Set the challenge in challenge1 property */
    DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_CHALLENGE1,
                                             relation->lchallenge->value,
                                             sizeof(AuthenticationChallenge));
    DBG_TRACE("Set CHALLENGE1 property\n");

    (void)ddsrt_hh_add(impl->objectHash, handshake);
    DBG_TRACE("Re-added handshake to hash table after populating tokens\n");

    ddsrt_mutex_unlock(&impl->lock);

    assert(tokcount == tokidx);

    handshake_message->class_id = ddsrt_strdup(DDS_SECURITY_AUTH_HANDSHAKE_REQUEST_TOKEN_ID);
    handshake_message->properties._length = 0;
    handshake_message->properties._buffer = NULL;
    handshake_message->binary_properties._length = tokidx;
    handshake_message->binary_properties._buffer = tokens;
    *handshake_handle = HANDSHAKE_HANDLE(handshake);

    DBG_HANDSHAKE("Leaving begin_handshake_request with handle: 0x%lx\n",
                  (unsigned long)*handshake_handle);

    return DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_MESSAGE;

err_get_public_key:
    DBG_ERR("Error extracting public key in begin_handshake_request\n");
err_gen_dh_keys:
    if (created) {
        (void)ddsrt_hh_remove(impl->objectHash, handshake);
        security_object_free((SecurityObject *)handshake);
        DBG_TRACE("Cleaned up handshake after key generation failure\n");
    }
#ifdef PQ_CRYPTO
err_gen_kem_keys:
    if (created) {
        (void)ddsrt_hh_remove(impl->objectHash, handshake);
        security_object_free((SecurityObject *)handshake);
        DBG_TRACE("Cleaned up handshake after KEM key generation failure\n");
    }
#endif
err_alloc_cid:
    ddsrt_free(certData);
    DBG_TRACE("Freed certificate data buffer\n");
err_inv_handle:
    ddsrt_mutex_unlock(&impl->lock);
    return DDS_SECURITY_VALIDATION_FAILED;
}

static DDS_Security_ValidationResult_t validate_pdata(const DDS_Security_OctetSeq *seq, X509 *cert,
                                                      DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_pdata (length=%u)\n", seq->_length);

    DDS_Security_ParticipantBuiltinTopicData *pdata;
    DDS_Security_GUID_t cguid, aguid;
    DDS_Security_Deserializer deserializer =
        DDS_Security_Deserializer_new(seq->_buffer, seq->_length);
    if (!deserializer) {
        DBG_ERR("Failed to create deserializer for pdata\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_reply: c.pdata invalid encoding");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Created deserializer for pdata\n");

    pdata = DDS_Security_ParticipantBuiltinTopicData_alloc();
    if (!pdata) {
        DBG_ERR("Failed to allocate ParticipantBuiltinTopicData\n");
        DDS_Security_Deserializer_free(deserializer);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Allocated ParticipantBuiltinTopicData\n");

    if (!DDS_Security_Deserialize_ParticipantBuiltinTopicData(deserializer, pdata, ex)) {
        DBG_ERR("Failed to deserialize ParticipantBuiltinTopicData\n");
        DDS_Security_ParticipantBuiltinTopicData_free(pdata);
        DDS_Security_Deserializer_free(deserializer);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Deserialized ParticipantBuiltinTopicData successfully\n");

    memset(&cguid, 0, sizeof(DDS_Security_GUID_t));
    if (get_adjusted_participant_guid(cert, &cguid, &aguid, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to get adjusted participant GUID from certificate\n");
        DDS_Security_ParticipantBuiltinTopicData_free(pdata);
        DDS_Security_Deserializer_free(deserializer);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Obtained adjusted GUID from certificate\n");

    DDS_Security_BuiltinTopicKey_t key;
    DDS_Security_BuiltinTopicKeyBE(key, pdata->key);
    if (memcmp(key, aguid.prefix, 6) != 0) {
        DBG_ERR("ParticipantBuiltinTopicData key does not match adjusted GUID\n");
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "begin_handshake_reply: c.pdata contains incorrect participant guid");
        DDS_Security_ParticipantBuiltinTopicData_free(pdata);
        DDS_Security_Deserializer_free(deserializer);
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("ParticipantBuiltinTopicData key matches adjusted GUID\n");

    DDS_Security_ParticipantBuiltinTopicData_free(pdata);
    DDS_Security_Deserializer_free(deserializer);
    DBG_TRACE("validate_pdata succeeded\n");
    return DDS_SECURITY_VALIDATION_OK;
}

enum handshake_token_type { HS_TOKEN_REQ, HS_TOKEN_REPLY, HS_TOKEN_FINAL };

static DDS_Security_ValidationResult_t set_exception(DDS_Security_SecurityException *ex,
                                                     const char *fmt, ...) {
    DBG_TRACE("Entering set_exception\n");
    va_list ap;
    va_start(ap, fmt);
    DDS_Security_Exception_vset(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                DDS_SECURITY_VALIDATION_FAILED, fmt, ap);
    va_end(ap);
    DBG_ERR("set_exception: %s\n", fmt);
    return DDS_SECURITY_VALIDATION_FAILED;
}

static const DDS_Security_BinaryProperty_t *
find_required_binprop(const DDS_Security_HandshakeMessageToken *token, const char *name,
                      DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering find_required_binprop (name='%s')\n", name);
    const DDS_Security_BinaryProperty_t *prop =
        DDS_Security_DataHolder_find_binary_property(token, name);
    if (prop == NULL) {
        DBG_ERR("Property '%s' missing in handshake token\n", name);
        set_exception(ex, "process_handshake: HandshakeMessageToken property %s missing", name);
        return NULL;
    }
    if (prop->value._length > INT_MAX) {
        DBG_ERR("Property '%s' has unsupported size (%" PRIu32 " bytes)\n", name,
                prop->value._length);
        set_exception(
            ex,
            "process_handshake: HandshakeMessageToken property %s has unsupported size (%" PRIu32
            " bytes)",
            name, prop->value._length);
        return NULL;
    }
    DBG_TRACE("Found property '%s' (length=%" PRIu32 ")\n", name, prop->value._length);
    return prop;
}

static const DDS_Security_BinaryProperty_t *
find_required_nonempty_binprop(const DDS_Security_HandshakeMessageToken *token, const char *name,
                               DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering find_required_nonempty_binprop (name='%s')\n", name);
    const DDS_Security_BinaryProperty_t *prop = find_required_binprop(token, name, ex);
    if (!prop) {
        return NULL;
    }
#ifndef PQ_CRYPTO
    if (prop->value._length == 0 || prop->value._buffer == NULL)
#else
    if (prop->value._length == 0 || prop->value._buffer == NULL)
#endif
    {
        DBG_ERR("Property '%s' is empty\n", name);
        set_exception(ex, "process_handshake: HandshakeMessageToken property %s is empty", name);
        return NULL;
    }
    DBG_TRACE("Property '%s' is non-empty (length=%" PRIu32 ")\n", name, prop->value._length);
    return prop;
}

static const DDS_Security_BinaryProperty_t *
find_required_binprop_exactsize(const DDS_Security_HandshakeMessageToken *token, const char *name,
                                size_t size, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering find_required_binprop_exactsize (name='%s', expected_size=%zu)\n", name,
              size);
    const DDS_Security_BinaryProperty_t *prop = find_required_binprop(token, name, ex);
    if (prop && prop->value._length != size) {
        DBG_ERR("Property '%s' wrong size (got %" PRIu32 ", expected %zu)\n", name,
                prop->value._length, size);
        set_exception(
            ex,
            "process_handshake: HandshakeMessageToken property %s has wrong size (%" PRIu32
            " while expecting %" PRIuSIZE ")",
            name, prop->value._length, size);
        return NULL;
    }
    if (prop) {
        DBG_TRACE("Property '%s' has expected size (%zu)\n", name, size);
    }
    return prop;
}

static X509 *load_X509_certificate_from_binprop(const DDS_Security_BinaryProperty_t *prop,
                                                X509 *own_ca, X509_CRL *own_crl,
                                                const X509Seq *trusted_ca_list,
                                                OSSL_LIB_CTX *oqs_libctx,
                                                DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering load_X509_certificate_from_binprop (name='%s', length=%" PRIu32 ")\n",
              prop->name, prop->value._length);

    if (own_crl && trusted_ca_list->length > 0) {
        DBG_ERR("Cannot specify both CRL and trusted_ca_list\n");
        set_exception(
            ex, "load_X509_certificate_from_binprop: Cannot specify both CRL and trusted_ca_list");
        return NULL;
    }

    X509 *cert = NULL;
    DBG_TRACE("Calling load_X509_certificate_from_data\n");
    if (load_X509_certificate_from_data((char *)prop->value._buffer, (int)prop->value._length,
                                        &cert, oqs_libctx, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("load_X509_certificate_from_data failed\n");
        return NULL;
    }
    DBG_TRACE("Loaded X509 certificate from binary data\n");

    DDS_Security_ValidationResult_t result = DDS_SECURITY_VALIDATION_FAILED;
    if (trusted_ca_list->length == 0) {
        DBG_TRACE("Verifying certificate against own CA/CRL\n");
        result = verify_certificate(cert, own_ca, own_crl, oqs_libctx, ex);
    } else {
        DBG_TRACE("Verifying certificate against trusted CA list (length=%u)\n",
                  trusted_ca_list->length);
        DDS_Security_Exception_clean(ex);
        for (unsigned i = 0; i < trusted_ca_list->length; ++i) {
            DBG_TRACE("Attempting verification with trusted CA index %u\n", i);
            DDS_Security_Exception_reset(ex);
            if ((result = verify_certificate(cert, trusted_ca_list->buffer[i], NULL, oqs_libctx,
                                             ex)) == DDS_SECURITY_VALIDATION_OK) {
                DBG_TRACE("Verification succeeded with trusted CA index %u\n", i);
                break;
            }
            DBG_TRACE("Verification failed with trusted CA index %u\n", i);
        }
    }

    if (result != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Certificate verification failed\n");
        X509_free(cert);
        return NULL;
    }
    DBG_TRACE("Certificate verified successfully\n");

    if (check_certificate_expiry(cert, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Certificate expiry check failed\n");
        X509_free(cert);
        return NULL;
    }
    DBG_TRACE("Certificate expiry is valid\n");

    return cert;
}

static DDS_Security_BinaryProperty_t *create_dhkey_property(const char *name, EVP_PKEY *pkey,
                                                            AuthenticationAlgoKind_t kagreeAlgoKind,
                                                            DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering create_dhkey_property (name='%s', kagreeAlgoKind=%d)\n", name,
              kagreeAlgoKind);

    unsigned char *data = NULL;
    uint32_t len = 0;
    DDS_Security_ValidationResult_t rv =
        dh_public_key_to_oct(pkey, kagreeAlgoKind, &data, &len, ex);
    if (rv != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("dh_public_key_to_oct failed for algo %d\n", kagreeAlgoKind);
        return NULL;
    }
    DBG_TRACE("Obtained DH public key octets (length=%" PRIu32 ")\n", len);

    DDS_Security_BinaryProperty_t *prop = DDS_Security_BinaryProperty_alloc();
    if (!prop) {
        DBG_ERR("Failed to allocate DDS_Security_BinaryProperty_t\n");
        ddsrt_free(data);
        return NULL;
    }
    DDS_Security_BinaryProperty_set_by_ref(prop, name, data, len);
    DBG_TRACE("Created binary property '%s' with data length=%" PRIu32 "\n", name, len);

    return prop;
}

static DDS_Security_ValidationResult_t validate_handshake_token_impl(
    const DDS_Security_HandshakeMessageToken *token, enum handshake_token_type token_type,
    HandshakeInfo *handshake, X509Seq *trusted_ca_list,
    const DDS_Security_BinaryProperty_t *dh1_ref, const DDS_Security_BinaryProperty_t *dh2_ref,
    dds_security_authentication_impl *auth_impl, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_handshake_token_impl (token_type=%d)\n", token_type);
    IdentityRelation *const relation = handshake->relation;
    X509 *identityCert = NULL;
    const DDS_Security_BinaryProperty_t *c_pdata = NULL;
    AuthenticationAlgoKind_t dsignAlgoKind = AUTH_ALGO_KIND_UNKNOWN,
                             kagreeAlgoKind = AUTH_ALGO_KIND_UNKNOWN;
    const DDS_Security_BinaryProperty_t *dh1 = NULL, *dh2 = NULL;
    const DDS_Security_BinaryProperty_t *hash_c1 = NULL, *hash_c2 = NULL;
    const DDS_Security_BinaryProperty_t *challenge1 = NULL, *challenge2 = NULL;
    const DDS_Security_BinaryProperty_t *signature = NULL;
#ifdef PQ_CRYPTO
    const DDS_Security_BinaryProperty_t *signature_kem = NULL;
    const DDS_Security_BinaryProperty_t *kem_ciphertext = NULL;
    const DDS_Security_BinaryProperty_t *kem_public = NULL;
    OSSL_LIB_CTX *oqs_ctx = get_oqs_context(auth_impl);
    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)auth_impl;

    if (!oqs_ctx) {
        DBG_WARN("No OQS context available in validate_handshake_token_impl\n");
        // Individual crypto operations will handle missing context
    }
#else
    OSSL_LIB_CTX *oqs_ctx = NULL;
#endif

    const char *token_class_id = NULL;
    DBG_INFO("validate_handshake_token_impl() called\n");

    assert(relation);

    /* Validate token type */
    switch (token_type) {
    case HS_TOKEN_REQ:
        token_class_id = DDS_SECURITY_AUTH_HANDSHAKE_REQUEST_TOKEN_ID;
        DBG_TRACE("Token type: REQUEST\n");
        break;
    case HS_TOKEN_REPLY:
        token_class_id = DDS_SECURITY_AUTH_HANDSHAKE_REPLY_TOKEN_ID;
        DBG_TRACE("Token type: REPLY\n");
        break;
    case HS_TOKEN_FINAL:
        token_class_id = DDS_SECURITY_AUTH_HANDSHAKE_FINAL_TOKEN_ID;
        DBG_TRACE("Token type: FINAL\n");
        break;
    default:
        DBG_ERR("Invalid handshake token type: %d\n", token_type);
        return set_exception(ex, "Invalid handshake token type");
    }

#ifndef PQ_CRYPTO
    /* Classical crypto parameter validation */
    assert(dh1_ref != NULL || token_type == HS_TOKEN_REQ);
    assert(dh2_ref != NULL || token_type == HS_TOKEN_REQ || token_type == HS_TOKEN_REPLY);
    DBG_TRACE("Classical crypto parameter assertions passed\n");
#endif

    /* Validate class ID */
    if (!token->class_id || strncmp(token_class_id, token->class_id, strlen(token_class_id)) != 0) {
        DBG_ERR("Incorrect class_id: '%s' (expected '%s')\n",
                token->class_id ? token->class_id : "NULL", token_class_id);
        return set_exception(
            ex, "process_handshake: HandshakeMessageToken incorrect class_id: %s (expected %s)",
            token->class_id ? token->class_id : "NULL", token_class_id);
    }
    DBG_TRACE("Token class_id '%s' validated\n", token->class_id);

    /* Process REQUEST and REPLY tokens (certificate validation) */
    if (token_type == HS_TOKEN_REQ || token_type == HS_TOKEN_REPLY) {
        const DDS_Security_BinaryProperty_t *c_id, *c_perm, *c_dsign_algo, *c_kagree_algo;

        /* Validate certificate and participant data */
        if ((c_id = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_C_ID, ex)) == NULL) {
            DBG_ERR("Missing or empty C_ID property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found C_ID property (length=%" PRIu32 ")\n", c_id->value._length);

        if ((identityCert = load_X509_certificate_from_binprop(
                 c_id, relation->localIdentity->identityCA, relation->localIdentity->crl,
                 trusted_ca_list, oqs_ctx, ex)) == NULL) {
            DBG_ERR("Failed to load identity certificate from C_ID\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Loaded identityCert from C_ID\n");

        /* Update remote identity certificate */
        if (relation->remoteIdentity->identityCert) {
            X509_free(relation->remoteIdentity->identityCert);
            DBG_TRACE("Freed old remote identity certificate\n");
        }
        relation->remoteIdentity->identityCert = identityCert;
        DBG_TRACE("Set new remote identity certificate\n");

        if ((c_perm = find_required_binprop(token, DDS_AUTHTOKEN_PROP_C_PERM, ex)) == NULL) {
            DBG_ERR("Missing C_PERM property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found C_PERM property (length=%" PRIu32 ")\n", c_perm->value._length);
        if (c_perm->value._length > 0) {
            ddsrt_free(relation->remoteIdentity->permissionsDocument);
            relation->remoteIdentity->permissionsDocument =
                string_from_data(c_perm->value._buffer, c_perm->value._length);
            DBG_TRACE("Set remote permissionsDocument\n");
        }

        if ((c_pdata = find_required_binprop(token, DDS_AUTHTOKEN_PROP_C_PDATA, ex)) == NULL) {
            DBG_ERR("Missing C_PDATA property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found C_PDATA property (length=%" PRIu32 ")\n", c_pdata->value._length);

        if (validate_pdata(&c_pdata->value, identityCert, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("validate_pdata failed\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("validate_pdata succeeded\n");

        if ((c_dsign_algo = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_C_DSIGN_ALGO,
                                                           ex)) == NULL) {
            DBG_ERR("Missing C_DSIGN_ALGO property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found C_DSIGN_ALGO property (length=%" PRIu32 ")\n",
                  c_dsign_algo->value._length);

        if ((dsignAlgoKind = get_dsign_algo_from_octseq(&c_dsign_algo->value)) ==
            AUTH_ALGO_KIND_UNKNOWN) {
            DBG_ERR("Unsupported C_DSIGN_ALGO value\n");
            return set_exception(
                ex, "process_handshake: HandshakeMessageToken property %s not supported",
                DDS_AUTHTOKEN_PROP_C_DSIGN_ALGO);
        }
        DBG_TRACE("Determined dsignAlgoKind = %d\n", dsignAlgoKind);

        if ((c_kagree_algo = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_C_KAGREE_ALGO,
                                                            ex)) == NULL) {
            DBG_ERR("Missing C_KAGREE_ALGO property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found C_KAGREE_ALGO property (length=%" PRIu32 ")\n",
                  c_kagree_algo->value._length);

        if ((kagreeAlgoKind = get_kagree_algo_from_octseq(&c_kagree_algo->value)) ==
            AUTH_ALGO_KIND_UNKNOWN) {
            DBG_ERR("Unsupported C_KAGREE_ALGO value\n");
            return set_exception(
                ex, "process_handshake: HandshakeMessageToken property %s not supported",
                DDS_AUTHTOKEN_PROP_C_KAGREE_ALGO);
        }
        DBG_TRACE("Determined kagreeAlgoKind = %d\n", kagreeAlgoKind);

        /* Calculate hash value */
        {
            const DDS_Security_BinaryProperty_t *binary_properties[] = {
                c_id, c_perm, c_pdata, c_dsign_algo, c_kagree_algo};
            (void)compute_hash_value((token_type == HS_TOKEN_REQ) ? handshake->hash_c1
                                                                  : handshake->hash_c2,
                                     binary_properties, 5, NULL);
            DBG_TRACE("Computed hash_%s\n", (token_type == HS_TOKEN_REQ) ? "c1" : "c2");
        }
    }

    /* Process key exchange material for REQUEST tokens */
    if (token_type == HS_TOKEN_REQ) {
#ifdef PQ_CRYPTO
        /* PQ: Extract and validate KEM public key */
        EVP_PKEY *pdhkey_req = NULL;
        if ((dh1 = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_KEM_PUBLIC, ex)) ==
            NULL) {
            DBG_ERR("Missing KEM_PUBLIC property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Received KEM_PUBLIC property (length=%" PRIu32 ")\n", dh1->value._length);

        /* Dynamic KEM public key validation */
        if (validate_kem_public_key_in_token(dh1, kagreeAlgoKind, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("KEM public key validation failed\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("KEM public key size validated for algorithm %s (%zu bytes)\n",
                  get_authentication_algo(kagreeAlgoKind), get_kem_public_key_size(kagreeAlgoKind));

        if (pq_oct_to_public_key(&pdhkey_req, dh1->value._buffer, dh1->value._length,
                                 kagreeAlgoKind, oqs_ctx, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("pq_oct_to_public_key failed\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Converted KEM public key to EVP_PKEY\n");

        if (handshake->kem_pk) {
            EVP_PKEY_free(handshake->kem_pk);
            DBG_TRACE("Freed existing handshake->kem_pk\n");
        }
        handshake->kem_pk = pdhkey_req;
        DBG_TRACE("Set handshake->kem_pk to new key\n");
#else
        /* Classical: Extract and validate DH public key */
        EVP_PKEY *pdhkey_req = NULL;
        if ((dh1 = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_DH1, ex)) == NULL) {
            DBG_ERR("Missing DH1 property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Received DH1 property (length=%" PRIu32 ")\n", dh1->value._length);

        if (dh_oct_to_public_key(&pdhkey_req, kagreeAlgoKind, dh1->value._buffer,
                                 dh1->value._length, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("dh_oct_to_public_key failed\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Converted DH1 octets to EVP_PKEY rdh\n");

        if (handshake->rdh) {
            EVP_PKEY_free(handshake->rdh);
            DBG_TRACE("Freed existing handshake->rdh\n");
        }
        handshake->rdh = pdhkey_req;
        DBG_TRACE("Set handshake->rdh to new key\n");
#endif
    } else {
        /* For REPLY and FINAL tokens, validate key material consistency */
#ifdef PQ_CRYPTO
        /* PQ: Extract and validate KEM public key for REPLY/FINAL tokens */
        if ((dh1 = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_KEM_PUBLIC, ex)) ==
            NULL) {
            DBG_ERR("Missing KEM_PUBLIC property in %s token\n",
                    token_type == HS_TOKEN_REPLY ? "REPLY" : "FINAL");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found KEM_PUBLIC property in %s token (length=%" PRIu32 ")\n",
                  token_type == HS_TOKEN_REPLY ? "REPLY" : "FINAL", dh1->value._length);

        /* Validate the KEM public key size and format */
        AuthenticationAlgoKind_t validation_algo = kagreeAlgoKind;
        if (token_type == HS_TOKEN_FINAL && validation_algo == AUTH_ALGO_KIND_UNKNOWN) {
            validation_algo = relation->remoteIdentity->kagreeAlgoKind;
        }

        if (validate_kem_public_key_in_token(dh1, validation_algo, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("KEM public key validation failed for %s token\n",
                    token_type == HS_TOKEN_REPLY ? "REPLY" : "FINAL");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("KEM public key validated for %s token\n",
                  token_type == HS_TOKEN_REPLY ? "REPLY" : "FINAL");
#else
        /* For classical crypto, verify against reference */
        dh1 = DDS_Security_DataHolder_find_binary_property(token, DDS_AUTHTOKEN_PROP_DH1);
        if (dh1 && dh1_ref && !DDS_Security_BinaryProperty_equal(dh1_ref, dh1)) {
            DBG_ERR("DH1 in token does not match reference\n");
            return set_exception(ex, "process_handshake: %s token property %s not correct",
                                 (token_type == HS_TOKEN_REPLY) ? "Reply" : "Final",
                                 DDS_AUTHTOKEN_PROP_DH1);
        }
        dh1 = dh1_ref;
        DBG_TRACE("DH1 reference validated\n");
#endif
    }

    /* Validate challenges (required for all token types) */
    if ((challenge1 = find_required_binprop_exactsize(
             token, DDS_AUTHTOKEN_PROP_CHALLENGE1, sizeof(AuthenticationChallenge), ex)) == NULL) {
        DBG_ERR("Missing or invalid CHALLENGE1 property\n");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    DBG_TRACE("Found CHALLENGE1 property (exact size)\n");

    /* Process REPLY and FINAL tokens (signature validation) */
    if (token_type == HS_TOKEN_REPLY || token_type == HS_TOKEN_FINAL) {
        if ((challenge2 = find_required_binprop_exactsize(token, DDS_AUTHTOKEN_PROP_CHALLENGE2,
                                                          sizeof(AuthenticationChallenge), ex)) ==
            NULL) {
            DBG_ERR("Missing or invalid CHALLENGE2 property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found CHALLENGE2 property (exact size)\n");

#ifdef PQ_CRYPTO
        /* PQ: Extract KEM ciphertext and signatures */
        DBG_TRACE("Extracting KEM_CIPHERTEXT and KEM_SIGNATURE\n");
        if ((kem_ciphertext = find_required_nonempty_binprop(
                 token, DDS_AUTHTOKEN_PROP_KEM_CIPHERTEXT, ex)) == NULL) {
            DBG_ERR("Missing KEM_CIPHERTEXT property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found KEM_CIPHERTEXT property (length=%" PRIu32 ")\n",
                  kem_ciphertext->value._length);

        /* Dynamic KEM ciphertext validation using stored algorithm kind */
        AuthenticationAlgoKind_t validation_algo_kind = kagreeAlgoKind;

        /* For FINAL tokens, use the stored algorithm from the relation */
        if (token_type == HS_TOKEN_FINAL && validation_algo_kind == AUTH_ALGO_KIND_UNKNOWN) {
            validation_algo_kind = relation->remoteIdentity->kagreeAlgoKind;
            DBG_TRACE("Using stored algorithm kind %d for FINAL token validation\n",
                      validation_algo_kind);
        }

        if (validate_kem_ciphertext_in_token(kem_ciphertext, validation_algo_kind, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("KEM ciphertext validation failed\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("KEM ciphertext size validated for algorithm %s (%zu bytes)\n",
                  get_authentication_algo(validation_algo_kind),
                  get_kem_ciphertext_size(validation_algo_kind));
#endif

        if ((signature = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_SIGNATURE, ex)) ==
            NULL) {
            DBG_ERR("Missing SIGNATURE property\n");
            return DDS_SECURITY_VALIDATION_FAILED;
        }
        DBG_TRACE("Found SIGNATURE property (length=%" PRIu32 ")\n", signature->value._length);

        /* Handle REPLY-specific key exchange */
        if (token_type == HS_TOKEN_REPLY) {
#ifndef PQ_CRYPTO
            /* Classical: Extract DH2 public key */
            EVP_PKEY *pdhkey_reply = NULL;
            DBG_TRACE("Processing DH2 for REPLY token\n");
            if ((dh2 = find_required_nonempty_binprop(token, DDS_AUTHTOKEN_PROP_DH2, ex)) == NULL) {
                DBG_ERR("Missing DH2 property in REPLY token\n");
                return DDS_SECURITY_VALIDATION_FAILED;
            }
            DBG_TRACE("Found DH2 property (length=%" PRIu32 ")\n", dh2->value._length);

            if (dh_oct_to_public_key(&pdhkey_reply, kagreeAlgoKind, dh2->value._buffer,
                                     dh2->value._length, ex) != DDS_SECURITY_VALIDATION_OK) {
                DBG_ERR("dh_oct_to_public_key failed for DH2\n");
                return DDS_SECURITY_VALIDATION_FAILED;
            }
            DBG_TRACE("Converted DH2 octets to EVP_PKEY rdh\n");

            if (handshake->rdh) {
                EVP_PKEY_free(handshake->rdh);
                DBG_TRACE("Freed existing handshake->rdh\n");
            }
            handshake->rdh = pdhkey_reply;
            DBG_TRACE("Set handshake->rdh to new key from REPLY\n");
#endif
            /* PQ: Key exchange already handled via encapsulation/decapsulation */
        } else { /* HS_TOKEN_FINAL */
#ifndef PQ_CRYPTO
            /* Classical: Validate DH2 consistency */
            DBG_TRACE("Validating DH2 in FINAL token\n");
            dh2 = DDS_Security_DataHolder_find_binary_property(token, DDS_AUTHTOKEN_PROP_DH2);
            if (dh2 && dh2_ref && !DDS_Security_BinaryProperty_equal(dh2_ref, dh2)) {
                DBG_ERR("DH2 in FINAL token does not match reference\n");
                return set_exception(ex, "process_handshake: Final token property %s not correct",
                                     DDS_AUTHTOKEN_PROP_DH2);
            }
            dh2 = dh2_ref;
            DBG_TRACE("DH2 reference validated for FINAL token\n");
#endif
            /* PQ: Consistency already validated above */
        }
    }

    /* Validate challenge consistency with stored challenges */
    {
        const DDS_Security_BinaryProperty_t *rc =
            (token_type == HS_TOKEN_REPLY) ? challenge2 : challenge1;
        if (relation->rchallenge) {
            if (memcmp(relation->rchallenge->value, rc->value._buffer,
                       sizeof(AuthenticationChallenge)) != 0) {
                DBG_ERR("Challenge mismatch: token challenge vs future_challenge\n");
                return set_exception(
                    ex,
                    "process_handshake: HandshakeMessageToken property challenge%d "
                    "does not match future_challenge",
                    (token_type == HS_TOKEN_REPLY) ? 2 : 1);
            }
            DBG_TRACE("Challenge matches stored rchallenge\n");
        } else if (token_type != HS_TOKEN_FINAL) {
            relation->rchallenge = ddsrt_memdup(rc->value._buffer, sizeof(AuthenticationChallenge));
            DBG_TRACE("Stored new rchallenge from token\n");
        }
    }

    /* Validate optional hash properties */
    if ((hash_c1 =
             DDS_Security_DataHolder_find_binary_property(token, DDS_AUTHTOKEN_PROP_HASH_C1))) {
        assert(handshake->hash_c1 != NULL);
        if (hash_c1->value._length != sizeof(HashValue_t) ||
            memcmp(hash_c1->value._buffer, handshake->hash_c1, sizeof(HashValue_t)) != 0) {
            DBG_ERR("HASH_C1 invalid\n");
            return set_exception(ex, "process_handshake: HandshakeMessageToken property %s invalid",
                                 DDS_AUTHTOKEN_PROP_HASH_C1);
        }
        DBG_TRACE("Optional HASH_C1 validated\n");
    }

    if (token_type == HS_TOKEN_REPLY || token_type == HS_TOKEN_FINAL) {
        assert(handshake->hash_c2 != NULL);

        if ((hash_c2 =
                 DDS_Security_DataHolder_find_binary_property(token, DDS_AUTHTOKEN_PROP_HASH_C2))) {
            if (hash_c2->value._length != sizeof(HashValue_t) ||
                memcmp(hash_c2->value._buffer, handshake->hash_c2, sizeof(HashValue_t)) != 0) {
                DBG_ERR("HASH_C2 invalid\n");
                return set_exception(
                    ex, "process_handshake: HandshakeMessageToken property hash_c2 invalid");
            }
            DBG_TRACE("Optional HASH_C2 validated\n");
        }

        if (relation->lchallenge == NULL) {
            DBG_ERR("Missing future_challenge for this token\n");
            return set_exception(ex,
                                 "process_handshake: No future challenge exists for this token");
        }

        const DDS_Security_BinaryProperty_t *lc =
            (token_type == HS_TOKEN_REPLY) ? challenge1 : challenge2;
        if (memcmp(relation->lchallenge->value, lc->value._buffer,
                   sizeof(AuthenticationChallenge)) != 0) {
            DBG_ERR("challenge1 in token does not match future_challenge\n");
            return set_exception(ex, "process_handshake: HandshakeMessageToken property challenge1 "
                                     "does not match future_challenge");
        }
        DBG_TRACE("challenge1 validated\n");
    }

    /* Update remote identity information for REQUEST and REPLY tokens */
    if (token_type == HS_TOKEN_REQ || token_type == HS_TOKEN_REPLY) {
        assert(dsignAlgoKind != AUTH_ALGO_KIND_UNKNOWN);
        assert(kagreeAlgoKind != AUTH_ALGO_KIND_UNKNOWN);
        assert(c_pdata != NULL);

        relation->remoteIdentity->dsignAlgoKind = dsignAlgoKind;
        relation->remoteIdentity->kagreeAlgoKind = kagreeAlgoKind;
        DDS_Security_OctetSeq_copy(&relation->remoteIdentity->pdata, &c_pdata->value);
        DBG_TRACE("Updated remote identity dsignAlgoKind=%d, kagreeAlgoKind=%d\n", dsignAlgoKind,
                  kagreeAlgoKind);
    }

    /* Validate signatures for REPLY and FINAL tokens */
    if (token_type == HS_TOKEN_REPLY || token_type == HS_TOKEN_FINAL) {
#ifdef PQ_CRYPTO
        DBG_CRYPTO("Validating PQ signature for %s token\n",
                   token_type == HS_TOKEN_REPLY ? "REPLY" : "FINAL");

        EVP_PKEY *public_key = X509_get_pubkey(relation->remoteIdentity->identityCert);
        if (!public_key) {
            DBG_ERR("X509_get_pubkey failed\n");
            return set_exception(ex, "X509_get_pubkey failed");
        }
        DBG_TRACE("Obtained public key from remote identity certificate\n");

        const char *type_name = EVP_PKEY_get0_type_name(public_key);
        DBG_TRACE("Certificate key type: %s, can_sign=%d\n", type_name ? type_name : "NULL",
                  EVP_PKEY_can_sign(public_key));
        if (!EVP_PKEY_can_sign(public_key)) {
            DBG_ERR("Certificate key cannot sign\n");
            EVP_PKEY_free(public_key);
            return set_exception(
                ex,
                "Certificate contains non-signing key - need ML-DSA certificate for signatures");
        }

        DDS_Security_BinaryProperty_t hash_c1_val = {
            .name = DDS_AUTHTOKEN_PROP_HASH_C1,
            .value = {._length = sizeof(handshake->hash_c1), ._buffer = handshake->hash_c1}};
        DDS_Security_BinaryProperty_t hash_c2_val = {
            .name = DDS_AUTHTOKEN_PROP_HASH_C2,
            .value = {._length = sizeof(handshake->hash_c2), ._buffer = handshake->hash_c2}};

        const DDS_Security_BinaryProperty_t
            *binary_properties[PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE_OPT];

        if (token_type == HS_TOKEN_REPLY) {
            const DDS_Security_BinaryProperty_t *kem_public_from_reply =
                DDS_Security_DataHolder_find_binary_property(token, DDS_AUTHTOKEN_PROP_KEM_PUBLIC);
            if (!kem_public_from_reply) {
                DBG_ERR("Missing KEM_PUBLIC in REPLY token\n");
                EVP_PKEY_free(public_key);
                return set_exception(ex, "KEM public key not found in REPLY token");
            }
            DBG_TRACE("Extracted KEM_PUBLIC from REPLY token\n");

            if (impl->include_optional) {
                binary_properties[0] = &hash_c2_val;
                binary_properties[1] = challenge2;
                binary_properties[2] = kem_ciphertext;
                binary_properties[3] = challenge1;
                binary_properties[4] = kem_public_from_reply;
                binary_properties[5] = &hash_c1_val;
                DBG_TRACE("Using optional fields for PQ signature validation\n");
            } else {
                binary_properties[0] = challenge2;
                binary_properties[1] = kem_ciphertext;
                binary_properties[2] = challenge1;
                binary_properties[3] = kem_public_from_reply;
                DBG_TRACE("Using standard fields for PQ signature validation\n");
            }

            DBG_TRACE("Validating PQ signature with %u properties\n",
                      impl->include_optional ? 6 : 4);
            DDS_Security_ValidationResult_t result = validate_pq_signature(
                public_key, binary_properties, impl->include_optional ? 6 : 4,
                signature->value._buffer, signature->value._length, ex, oqs_ctx);
            EVP_PKEY_free(public_key);

            if (result != DDS_SECURITY_VALIDATION_OK) {
                DBG_ERR("PQ signature validation failed for REPLY token\n");
                return set_exception(ex, "PQ signature validation failed");
            }
            DBG_TRACE("PQ signature validated for REPLY token\n");
        } else { /* HS_TOKEN_FINAL */
            if (impl->include_optional) {
                binary_properties[0] = &hash_c1_val;
                binary_properties[1] = challenge1;
                binary_properties[2] = dh1;
                binary_properties[3] = challenge2;
                binary_properties[4] = kem_ciphertext;
                binary_properties[5] = &hash_c2_val;
                DBG_TRACE("Using optional fields for PQ signature validation (FINAL)\n");
            } else {
                binary_properties[0] = challenge1;
                binary_properties[1] = dh1;
                binary_properties[2] = challenge2;
                binary_properties[3] = kem_ciphertext;
                DBG_TRACE("Using standard fields for PQ signature validation (FINAL)\n");
            }

            DBG_TRACE("Validating PQ signature for FINAL token with %u properties\n",
                      impl->include_optional ? 6 : 4);
            DDS_Security_ValidationResult_t result = validate_pq_signature(
                public_key, binary_properties, impl->include_optional ? 6 : 4,
                signature->value._buffer, signature->value._length, ex, oqs_ctx);
            EVP_PKEY_free(public_key);

            if (result != DDS_SECURITY_VALIDATION_OK) {
                DBG_ERR("PQ signature validation failed for FINAL token\n");
                return set_exception(ex, "PQ signature validation failed");
            }
            DBG_TRACE("PQ signature validated for FINAL token\n");
        }
#else  // Classical cryptography
        DBG_TRACE("Validating classical signature for %s token\n",
                  token_type == HS_TOKEN_REPLY ? "REPLY" : "FINAL");

        EVP_PKEY *public_key = X509_get_pubkey(relation->remoteIdentity->identityCert);
        if (!public_key) {
            DBG_ERR("X509_get_pubkey failed\n");
            return set_exception(ex, "X509_get_pubkey failed");
        }
        DBG_TRACE("Obtained public key from remote identity certificate\n");

        DDS_Security_BinaryProperty_t hash_c1_val = {
            .name = DDS_AUTHTOKEN_PROP_HASH_C1,
            .value = {._length = sizeof(handshake->hash_c1), ._buffer = handshake->hash_c1}};
        DDS_Security_BinaryProperty_t hash_c2_val = {
            .name = DDS_AUTHTOKEN_PROP_HASH_C2,
            .value = {._length = sizeof(handshake->hash_c2), ._buffer = handshake->hash_c2}};

        DDS_Security_ValidationResult_t result;
        if (token_type == HS_TOKEN_REPLY) {
            result = validate_signature(
                public_key,
                (const DDS_Security_BinaryProperty_t *[]){&hash_c2_val, challenge2, dh2, challenge1,
                                                          dh1, &hash_c1_val},
                6, signature->value._buffer, signature->value._length, ex);
            DBG_TRACE("validate_signature called for REPLY token\n");
        } else {
            result = validate_signature(
                public_key,
                (const DDS_Security_BinaryProperty_t *[]){&hash_c1_val, challenge1, dh1, challenge2,
                                                          dh2, &hash_c2_val},
                6, signature->value._buffer, signature->value._length, ex);
            DBG_TRACE("validate_signature called for FINAL token\n");
        }

        EVP_PKEY_free(public_key);
        if (result != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Classical signature validation failed\n");
            return result;
        }
        DBG_TRACE("Classical signature validated successfully\n");
#endif // PQ_CRYPTO
    }

    DBG_TRACE("validate_handshake_token_impl succeeded\n");
    return DDS_SECURITY_VALIDATION_OK;
}

static DDS_Security_ValidationResult_t validate_handshake_token(
    const DDS_Security_HandshakeMessageToken *token, enum handshake_token_type token_type,
    HandshakeInfo *handshake, X509Seq *trusted_ca_list,
    const DDS_Security_BinaryProperty_t *dh1_ref, const DDS_Security_BinaryProperty_t *dh2_ref,
    dds_security_authentication_impl *auth_impl, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering validate_handshake_token\n");
    const DDS_Security_ValidationResult_t ret = validate_handshake_token_impl(
        token, token_type, handshake, trusted_ca_list, dh1_ref, dh2_ref, auth_impl, ex);

    if (ret != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("validate_handshake_token_impl failed with code %d\n", ret);
        if (token_type == HS_TOKEN_REQ || token_type == HS_TOKEN_REPLY) {
            IdentityRelation *relation = handshake->relation;

            if (relation->remoteIdentity->identityCert) {
                X509_free(relation->remoteIdentity->identityCert);
                relation->remoteIdentity->identityCert = NULL;
                DBG_TRACE("Freed remote identity certificate after failure\n");
            }
#ifdef PQ_CRYPTO
            if (handshake->kem_pk) {
                EVP_PKEY_free(handshake->kem_pk);
                handshake->kem_pk = NULL;
                DBG_TRACE("Freed handshake->kem_pk after failure\n");
            }
#else
            if (handshake->rdh) {
                EVP_PKEY_free(handshake->rdh);
                handshake->rdh = NULL;
                DBG_TRACE("Freed handshake->rdh after failure\n");
            }
#endif
        }
    } else {
        DBG_TRACE("validate_handshake_token_impl returned OK\n");
    }

    return ret;
}

DDS_Security_ValidationResult_t
begin_handshake_reply(dds_security_authentication *instance,
                      DDS_Security_HandshakeHandle *handshake_handle,
                      DDS_Security_HandshakeMessageToken *handshake_message_out,
                      const DDS_Security_HandshakeMessageToken *handshake_message_in,
                      const DDS_Security_IdentityHandle initiator_identity_handle,
                      const DDS_Security_IdentityHandle replier_identity_handle,
                      const DDS_Security_OctetSeq *serialized_local_participant_data,
                      DDS_Security_SecurityException *ex) {

    DBG_HANDSHAKE("begin_handshake_reply called (initiator=0x%lx, replier=0x%lx)\n",
                  (unsigned long)initiator_identity_handle, (unsigned long)replier_identity_handle);

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;

    if (!instance || !handshake_handle || !handshake_message_out || !handshake_message_in ||
        !serialized_local_participant_data) {
        DBG_ERR("Invalid parameter provided to begin_handshake_reply\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_reply: Invalid parameter provided");
        return DDS_SECURITY_VALIDATION_FAILED;
    }
    if (serialized_local_participant_data->_length == 0 ||
        serialized_local_participant_data->_buffer == NULL) {
        DBG_ERR("Invalid serialized_local_participant_data in "
                "begin_handshake_reply\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_reply: Invalid parameter provided");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    HandshakeInfo *handshake = NULL;
    IdentityRelation *relation = NULL;
    SecurityObject *obj;
    LocalIdentityInfo *localIdent;
    RemoteIdentityInfo *remoteIdent;
    unsigned char *certData = NULL;
    uint32_t certDataSize;

#ifdef PQ_CRYPTO
    const DDS_Security_BinaryProperty_t *binary_property_kem_public;
    OSSL_LIB_CTX *oqs_ctx = get_oqs_context(impl);
    if (HASH_OPTIONAL) {
        impl->include_optional = 1;
    }
    uint32_t tokcount = impl->include_optional ? 13 : 11; // KEM tokens count
#else
    EVP_PKEY *dhkeyLocal = NULL;
    unsigned char *dhPubKeyData;
    uint32_t dhPubKeyDataSize;
    uint32_t tokcount = impl->include_optional ? 12 : 9;
#endif
    int created = 0;

    ddsrt_mutex_lock(&impl->lock);

    /* Find the local identity (replier) */
    obj = security_object_find(impl->objectHash, replier_identity_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_LOCAL_IDENTITY)) {
        DBG_ERR("Invalid replier_identity_handle provided to "
                "begin_handshake_reply\n");
        DDS_Security_Exception_set(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "begin_handshake_reply: Invalid replier_identity_handle provided");
        goto err_inv_handle;
    }
    localIdent = (LocalIdentityInfo *)obj;
    DBG_TRACE("Found local identity for replier (handle=0x%lx)\n",
              (unsigned long)replier_identity_handle);

    /* Find the remote identity (initiator) */
    obj = security_object_find(impl->objectHash, initiator_identity_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_REMOTE_IDENTITY)) {
        DBG_ERR("Invalid initiator_identity_handle provided to "
                "begin_handshake_reply\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "begin_handshake_reply: Invalid "
                                   "initiator_identity_handle provided");
        goto err_inv_handle;
    }
    remoteIdent = (RemoteIdentityInfo *)obj;
    DBG_TRACE("Found remote identity for initiator (handle=0x%lx)\n",
              (unsigned long)initiator_identity_handle);

    if (!(handshake = find_handshake(impl, SECURITY_OBJECT_HANDLE(localIdent),
                                     SECURITY_OBJECT_HANDLE(remoteIdent)))) {
        relation = find_identity_relation(remoteIdent, SECURITY_OBJECT_HANDLE(localIdent));
        assert(relation);
        handshake = handshake_info_new(localIdent, remoteIdent, relation);
        handshake->created_in = CREATEDREPLY;
        (void)ddsrt_hh_add(impl->objectHash, handshake);
        created = 1;
        DBG_HANDSHAKE("Created new handshake for REPLY (handle=0x%lx)\n",
                      (unsigned long)HANDSHAKE_HANDLE(handshake));
    } else {
        relation = handshake->relation;
        assert(relation);
        DBG_TRACE("Reusing existing handshake for REPLY (handle=0x%lx)\n",
                  (unsigned long)HANDSHAKE_HANDLE(handshake));
    }

    if (validate_handshake_token(handshake_message_in, HS_TOKEN_REQ, handshake,
                                 &(impl->trustedCAList), NULL, NULL, impl,
                                 ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Handshake token validation failed in begin_handshake_reply\n");
        goto err_inv_token;
    }
    DBG_HANDSHAKE("Handshake request token validated (handle=0x%lx)\n",
                  (unsigned long)HANDSHAKE_HANDLE(handshake));

    if (get_certificate_contents(localIdent->identityCert, &certData, &certDataSize, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to get certificate contents in begin_handshake_reply\n");
        goto err_alloc_cid;
    }
    DBG_TRACE("Certificate contents retrieved (size=%u bytes)\n", certDataSize);

#ifdef PQ_CRYPTO
    /* PQ KEM encapsulation using the remote party's public key */
    if (!handshake->kem_ct || !handshake->kem_ss) {
        /* Extract the KEM public key from the received request token */
        binary_property_kem_public = DDS_Security_DataHolder_find_binary_property(
            handshake_message_in, DDS_AUTHTOKEN_PROP_KEM_PUBLIC);
        if (binary_property_kem_public == NULL) {
            DBG_ERR("KEM public key not found in request token\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "begin_handshake_reply: KEM public key not found");
            goto err_encap_kem_key;
        }
        DBG_CRYPTO("Found KEM public key from remote party\n");

        /* Convert the remote party's public key to EVP_PKEY format */
        EVP_PKEY *remote_public_key = NULL;
        if (pq_oct_to_public_key(&remote_public_key, binary_property_kem_public->value._buffer,
                                 binary_property_kem_public->value._length,
                                 remoteIdent->kagreeAlgoKind, oqs_ctx,
                                 ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Failed to convert remote KEM public key\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Failed to convert remote KEM public key");
            goto err_encap_kem_key;
        }
        DBG_CRYPTO("Remote KEM public key converted successfully\n");

        /* Store the remote public key for later use */
        handshake->kem_pk = remote_public_key;

        /* Perform KEM encapsulation using the remote party's public key */
        DBG_CRYPTO("Performing KEM encapsulation\n");
        if (pq_kem_encapsulation(handshake->kem_pk, // ← FIX: Use remote public key!
                                 &handshake->kem_ct_len, &handshake->kem_ss_len, &handshake->kem_ct,
                                 &handshake->kem_ss, binary_property_kem_public,
                                 remoteIdent->kagreeAlgoKind, ex,
                                 oqs_ctx) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("KEM encapsulation failed in begin_handshake_reply\n");
            goto err_encap_kem_key;
        }
        DBG_CRYPTO("KEM encapsulation successful (ct_len=%zu, ss_len=%zu)\n", handshake->kem_ct_len,
                   handshake->kem_ss_len);
    }
#else
    /* Classical DH key generation */
    if (!handshake->ldh) {
        if (generate_dh_keys(&dhkeyLocal, remoteIdent->kagreeAlgoKind, ex) !=
            DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Failed to generate DH keys in begin_handshake_reply\n");
            goto err_gen_dh_keys;
        }
        handshake->ldh = dhkeyLocal;
        EVP_PKEY_copy_parameters(handshake->rdh, handshake->ldh);
        DBG_CRYPTO("Generated DH keypair for reply\n");
    }

    if (dh_public_key_to_oct(handshake->ldh, remoteIdent->kagreeAlgoKind, &dhPubKeyData,
                             &dhPubKeyDataSize, ex) != DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to extract DH public key in begin_handshake_reply\n");
        goto err_get_public_key;
    }
    DBG_CRYPTO("Extracted DH public key data (size=%u bytes)\n", dhPubKeyDataSize);
#endif /* PQ_CRYPTO */

    if (localIdent->pdata._length == 0) {
        DDS_Security_OctetSeq_copy(&localIdent->pdata, serialized_local_participant_data);
        DBG_TRACE("Copied serialized local participant data for reply\n");
    }

    DDS_Security_BinaryProperty_t *tokens = DDS_Security_BinaryPropertySeq_allocbuf(tokcount);
    uint32_t tokidx = 0;

    /* Store the Identity Certificate associated with the local identity in c.id
     * property */
    DDS_Security_BinaryProperty_set_by_ref(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_ID, certData,
                                           certDataSize);
    certData = NULL;
    DBG_TRACE("Set C_ID property (size=%u bytes)\n", certDataSize);

    DDS_Security_BinaryProperty_set_by_string(
        &tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_PERM,
        localIdent->permissionsDocument ? localIdent->permissionsDocument : "");
    DBG_TRACE("Set C_PERM property\n");

    DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_PDATA,
                                             serialized_local_participant_data->_buffer,
                                             serialized_local_participant_data->_length);
    DBG_TRACE("Set C_PDATA property (length=%u bytes)\n",
              serialized_local_participant_data->_length);

    DDS_Security_BinaryProperty_set_by_string(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_DSIGN_ALGO,
                                              get_dsign_algo(localIdent->dsignAlgoKind));
    DBG_TRACE("Set C_DSIGN_ALGO property\n");

    DDS_Security_BinaryProperty_set_by_string(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_C_KAGREE_ALGO,
                                              get_kagree_algo(remoteIdent->kagreeAlgoKind));
    DBG_TRACE("Set C_KAGREE_ALGO property\n");

    /* Calculate the hash_c2 */
    DDS_Security_BinaryPropertySeq bseq = {._length = 5, ._buffer = tokens};
    get_hash_binary_property_seq(&bseq, handshake->hash_c2);
    DBG_TRACE("Calculated HASH_C2\n");

#ifdef PQ_CRYPTO
    /* Set the KEM ciphertext and KEM public key in properties */
    DDS_Security_BinaryProperty_t *ciphertext = &tokens[tokidx++];
    DDS_Security_BinaryProperty_set_by_value(ciphertext, DDS_AUTHTOKEN_PROP_KEM_CIPHERTEXT,
                                             handshake->kem_ct, handshake->kem_ct_len);
    DBG_CRYPTO("Set KEM_CIPHERTEXT property (length=%zu bytes)\n", handshake->kem_ct_len);

    DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_KEM_PUBLIC,
                                             binary_property_kem_public->value._buffer,
                                             binary_property_kem_public->value._length);
    DBG_CRYPTO("Set KEM_PUBLIC property (length=%u bytes)\n",
               binary_property_kem_public->value._length);

    /* Find the kem_public property from the received request token for
     * challenges */
    assert(binary_property_kem_public);
#else
    /* Set the DH public key associated with the local participant in dh2
     * property */
    DDS_Security_BinaryProperty_t *dh2 = &tokens[tokidx++];
    DDS_Security_BinaryProperty_set_by_ref(dh2, DDS_AUTHTOKEN_PROP_DH2, dhPubKeyData,
                                           dhPubKeyDataSize);
    DBG_TRACE("Set DH2 property (size=%u bytes)\n", dhPubKeyDataSize);

    /* Find the dh1 property from the received request token */
    const DDS_Security_BinaryProperty_t *dh1 =
        DDS_Security_DataHolder_find_binary_property(handshake_message_in, DDS_AUTHTOKEN_PROP_DH1);
    assert(dh1);
    DBG_TRACE("Found DH1 property in incoming request token\n");
#endif

    assert(relation->rchallenge);
    DDS_Security_BinaryProperty_t *challenge1 = &tokens[tokidx++];
    DDS_Security_BinaryProperty_set_by_value(challenge1, DDS_AUTHTOKEN_PROP_CHALLENGE1,
                                             relation->rchallenge->value,
                                             sizeof(AuthenticationChallenge));
    DBG_TRACE("Set CHALLENGE1 property\n");

    assert(relation->lchallenge);
    DDS_Security_BinaryProperty_t *challenge2 = &tokens[tokidx++];
    DDS_Security_BinaryProperty_set_by_value(challenge2, DDS_AUTHTOKEN_PROP_CHALLENGE2,
                                             relation->lchallenge->value,
                                             sizeof(AuthenticationChallenge));
    DBG_TRACE("Set CHALLENGE2 property\n");

    /* Add optional hash values if enabled */
    if (impl->include_optional) {
#ifdef PQ_CRYPTO
        /* For PQ, add hash values */
        DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_HASH_C2,
                                                 handshake->hash_c2, sizeof(HashValue_t));
        DBG_TRACE("Set HASH_C2 property (optional)\n");

        DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_HASH_C1,
                                                 handshake->hash_c1, sizeof(HashValue_t));
        DBG_TRACE("Set HASH_C1 property (optional)\n");
#else
        /* For classical, add DH keys and hash values */
        DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_DH1,
                                                 dh1->value._buffer, dh1->value._length);
        DBG_TRACE("Set DH1 property (optional)\n");

        DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_HASH_C2,
                                                 handshake->hash_c2, sizeof(HashValue_t));
        DBG_TRACE("Set HASH_C2 property (optional)\n");

        DDS_Security_BinaryProperty_set_by_value(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_HASH_C1,
                                                 handshake->hash_c1, sizeof(HashValue_t));
        DBG_TRACE("Set HASH_C1 property (optional)\n");
#endif
    }

#ifdef PQ_CRYPTO
    /* Calculate the PQ signature using ML-DSA */
    {
        uint8_t *sign_public_key = NULL;
        unsigned char *kem_signature = NULL;
        size_t kem_signature_len = 0;

        /* Get the signing key */
        EVP_PKEY *signing_key = localIdent->privateKey;

        if (!signing_key) {
            DBG_ERR("No suitable ML-DSA signing key available in "
                    "begin_handshake_reply\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "No ML-DSA signing key available");
            goto err_signature;
        }
        DBG_CRYPTO("Using private key for signing (ML-DSA)\n");

        /* Verify the signing key can actually sign */
        if (!EVP_PKEY_can_sign(signing_key)) {
            DBG_ERR("Selected key cannot perform signing operations\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Selected key cannot perform signing operations");
            goto err_signature;
        }

        /* Create signature with proper binary properties */
        if (impl->include_optional) {
            DDS_Security_BinaryProperty_t *hash_c1_val =
                hash_value_to_binary_property(DDS_AUTHTOKEN_PROP_HASH_C1, handshake->hash_c1);
            DDS_Security_BinaryProperty_t *hash_c2_val =
                hash_value_to_binary_property(DDS_AUTHTOKEN_PROP_HASH_C2, handshake->hash_c2);
            const DDS_Security_BinaryProperty_t
                *binary_properties[PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE_OPT] = {
                    hash_c2_val, challenge2, ciphertext, challenge1, binary_property_kem_public,
                    hash_c1_val};

            DBG_CRYPTO("Creating ML-DSA signature with optional fields\n");
            DDS_Security_ValidationResult_t result = create_pq_signature(
                signing_key, binary_properties, PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE_OPT,
                &kem_signature, &kem_signature_len, ex, &sign_public_key, localIdent->dsignAlgoKind,
                oqs_ctx);
            DDS_Security_BinaryProperty_free(hash_c1_val);
            DDS_Security_BinaryProperty_free(hash_c2_val);
            if (result != DDS_SECURITY_VALIDATION_OK) {
                DBG_ERR("ML-DSA signature creation failed (optional fields)\n");
                goto err_signature;
            }
        } else {
            const DDS_Security_BinaryProperty_t
                *binary_properties[PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE] = {
                    challenge2, ciphertext, challenge1, binary_property_kem_public};

            DBG_CRYPTO("Creating ML-DSA signature without optional fields\n");
            if (create_pq_signature(
                    signing_key, binary_properties, PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE,
                    &kem_signature, &kem_signature_len, ex, &sign_public_key,
                    localIdent->dsignAlgoKind, oqs_ctx) != DDS_SECURITY_VALIDATION_OK) {
                DBG_ERR("ML-DSA signature creation failed (standard)\n");
                goto err_signature;
            }
        }

        DBG_CRYPTO("Setting ML-DSA signature (len=%zu)\n", kem_signature_len);
        DDS_Security_BinaryProperty_set_by_ref(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_SIGNATURE,
                                               kem_signature, kem_signature_len);

        DDS_Security_BinaryProperty_set_by_value(
            &tokens[tokidx++], DDS_AUTHTOKEN_PROP_KEM_SIGNATURE, kem_signature, kem_signature_len);
        DBG_CRYPTO("Signature properties set\n");
    }
#else
    /* Calculate the classical signature */
    {
        unsigned char *sign;
        size_t signlen;
        DDS_Security_BinaryProperty_t *hash_c1_val =
            hash_value_to_binary_property(DDS_AUTHTOKEN_PROP_HASH_C1, handshake->hash_c1);
        DDS_Security_BinaryProperty_t *hash_c2_val =
            hash_value_to_binary_property(DDS_AUTHTOKEN_PROP_HASH_C2, handshake->hash_c2);
        const DDS_Security_BinaryProperty_t *binary_properties[HANDSHAKE_SIGNATURE_CONTENT_SIZE] = {
            hash_c2_val, challenge2, dh2, challenge1, dh1, hash_c1_val};
        DDS_Security_ValidationResult_t result =
            create_signature(localIdent->privateKey, binary_properties,
                             HANDSHAKE_SIGNATURE_CONTENT_SIZE, &sign, &signlen, ex);
        DDS_Security_BinaryProperty_free(hash_c1_val);
        DDS_Security_BinaryProperty_free(hash_c2_val);
        if (result != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("Classical signature creation failed in "
                    "begin_handshake_reply\n");
            goto err_signature;
        }
        DDS_Security_BinaryProperty_set_by_ref(&tokens[tokidx++], DDS_AUTHTOKEN_PROP_SIGNATURE,
                                               sign, (uint32_t)signlen);
        DBG_CRYPTO("Classical signature set (len=%zu)\n", signlen);
    }
#endif /* PQ_CRYPTO */

    assert(tokidx == tokcount);
    DBG_TRACE("All %u handshake reply properties set\n", tokcount);

    (void)ddsrt_hh_add(impl->objectHash, handshake);
    handshake_message_out->class_id = ddsrt_strdup(DDS_SECURITY_AUTH_HANDSHAKE_REPLY_TOKEN_ID);
    handshake_message_out->binary_properties._length = tokidx;
    handshake_message_out->binary_properties._buffer = tokens;

    /* Set the handle BEFORE unlocking the mutex (critical for thread safety) */
    *handshake_handle = HANDSHAKE_HANDLE(handshake);

    ddsrt_mutex_unlock(&impl->lock);

    DBG_HANDSHAKE("Leaving begin_handshake_reply with handle: 0x%lx\n",
                  (unsigned long)*handshake_handle);
    return DDS_SECURITY_VALIDATION_PENDING_HANDSHAKE_MESSAGE;

err_signature:
    free_binary_properties(tokens, tokcount);
    DBG_ERR("Error during signature generation in begin_handshake_reply\n");
#ifdef PQ_CRYPTO
err_gen_kem_keys:
err_encap_kem_key:
#else
err_get_public_key:
err_gen_dh_keys:
#endif
    if (certData) {
        ddsrt_free(certData);
        DBG_TRACE("Freed certificate data buffer after error\n");
    }
err_alloc_cid:
err_inv_token:
    if (created) {
        (void)ddsrt_hh_remove(impl->objectHash, handshake);
        security_object_free((SecurityObject *)handshake);
        DBG_TRACE("Cleaned up handshake after error\n");
    }
err_inv_handle:
    ddsrt_mutex_unlock(&impl->lock);
    return DDS_SECURITY_VALIDATION_FAILED;
}

static bool generate_shared_secret(const HandshakeInfo *handshake, unsigned char **shared_secret,
                                   DDS_Security_long *length, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering generate_shared_secret\n");

#ifdef PQ_CRYPTO
    /* PQ KEM shared secret generation */
    *shared_secret = NULL;
    *length = 0;

    DBG_CRYPTO("Using PQ mode for shared secret generation\n");

    /* Validate that we have a KEM shared secret in the handshake */
    if (!handshake->kem_ss || handshake->kem_ss_len == 0) {
        DBG_ERR("No KEM shared secret available\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "process_handshake: No KEM shared secret available");
        return false;
    }
    DBG_CRYPTO("Found KEM shared secret (len=%zu)\n", handshake->kem_ss_len);

    /* Hash the KEM shared secret to get final shared secret */
    *shared_secret = ddsrt_malloc(SHA256_DIGEST_LENGTH);
    if (!*shared_secret) {
        DBG_ERR("Memory allocation failed for shared_secret\n");
        return false;
    }
    *length = SHA256_DIGEST_LENGTH;
    SHA256(handshake->kem_ss, handshake->kem_ss_len, *shared_secret);
    DBG_CRYPTO("Generated shared secret from KEM ss (len=%zu)\n", handshake->kem_ss_len);
    return true;

#else
    /* Classical DH shared secret generation */
    EVP_PKEY_CTX *ctx = NULL;
    size_t skeylen;
    unsigned char *secret = NULL;
    *shared_secret = NULL;

    DBG_CRYPTO("Using classical DH mode for shared secret generation\n");

    /* Create context */
    ctx = EVP_PKEY_CTX_new(handshake->ldh, NULL);
    if (!ctx) {
        DBG_ERR("Failed to create EVP_PKEY_CTX\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "process_handshake: Shared secret failed to create context: ");
        goto fail_ctx_new;
    }
    DBG_TRACE("Created EVP_PKEY_CTX\n");

    /* Initialize derive */
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        DBG_ERR("EVP_PKEY_derive_init failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "process_handshake: Shared secret failed to initialize context: ");
        goto fail_derive;
    }
    DBG_TRACE("EVP_PKEY_derive_init succeeded\n");

    /* Set peer key */
    if (EVP_PKEY_derive_set_peer(ctx, handshake->rdh) <= 0) {
        DBG_ERR("EVP_PKEY_derive_set_peer failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "process_handshake: Shared secret failed to set peer key: ");
        goto fail_derive;
    }
    DBG_TRACE("EVP_PKEY_derive_set_peer succeeded\n");

    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
        DBG_ERR("EVP_PKEY_derive (determine length) failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "process_handshake: Shared secret failed to determine key length: ");
        goto fail_derive;
    }
    DBG_TRACE("Determined shared secret raw length: %zu\n", skeylen);

    /* Allocate and derive */
    secret = ddsrt_malloc(skeylen);
    if (!secret) {
        DBG_ERR("Memory allocation failed for raw secret\n");
        goto fail_derive;
    }
    if (EVP_PKEY_derive(ctx, secret, &skeylen) <= 0) {
        DBG_ERR("EVP_PKEY_derive (compute secret) failed\n");
        DDS_Security_Exception_set_with_openssl_error(
            ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
            DDS_SECURITY_VALIDATION_FAILED,
            "process_handshake: Could not compute the shared secret: ");
        goto fail_derive;
    }
    DBG_TRACE("Computed raw shared secret (len=%zu)\n", skeylen);

    /* Hash to finalize */
    *shared_secret = ddsrt_malloc(SHA256_DIGEST_LENGTH);
    if (!*shared_secret) {
        DBG_ERR("Memory allocation failed for hashed shared_secret\n");
        ddsrt_free(secret);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    *length = SHA256_DIGEST_LENGTH;
    SHA256(secret, skeylen, *shared_secret);
    DBG_CRYPTO("Hashed shared secret to length %u\n", (unsigned)SHA256_DIGEST_LENGTH);

    ddsrt_free(secret);
    EVP_PKEY_CTX_free(ctx);
    return true;

fail_derive:
    DBG_ERR("Cleaning up after derive failure\n");
    ddsrt_free(secret);
    EVP_PKEY_CTX_free(ctx);
fail_ctx_new:
    return false;
#endif /* PQ_CRYPTO */
}

DDS_Security_ValidationResult_t
process_handshake(dds_security_authentication *instance,
                  DDS_Security_HandshakeMessageToken *handshake_message_out,
                  const DDS_Security_HandshakeMessageToken *handshake_message_in,
                  const DDS_Security_HandshakeHandle handshake_handle,
                  DDS_Security_SecurityException *ex) {
    if (!instance || !handshake_handle || !handshake_message_out || !handshake_message_in) {
        DBG_ERR("Invalid parameter provided\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "process_handshake: Invalid parameter provided");
        return DDS_SECURITY_VALIDATION_FAILED;
    }

    DBG_HANDSHAKE("Processing handshake (handle: 0x%lx)\n", (unsigned long)handshake_handle);

    DDS_Security_ValidationResult_t hs_result = DDS_SECURITY_VALIDATION_OK;
    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    HandshakeInfo *handshake = NULL;
    IdentityRelation *relation = NULL;
    SecurityObject *obj;

#ifdef PQ_CRYPTO
    /* PQ variables */
    OSSL_LIB_CTX *oqs_ctx = get_oqs_context(impl);
    const DDS_Security_BinaryProperty_t *kem_public, *kem_ciphertext;
    const uint32_t tsz =
        impl->include_optional ? 8 : 6; /* KEM signature + public key + ciphertext */
    DDS_Security_BinaryProperty_t *pq_gen = NULL;
    DBG_CRYPTO("Using post-quantum crypto mode\n");
#else
    /* Classical DH variables */
    DDS_Security_BinaryProperty_t *dh1_gen = NULL, *dh2_gen = NULL;
    const uint32_t tsz = impl->include_optional ? 7 : 3;
    DBG_CRYPTO("Using classical crypto mode\n");
#endif

    DDS_Security_octet *challenge1_ref_for_shared_secret, *challenge2_ref_for_shared_secret;

    memset(handshake_message_out, 0, sizeof(DDS_Security_HandshakeMessageToken));

    ddsrt_mutex_lock(&impl->lock);
    obj = security_object_find(impl->objectHash, handshake_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_HANDSHAKE)) {
        DBG_ERR("Invalid handshake handle provided\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "process_handshake: Invalid handshake_handle provided");
        goto err_inv_handle;
    }
    handshake = (HandshakeInfo *)obj;
    relation = handshake->relation;
    assert(relation);

    DBG_TRACE("Handshake found (created_in: %s)\n",
              handshake->created_in == CREATEDREQUEST ? "REQUEST" : "REPLY");

    /* check if the handle created by a handshake_request or handshake_reply */
    switch (handshake->created_in) {
    case CREATEDREQUEST:
        DBG_HANDSHAKE("Processing REPLY token (REQUEST creator)\n");
#ifdef PQ_CRYPTO
        /* PQ: Handle REPLY token processing for REQUEST creator */
        {
            // Create PQ key property for validation using KEM-specific fields
            if ((pq_gen =
                     create_pqkey_property(DDS_AUTHTOKEN_PROP_KEM_PUBLIC, handshake->kem_keypair,
                                           relation->localIdentity->kagreeAlgoKind, ex)) == NULL)
                goto err_inv_token;

            if (validate_handshake_token(handshake_message_in, HS_TOKEN_REPLY, handshake,
                                         &(impl->trustedCAList), pq_gen, NULL, impl,
                                         ex) != DDS_SECURITY_VALIDATION_OK)
                goto err_inv_token;

            // Get the KEM ciphertext and public key from the validated token
            kem_ciphertext = DDS_Security_DataHolder_find_binary_property(
                handshake_message_in, DDS_AUTHTOKEN_PROP_KEM_CIPHERTEXT);
            assert(kem_ciphertext);

            kem_public = DDS_Security_DataHolder_find_binary_property(
                handshake_message_in, DDS_AUTHTOKEN_PROP_KEM_PUBLIC);
            assert(kem_public);

            // Perform KEM decapsulation using our KEM keypair
            DBG_KEM("Performing KEM decapsulation\n");
            if (pq_kem_decapsulation(handshake->kem_keypair, &handshake->kem_ss,
                                     &handshake->kem_ss_len, kem_ciphertext,
                                     relation->localIdentity->kagreeAlgoKind, ex,
                                     oqs_ctx) != DDS_SECURITY_VALIDATION_OK)
                goto err_inv_token;

            DBG_KEM("Decapsulation successful (ss_len=%zu)\n", handshake->kem_ss_len);
        }
#else
        /* Classical: Handle REPLY token processing for REQUEST creator */
        {
            if ((dh1_gen = create_dhkey_property(DDS_AUTHTOKEN_PROP_DH1, handshake->ldh,
                                                 relation->localIdentity->kagreeAlgoKind, ex)) ==
                NULL)
                goto err_inv_token;

            /* The source of the handshake_handle is a begin_handshake_request
             * function. So, handshake_message_in is from a remote
             * begin_handshake_reply function */
            /* Verify Message Token contents according to Spec 9.3.2.5.2 (Reply
             * Message)  */
            if (validate_handshake_token(handshake_message_in, HS_TOKEN_REPLY, handshake,
                                         &(impl->trustedCAList), dh1_gen, NULL, impl,
                                         ex) != DDS_SECURITY_VALIDATION_OK)
                goto err_inv_token;

            EVP_PKEY_copy_parameters(handshake->rdh, handshake->ldh);

            /* Find the dh2 property from the received reply token */
            const DDS_Security_BinaryProperty_t *dh2 = DDS_Security_DataHolder_find_binary_property(
                handshake_message_in, DDS_AUTHTOKEN_PROP_DH2);
            assert(dh2);
            DBG_CRYPTO("DH key exchange parameters copied\n");
        }
#endif /* PQ_CRYPTO */

        DBG_HANDSHAKE("Key exchange completed, creating FINAL token\n");

        /* Create FINAL token */
        {
            DDS_Security_BinaryProperty_t *tokens = DDS_Security_BinaryPropertySeq_allocbuf(tsz);
            uint32_t idx = 0;

            assert(relation->lchallenge);
            DDS_Security_BinaryProperty_t *challenge1 = &tokens[idx++];
            DDS_Security_BinaryProperty_set_by_value(challenge1, DDS_AUTHTOKEN_PROP_CHALLENGE1,
                                                     relation->lchallenge->value,
                                                     sizeof(AuthenticationChallenge));
            assert(relation->rchallenge);
            DDS_Security_BinaryProperty_t *challenge2 = &tokens[idx++];
            DDS_Security_BinaryProperty_set_by_value(challenge2, DDS_AUTHTOKEN_PROP_CHALLENGE2,
                                                     relation->rchallenge->value,
                                                     sizeof(AuthenticationChallenge));

            if (impl->include_optional) {
                DBG_TRACE("Including optional hash values in FINAL token\n");
#ifdef PQ_CRYPTO
                /* For PQ, add hash values */
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_HASH_C2,
                                                         handshake->hash_c2, sizeof(HashValue_t));
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_HASH_C1,
                                                         handshake->hash_c1, sizeof(HashValue_t));
#else
                /* For classical, add DH keys and hash values */
                const DDS_Security_BinaryProperty_t *dh2 =
                    DDS_Security_DataHolder_find_binary_property(handshake_message_in,
                                                                 DDS_AUTHTOKEN_PROP_DH2);
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_DH1,
                                                         dh1_gen->value._buffer,
                                                         dh1_gen->value._length);
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_DH2,
                                                         dh2->value._buffer, dh2->value._length);
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_HASH_C2,
                                                         handshake->hash_c2, sizeof(HashValue_t));
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_HASH_C1,
                                                         handshake->hash_c1, sizeof(HashValue_t));
#endif
            }

#ifdef PQ_CRYPTO
            // Add KEM public key and ciphertext to FINAL token (always needed
            // for PQ)
            DDS_Security_BinaryProperty_set_by_value(&tokens[idx++], DDS_AUTHTOKEN_PROP_KEM_PUBLIC,
                                                     kem_public->value._buffer,
                                                     kem_public->value._length);
            DDS_Security_BinaryProperty_set_by_value(
                &tokens[idx++], DDS_AUTHTOKEN_PROP_KEM_CIPHERTEXT, kem_ciphertext->value._buffer,
                kem_ciphertext->value._length);
            DBG_TRACE("Added KEM public key (%u bytes) and ciphertext (%u "
                      "bytes) to FINAL token\n",
                      kem_public->value._length, kem_ciphertext->value._length);
#endif

            /* Calculate the signature */
            {
                DDS_Security_BinaryProperty_t *hash_c1_val =
                    hash_value_to_binary_property(DDS_AUTHTOKEN_PROP_HASH_C1, handshake->hash_c1);
                DDS_Security_BinaryProperty_t *hash_c2_val =
                    hash_value_to_binary_property(DDS_AUTHTOKEN_PROP_HASH_C2, handshake->hash_c2);

#ifdef PQ_CRYPTO
                unsigned char *kem_signature = NULL;
                size_t kem_signature_len = 0;
                DDS_Security_ValidationResult_t result;

                // Get the signing key
                EVP_PKEY *signing_key = relation->localIdentity->privateKey;
                if (!signing_key) {
                    DBG_ERR("No ML-DSA signing key available\n");
                    DDS_Security_Exception_set(
                        ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                        DDS_SECURITY_VALIDATION_FAILED, "No ML-DSA signing key available");
                    DDS_Security_BinaryProperty_free(hash_c1_val);
                    DDS_Security_BinaryProperty_free(hash_c2_val);
                    goto err_signature;
                }

                DBG_SIG("Creating ML-DSA signature for FINAL token (%s fields)\n",
                        impl->include_optional ? "with optional" : "standard");

                if (impl->include_optional) {
                    const DDS_Security_BinaryProperty_t
                        *binary_properties[PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE_OPT] = {
                            hash_c1_val, challenge1,     kem_public,
                            challenge2,  kem_ciphertext, hash_c2_val};
                    result = create_pq_signature(signing_key, binary_properties,
                                                 PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE_OPT,
                                                 &kem_signature, &kem_signature_len, ex, NULL,
                                                 relation->localIdentity->dsignAlgoKind, oqs_ctx);
                } else {
                    const DDS_Security_BinaryProperty_t
                        *binary_properties[PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE] = {
                            challenge1, kem_public, challenge2, kem_ciphertext};
                    result = create_pq_signature(signing_key, binary_properties,
                                                 PLUGIN_HANDSHAKE_SIGNATURE_CONTENT_SIZE,
                                                 &kem_signature, &kem_signature_len, ex, NULL,
                                                 relation->localIdentity->dsignAlgoKind, oqs_ctx);
                }

                DDS_Security_BinaryProperty_free(hash_c1_val);
                DDS_Security_BinaryProperty_free(hash_c2_val);

                if (result != DDS_SECURITY_VALIDATION_OK) {
                    DBG_ERR("ML-DSA signature creation failed\n");
                    goto err_signature;
                }

                DBG_SIG("ML-DSA signature created (%zu bytes)\n", kem_signature_len);
                DDS_Security_BinaryProperty_set_by_ref(&tokens[idx++], DDS_AUTHTOKEN_PROP_SIGNATURE,
                                                       kem_signature, kem_signature_len);

                // Add the KEM signature property if needed
                DDS_Security_BinaryProperty_set_by_value(&tokens[idx++],
                                                         DDS_AUTHTOKEN_PROP_KEM_SIGNATURE,
                                                         kem_signature, kem_signature_len);
#else
                unsigned char *sign;
                size_t signlen;
                const DDS_Security_BinaryProperty_t *dh2 =
                    DDS_Security_DataHolder_find_binary_property(handshake_message_in,
                                                                 DDS_AUTHTOKEN_PROP_DH2);
                const DDS_Security_BinaryProperty_t
                    *binary_properties[HANDSHAKE_SIGNATURE_CONTENT_SIZE] = {
                        hash_c1_val, challenge1, dh1_gen, challenge2, dh2, hash_c2_val};
                DDS_Security_ValidationResult_t result =
                    create_signature(relation->localIdentity->privateKey, binary_properties,
                                     HANDSHAKE_SIGNATURE_CONTENT_SIZE, &sign, &signlen, ex);
                DDS_Security_BinaryProperty_free(hash_c1_val);
                DDS_Security_BinaryProperty_free(hash_c2_val);
                if (result != DDS_SECURITY_VALIDATION_OK) {
                    DBG_ERR("Classical signature creation failed\n");
                    goto err_signature;
                }
                DBG_SIG("Classical signature created (%zu bytes)\n", signlen);
                DDS_Security_BinaryProperty_set_by_ref(&tokens[idx++], DDS_AUTHTOKEN_PROP_SIGNATURE,
                                                       sign, (uint32_t)signlen);
#endif
            }

            handshake_message_out->class_id =
                ddsrt_strdup(DDS_SECURITY_AUTH_HANDSHAKE_FINAL_TOKEN_ID);
            handshake_message_out->binary_properties._length = tsz;
            handshake_message_out->binary_properties._buffer = tokens;
            DBG_TRACE("FINAL token created with %u properties\n", tsz);
        }

        challenge1_ref_for_shared_secret = (DDS_Security_octet *)(handshake->relation->lchallenge);
        challenge2_ref_for_shared_secret = (DDS_Security_octet *)(handshake->relation->rchallenge);
        hs_result = DDS_SECURITY_VALIDATION_OK_FINAL_MESSAGE;
        break;

    case CREATEDREPLY:
        DBG_HANDSHAKE("Processing FINAL token (REPLY creator)\n");
        /* Handle FINAL token processing for REPLY creator */
#ifdef PQ_CRYPTO
        /* For PQ crypto, simply validate the FINAL token */
        if (validate_handshake_token(handshake_message_in, HS_TOKEN_FINAL, handshake, NULL, NULL,
                                     NULL, impl, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("FINAL token validation failed\n");
            goto err_inv_token;
        }
        DBG_TRACE("FINAL token validated successfully\n");
#else
        /* For classical crypto, create reference properties and validate */
        if ((dh1_gen = create_dhkey_property(DDS_AUTHTOKEN_PROP_DH1, handshake->rdh,
                                             relation->remoteIdentity->kagreeAlgoKind, ex)) == NULL)
            goto err_inv_token;
        if ((dh2_gen = create_dhkey_property(DDS_AUTHTOKEN_PROP_DH2, handshake->ldh,
                                             relation->remoteIdentity->kagreeAlgoKind, ex)) == NULL)
            goto err_inv_token;

        /* The source of the handshake_handle is a begin_handshake_reply
         * function So, handshake_message_in is from a remote process_handshake
         * function */
        /* Verify Message Token contents according to Spec 9.3.2.5.3 (Final
         * Message)   */
        if (validate_handshake_token(handshake_message_in, HS_TOKEN_FINAL, handshake, NULL, dh1_gen,
                                     dh2_gen, impl, ex) != DDS_SECURITY_VALIDATION_OK) {
            DBG_ERR("FINAL token validation failed\n");
            goto err_inv_token;
        }
        DBG_TRACE("FINAL token validated successfully\n");
#endif

        challenge2_ref_for_shared_secret = (DDS_Security_octet *)(handshake->relation->lchallenge);
        challenge1_ref_for_shared_secret = (DDS_Security_octet *)(handshake->relation->rchallenge);
        hs_result = DDS_SECURITY_VALIDATION_OK;
        break;

    default:
        DBG_ERR("Invalid handshake creation state\n");
        ddsrt_mutex_unlock(&impl->lock);
        goto err_bad_param;
    }

    /* Generate shared secret */
    {
        DDS_Security_long shared_secret_length;
        unsigned char *shared_secret;

        DBG_TRACE("Generating shared secret\n");
        if (!generate_shared_secret(handshake, &shared_secret, &shared_secret_length, ex)) {
            DBG_ERR("Shared secret generation failed\n");
            goto err_openssl;
        }

        DBG_DATA("Shared secret (%d bytes):\n", shared_secret_length);
        DBG_DUMP_HEX(shared_secret, shared_secret_length, "Shared Secret");

        handshake->shared_secret_handle_impl =
            ddsrt_malloc(sizeof(DDS_Security_SharedSecretHandleImpl));
        handshake->shared_secret_handle_impl->shared_secret = shared_secret;
        handshake->shared_secret_handle_impl->shared_secret_size = shared_secret_length;
        memcpy(handshake->shared_secret_handle_impl->challenge1, challenge1_ref_for_shared_secret,
               DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE);
        memcpy(handshake->shared_secret_handle_impl->challenge2, challenge2_ref_for_shared_secret,
               DDS_SECURITY_AUTHENTICATION_CHALLENGE_SIZE);

        DBG_INFO("Shared secret generated successfully (%d bytes)\n", shared_secret_length);
    }

    /* Setup expiry listener */
    {
        RemoteIdentityInfo *remoteIdentity = handshake->relation->remoteIdentity;
        dds_time_t cert_exp = get_certificate_expiry(remoteIdentity->identityCert);
        if (cert_exp == DDS_TIME_INVALID) {
            DBG_ERR("Certificate expiry date is invalid\n");
            DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                       DDS_SECURITY_VALIDATION_FAILED,
                                       "Expiry date of the certificate is invalid");
            goto err_invalid_expiry;
        } else if (cert_exp != DDS_NEVER && remoteIdentity->timer == 0)
            remoteIdentity->timer =
                add_validity_end_trigger(impl, IDENTITY_HANDLE(remoteIdentity), cert_exp);
    }

    ddsrt_mutex_unlock(&impl->lock);

#ifdef PQ_CRYPTO
    DDS_Security_BinaryProperty_free(pq_gen);
#else
    DDS_Security_BinaryProperty_free(dh1_gen);
    DDS_Security_BinaryProperty_free(dh2_gen);
#endif

    // TIME MEASUREMENT:
#ifdef MEASURE_HANDSHAKE_TIME
    if (handshake->created_in == CREATEDREPLY) {
        shm_read(&start);
        clock_gettime(CLOCK_MONOTONIC, &end);
        double time_taken =
            ((end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec)) / 1e6;
        // TODO_pq: this way I avoid storing garbage in Bob's side. Not a clean
        // solution but it works
        if (time_taken < 10000) {
            DBG_TRACE("Handshake timing: %.2f ms\n", time_taken);
            target_csv = fopen("../../handshake_times.csv", "a");
            fprintf(target_csv, "%f\n", time_taken);
            fclose(target_csv);
        }
    }
#endif // MEASURE_HANDSHAKE_TIME

    DBG_HANDSHAKE("\n--------------------------------------------------\n"
                  "Handshake processing completed successfully\n"
                  "--------------------------------------------------\n");
    return hs_result;

err_invalid_expiry:
    ddsrt_free(handshake->shared_secret_handle_impl->shared_secret);
    ddsrt_free(handshake->shared_secret_handle_impl);
    handshake->shared_secret_handle_impl = NULL;
err_openssl:
err_signature:
    if (handshake_message_out->class_id)
        DDS_Security_DataHolder_deinit(handshake_message_out);
err_inv_token:
#ifdef PQ_CRYPTO
    DDS_Security_BinaryProperty_free(pq_gen);
#else
    DDS_Security_BinaryProperty_free(dh1_gen);
    DDS_Security_BinaryProperty_free(dh2_gen);
#endif
err_inv_handle:
    ddsrt_mutex_unlock(&impl->lock);
err_bad_param:
    DBG_ERR("Handshake processing failed\n");
    return DDS_SECURITY_VALIDATION_FAILED;
}

DDS_Security_SharedSecretHandle
get_shared_secret(dds_security_authentication *instance,
                  const DDS_Security_HandshakeHandle handshake_handle,
                  DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering get_shared_secret (handshake_handle=0x%lx)\n",
              (unsigned long)handshake_handle);

    if (!instance || !handshake_handle) {
        DBG_ERR("Invalid parameter provided to get_shared_secret\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "get_shared_secret: Invalid parameter provided");
        return DDS_SECURITY_HANDLE_NIL;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    SecurityObject *obj;
    ddsrt_mutex_lock(&impl->lock);
    DBG_TRACE("Acquired lock in get_shared_secret\n");

    obj = security_object_find(impl->objectHash, handshake_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_HANDSHAKE)) {
        DBG_ERR("Invalid handshake_handle provided to get_shared_secret\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "get_shared_secret: Invalid handle provided");
        goto err_invalid_handle;
    }

    HandshakeInfo *handshake = (HandshakeInfo *)obj;
    DDS_Security_SharedSecretHandle sshandle =
        (DDS_Security_SharedSecretHandle)(ddsrt_address)(handshake->shared_secret_handle_impl);
    DBG_TRACE("Retrieved shared_secret_handle=0x%lx\n", (unsigned long)sshandle);

    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked lock and exiting get_shared_secret\n");
    return sshandle;

err_invalid_handle:
    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked lock in error path of get_shared_secret\n");
    return DDS_SECURITY_HANDLE_NIL;
}

DDS_Security_boolean get_authenticated_peer_credential_token(
    dds_security_authentication *instance,
    DDS_Security_AuthenticatedPeerCredentialToken *peer_credential_token,
    const DDS_Security_HandshakeHandle handshake_handle, DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering get_authenticated_peer_credential_token (handshake_handle=0x%lx)\n",
              (unsigned long)handshake_handle);

    if (!instance || !handshake_handle || !peer_credential_token) {
        DBG_ERR("Invalid parameter provided to get_authenticated_peer_credential_token\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                   DDS_SECURITY_ERR_INVALID_PARAMETER_CODE, 0,
                                   DDS_SECURITY_ERR_INVALID_PARAMETER_MESSAGE);
        return false;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    HandshakeInfo *handshake = NULL;
    X509 *identity_cert;
    char *permissions_doc;
    unsigned char *cert_data;
    uint32_t cert_data_size;

    ddsrt_mutex_lock(&impl->lock);
    DBG_TRACE("Acquired lock in get_authenticated_peer_credential_token\n");

    handshake = (HandshakeInfo *)security_object_find(impl->objectHash, handshake_handle);
    if (!handshake ||
        !security_object_valid((SecurityObject *)handshake, SECURITY_OBJECT_KIND_HANDSHAKE)) {
        DBG_ERR("Invalid handshake_handle provided to get_authenticated_peer_credential_token\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                   DDS_SECURITY_ERR_INVALID_PARAMETER_CODE, 0,
                                   DDS_SECURITY_ERR_INVALID_PARAMETER_MESSAGE);
        goto err_inv_handle;
    }
    DBG_TRACE("Found handshake object=0x%p\n", (void *)handshake);

    identity_cert = handshake->relation->remoteIdentity->identityCert;
    if (!identity_cert) {
        DBG_ERR("Missing remote identity certificate in handshake\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                   DDS_SECURITY_ERR_OPERATION_NOT_PERMITTED_CODE, 0,
                                   DDS_SECURITY_ERR_OPERATION_NOT_PERMITTED_MESSAGE);
        goto err_missing_attr;
    }
    DBG_TRACE("Obtained remote identity certificate\n");

    permissions_doc = handshake->relation->remoteIdentity->permissionsDocument;
    if (!permissions_doc) {
        DBG_ERR("Missing remote permissions document in handshake\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                   DDS_SECURITY_ERR_MISSING_REMOTE_PERMISSIONS_DOCUMENT_CODE, 0,
                                   DDS_SECURITY_ERR_MISSING_REMOTE_PERMISSIONS_DOCUMENT_MESSAGE);
        goto err_missing_attr;
    }
    DBG_TRACE("Obtained remote permissions document\n");

    if (get_certificate_contents(identity_cert, &cert_data, &cert_data_size, ex) !=
        DDS_SECURITY_VALIDATION_OK) {
        DBG_ERR("Failed to get certificate contents in get_authenticated_peer_credential_token\n");
        goto err_alloc_cid;
    }
    DBG_TRACE("Extracted certificate contents (size=%u bytes)\n", cert_data_size);

    memset(peer_credential_token, 0, sizeof(*peer_credential_token));
    peer_credential_token->class_id = ddsrt_strdup(DDS_SECURITY_AUTH_TOKEN_CLASS_ID);
    peer_credential_token->properties._length = 2;
    peer_credential_token->properties._buffer =
        DDS_Security_PropertySeq_allocbuf(peer_credential_token->properties._length);

    peer_credential_token->properties._buffer[0].name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_C_ID);
    peer_credential_token->properties._buffer[0].value = (char *)cert_data;
    peer_credential_token->properties._buffer[0].propagate = false;

    peer_credential_token->properties._buffer[1].name = ddsrt_strdup(DDS_AUTHTOKEN_PROP_C_PERM);
    peer_credential_token->properties._buffer[1].value = ddsrt_strdup(permissions_doc);
    peer_credential_token->properties._buffer[1].propagate = false;

    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Populated peer credential token and unlocked lock\n");
    return true;

err_alloc_cid:
err_missing_attr:
err_inv_handle:
    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked lock in error path of get_authenticated_peer_credential_token\n");
    return false;
}

DDS_Security_boolean set_listener(dds_security_authentication *instance,
                                  const dds_security_authentication_listener *listener,
                                  DDS_Security_SecurityException *ex) {
    DDSRT_UNUSED_ARG(ex);
    dds_security_authentication_impl *auth = (dds_security_authentication_impl *)instance;
    DBG_TRACE("Entering set_listener (listener=0x%p)\n", (void *)listener);

    auth->listener = listener;
    if (listener) {
        dds_security_timed_dispatcher_enable(auth->dispatcher);
        DBG_TRACE("Enabled timed dispatcher\n");
    } else {
        (void)dds_security_timed_dispatcher_disable(auth->dispatcher);
        DBG_TRACE("Disabled timed dispatcher\n");
    }
    return true;
}

DDS_Security_boolean return_identity_token(dds_security_authentication *instance,
                                           const DDS_Security_IdentityToken *token,
                                           DDS_Security_SecurityException *ex) {
    DDSRT_UNUSED_ARG(token);
    DDSRT_UNUSED_ARG(ex);
    DDSRT_UNUSED_ARG(instance);
    DBG_TRACE("return_identity_token called (no action)\n");
    return true;
}

DDS_Security_boolean return_identity_status_token(dds_security_authentication *instance,
                                                  const DDS_Security_IdentityStatusToken *token,
                                                  DDS_Security_SecurityException *ex) {
    DDSRT_UNUSED_ARG(token);
    DDSRT_UNUSED_ARG(ex);
    DDSRT_UNUSED_ARG(instance);
    DBG_TRACE("return_identity_status_token called (no action)\n");
    return true;
}

DDS_Security_boolean return_authenticated_peer_credential_token(
    dds_security_authentication *instance,
    const DDS_Security_AuthenticatedPeerCredentialToken *peer_credential_token,
    DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering return_authenticated_peer_credential_token\n");
    if (!instance || !peer_credential_token) {
        DBG_ERR("Invalid parameter provided to return_authenticated_peer_credential_token\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT,
                                   DDS_SECURITY_ERR_INVALID_PARAMETER_CODE, 0,
                                   DDS_SECURITY_ERR_INVALID_PARAMETER_MESSAGE);
        return false;
    }
    DDS_Security_DataHolder_deinit((DDS_Security_DataHolder *)peer_credential_token);
    DBG_TRACE("Deinitialized peer_credential_token\n");
    return true;
}

DDS_Security_boolean return_handshake_handle(dds_security_authentication *instance,
                                             const DDS_Security_HandshakeHandle handshake_handle,
                                             DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering return_handshake_handle (handshake_handle=0x%lx)\n",
              (unsigned long)handshake_handle);

    if (!instance || !handshake_handle) {
        DBG_ERR("Invalid parameter provided to return_handshake_handle\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "return_handshake_handle: Invalid parameter provided");
        return false;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    ddsrt_mutex_lock(&impl->lock);
    DBG_TRACE("Acquired lock in return_handshake_handle\n");

    SecurityObject *obj = security_object_find(impl->objectHash, handshake_handle);
    if (!obj || !security_object_valid(obj, SECURITY_OBJECT_KIND_HANDSHAKE)) {
        DBG_ERR("Invalid handshake_handle provided to return_handshake_handle\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "return_handshake_handle: Invalid handle provided");
        goto err_invalid_handle;
    }

    HandshakeInfo *handshake = (HandshakeInfo *)obj;
    assert(handshake->relation);
    DBG_TRACE("Found handshake object=0x%p, removing it\n", (void *)handshake);
    (void)ddsrt_hh_remove(impl->objectHash, obj);
    security_object_free((SecurityObject *)handshake);

    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked lock and exiting return_handshake_handle\n");
    return true;

err_invalid_handle:
    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked lock in error path of return_handshake_handle\n");
    return false;
}

static void invalidate_local_related_objects(dds_security_authentication_impl *impl,
                                             LocalIdentityInfo *localIdent) {
    DBG_TRACE("Entering invalidate_local_related_objects for localIdentity=0x%p\n",
              (void *)localIdent);

    struct ddsrt_hh_iter it;
    SecurityObject *obj;

    for (obj = ddsrt_hh_iter_first(impl->objectHash, &it); obj != NULL;
         obj = ddsrt_hh_iter_next(&it)) {
        if (obj->kind == SECURITY_OBJECT_KIND_REMOTE_IDENTITY) {
            RemoteIdentityInfo *remoteIdent = (RemoteIdentityInfo *)obj;
            HandshakeInfo *handshake = find_handshake(impl, SECURITY_OBJECT_HANDLE(localIdent),
                                                      SECURITY_OBJECT_HANDLE(remoteIdent));
            if (handshake) {
                DBG_TRACE("Removing handshake object=0x%p between local=0x%p and remote=0x%p\n",
                          (void *)handshake, (void *)localIdent, (void *)remoteIdent);
                (void)ddsrt_hh_remove(impl->objectHash, handshake);
                security_object_free((SecurityObject *)handshake);
            }
            IdentityRelation *relation =
                find_identity_relation(remoteIdent, SECURITY_OBJECT_HANDLE(localIdent));
            if (relation) {
                DBG_TRACE("Removing identity relation=0x%p for remote=0x%p and local=0x%p\n",
                          (void *)relation, (void *)remoteIdent, (void *)localIdent);
                remove_identity_relation(remoteIdent, relation);
            }
        }
    }

    DBG_TRACE("Completed invalidate_local_related_objects for localIdentity=0x%p\n",
              (void *)localIdent);
}

static void invalidate_remote_related_objects(dds_security_authentication_impl *impl,
                                              RemoteIdentityInfo *remoteIdentity) {
    DBG_TRACE("Entering invalidate_remote_related_objects for remoteIdentity=0x%p\n",
              (void *)remoteIdentity);

    struct ddsrt_hh_iter it;
    for (IdentityRelation *relation = ddsrt_hh_iter_first(remoteIdentity->linkHash, &it);
         relation != NULL; relation = ddsrt_hh_iter_next(&it)) {
        HandshakeInfo *handshake =
            find_handshake(impl, SECURITY_OBJECT_HANDLE(relation->localIdentity),
                           SECURITY_OBJECT_HANDLE(remoteIdentity));
        if (handshake) {
            DBG_TRACE("Removing handshake object=0x%p for local=0x%p and remote=0x%p\n",
                      (void *)handshake, (void *)relation->localIdentity, (void *)remoteIdentity);
            (void)ddsrt_hh_remove(impl->objectHash, handshake);
            security_object_free((SecurityObject *)handshake);
        }
        DBG_TRACE("Removing identity relation=0x%p from remoteIdentity->linkHash\n",
                  (void *)relation);
        (void)ddsrt_hh_remove(remoteIdentity->linkHash, relation);
        security_object_free((SecurityObject *)relation);
    }

    DBG_TRACE("Completed invalidate_remote_related_objects for remoteIdentity=0x%p\n",
              (void *)remoteIdentity);
}

DDS_Security_boolean return_identity_handle(dds_security_authentication *instance,
                                            const DDS_Security_IdentityHandle identity_handle,
                                            DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering return_identity_handle (handle=0x%lx)\n", (unsigned long)identity_handle);

    if (!instance || !identity_handle) {
        DBG_ERR("Invalid parameter provided to return_identity_handle\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "return_identity_handle: Invalid parameter provided");
        return false;
    }

    dds_security_authentication_impl *impl = (dds_security_authentication_impl *)instance;
    SecurityObject *obj;
    LocalIdentityInfo *localIdent;
    RemoteIdentityInfo *remoteIdent;

    /* The handle could refer to a LocalIdentityObject or a RemoteIdentityObject */
    ddsrt_mutex_lock(&impl->lock);
    DBG_TRACE("Acquired lock for return_identity_handle\n");

    obj = security_object_find(impl->objectHash, identity_handle);
    if (!obj) {
        DBG_ERR("Invalid handle provided to return_identity_handle\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "return_identity_handle: Invalid handle provided");
        goto failed;
    }

    switch (obj->kind) {
    case SECURITY_OBJECT_KIND_LOCAL_IDENTITY:
        localIdent = (LocalIdentityInfo *)obj;
        DBG_TRACE("Returning local identity object=0x%p\n", (void *)localIdent);
        if (localIdent->timer != 0) {
            DBG_TRACE("Removing timer %lu for local identity\n", localIdent->timer);
            dds_security_timed_dispatcher_remove(impl->dispatcher, localIdent->timer);
        }
        invalidate_local_related_objects(impl, localIdent);
        DBG_TRACE("Removing local identity object from objectHash\n");
        (void)ddsrt_hh_remove(impl->objectHash, obj);
        security_object_free(obj);
        break;

    case SECURITY_OBJECT_KIND_REMOTE_IDENTITY:
        remoteIdent = (RemoteIdentityInfo *)obj;
        DBG_TRACE("Returning remote identity object=0x%p\n", (void *)remoteIdent);
        if (remoteIdent->timer != 0) {
            DBG_TRACE("Removing timer %lu for remote identity\n", remoteIdent->timer);
            dds_security_timed_dispatcher_remove(impl->dispatcher, remoteIdent->timer);
        }
        invalidate_remote_related_objects(impl, remoteIdent);
        DBG_TRACE("Removing remote identity from remoteGuidHash and objectHash\n");
        (void)ddsrt_hh_remove(impl->remoteGuidHash, remoteIdent);
        (void)ddsrt_hh_remove(impl->objectHash, obj);
        security_object_free(obj);
        break;

    default:
        DBG_ERR("Invalid object kind in return_identity_handle\n");
        DDS_Security_Exception_set(ex, DDS_AUTH_PLUGIN_CONTEXT, DDS_SECURITY_ERR_UNDEFINED_CODE,
                                   DDS_SECURITY_VALIDATION_FAILED,
                                   "return_identity_handle: Invalid handle provided");
        goto failed;
    }

    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked impl->lock and exiting return_identity_handle\n");
    return true;

failed:
    ddsrt_mutex_unlock(&impl->lock);
    DBG_TRACE("Unlocked impl->lock in error path of return_identity_handle\n");
    return false;
}

DDS_Security_boolean
return_sharedsecret_handle(dds_security_authentication *instance,
                           const DDS_Security_SharedSecretHandle sharedsecret_handle,
                           DDS_Security_SecurityException *ex) {
    DBG_TRACE("Entering return_sharedsecret_handle (handle=0x%lx)\n",
              (unsigned long)sharedsecret_handle);

    /* No actual cleanup needed for shared secrets in this implementation */
    DBG_TRACE("return_sharedsecret_handle: no action required, returning true\n");
    DDSRT_UNUSED_ARG(sharedsecret_handle);
    DDSRT_UNUSED_ARG(ex);
    DDSRT_UNUSED_ARG(instance);
    return true;
}

int32_t init_authentication(const char *argument, void **context, struct ddsi_domaingv *gv) {
    DBG_INFO("Entering init_authentication\n");
    DBG_INFO("  Compile-time selected KEM: %s\n", get_default_kem_name());
    DBG_INFO("  Default KEM algorithm kind: %d\n", get_default_kem_algorithm_kind());
    DBG_INFO("  Default KEM OpenSSL name: %s\n", get_default_kem_openssl_name());
    DDSRT_UNUSED_ARG(argument);

    dds_security_authentication_impl *authentication =
        (dds_security_authentication_impl *)ddsrt_malloc(sizeof(dds_security_authentication_impl));
    if (!authentication) {
        DBG_ERR("Failed to allocate dds_security_authentication_impl\n");
        return -1;
    }
    memset(authentication, 0, sizeof(dds_security_authentication_impl));
    DBG_TRACE("Allocated and zeroed authentication at %p\n", (void *)authentication);

    authentication->base.gv = gv;
    authentication->listener = NULL;
    authentication->dispatcher = dds_security_timed_dispatcher_new(gv->xevents);
    DBG_TRACE("Created timed dispatcher at %p\n", (void *)authentication->dispatcher);

    authentication->base.validate_local_identity = &validate_local_identity;
    authentication->base.get_identity_token = &get_identity_token;
    authentication->base.get_identity_status_token = &get_identity_status_token;
    authentication->base.set_permissions_credential_and_token =
        &set_permissions_credential_and_token;
    authentication->base.validate_remote_identity = &validate_remote_identity;
    authentication->base.begin_handshake_request = &begin_handshake_request;
    authentication->base.begin_handshake_reply = &begin_handshake_reply;
    authentication->base.process_handshake = &process_handshake;
    authentication->base.get_shared_secret = &get_shared_secret;
    authentication->base.get_authenticated_peer_credential_token =
        &get_authenticated_peer_credential_token;
    authentication->base.set_listener = &set_listener;
    authentication->base.return_identity_token = &return_identity_token;
    authentication->base.return_identity_status_token = &return_identity_status_token;
    authentication->base.return_authenticated_peer_credential_token =
        &return_authenticated_peer_credential_token;
    authentication->base.return_handshake_handle = &return_handshake_handle;
    authentication->base.return_identity_handle = &return_identity_handle;
    authentication->base.return_sharedsecret_handle = &return_sharedsecret_handle;
    DBG_TRACE("Assigned function pointers in authentication->base\n");

    ddsrt_mutex_init(&authentication->lock);
    DBG_TRACE("Initialized mutex at %p\n", (void *)&authentication->lock);

    authentication->objectHash = ddsrt_hh_new(32, security_object_hash, security_object_equal);
    authentication->remoteGuidHash = ddsrt_hh_new(32, remote_guid_hash, remote_guid_equal);
    DBG_TRACE("Created objectHash at %p and remoteGuidHash at %p\n",
              (void *)authentication->objectHash, (void *)authentication->remoteGuidHash);

    memset(&authentication->trustedCAList, 0, sizeof(X509Seq));
    authentication->include_optional = gv->handshake_include_optional;
    DBG_TRACE("Set include_optional = %d\n", authentication->include_optional);

    pq_debug_init();
    DBG_INFO("PQ debug initialized\n");

    dds_openssl_init();
    DBG_TRACE("OpenSSL initialized\n");

#ifdef PQ_CRYPTO
    authentication->oqs_libctx = NULL;
    authentication->oqs_provider_available = false;
    const char *provider_name = get_oqs_provider_name();
    const char *config_file = get_oqs_config_file();
    DBG_TRACE("Attempting to load OQS provider '%s' with config '%s'\n", provider_name,
              config_file ? config_file : "NULL");

    authentication->oqs_provider_available =
        load_oqs_provider_to_context(&authentication->oqs_libctx, provider_name, config_file);

    if (authentication->oqs_provider_available) {
        DBG_INFO("OQS provider initialized for authentication instance\n");
    } else {
        DBG_WARN("OQS provider not available, falling back to classical crypto\n");
    }
#endif

    *context = authentication;
    DBG_INFO("init_authentication completed, returning success\n");
    return 0;
}

int32_t finalize_authentication(void *instance) {
    DBG_INFO("Entering finalize_authentication\n");
    dds_security_authentication_impl *authentication = (dds_security_authentication_impl *)instance;
    if (authentication) {
        ddsrt_mutex_lock(&authentication->lock);
        DBG_TRACE("Acquired lock for finalize_authentication\n");

        shm_finalize(); /* Deleting the shared memory */
        DBG_TRACE("shm_finalize called\n");

#ifdef PQ_CRYPTO
        if (authentication->oqs_libctx) {
            DBG_TRACE("Freeing OQS library context\n");
            OSSL_LIB_CTX_free(authentication->oqs_libctx);
            authentication->oqs_libctx = NULL;
            authentication->oqs_provider_available = false;
            DBG_TRACE("OQS library context freed\n");
        }
#endif

        dds_security_timed_dispatcher_free(authentication->dispatcher);
        DBG_TRACE("Timed dispatcher freed\n");

        if (authentication->remoteGuidHash) {
            DBG_TRACE("Freeing remoteGuidHash\n");
            ddsrt_hh_free(authentication->remoteGuidHash);
        }
        if (authentication->objectHash) {
            DBG_TRACE("Freeing objects in objectHash\n");
            struct ddsrt_hh_iter it;
            for (SecurityObject *obj = ddsrt_hh_iter_first(authentication->objectHash, &it);
                 obj != NULL; obj = ddsrt_hh_iter_next(&it)) {
                DBG_TRACE("Freeing SecurityObject at %p\n", (void *)obj);
                security_object_free(obj);
            }
            ddsrt_hh_free(authentication->objectHash);
            DBG_TRACE("objectHash freed\n");
        }

        free_ca_list_contents(&(authentication->trustedCAList));
        DBG_TRACE("Freed trusted CA list contents\n");

        ddsrt_mutex_unlock(&authentication->lock);
        DBG_TRACE("Unlocked lock for finalize_authentication\n");

        ddsrt_mutex_destroy(&authentication->lock);
        DBG_TRACE("Destroyed mutex\n");

        ddsrt_free(authentication);
        DBG_INFO("Freed authentication instance\n");
    }
    DBG_INFO("finalize_authentication completed\n");
    return 0;
}
