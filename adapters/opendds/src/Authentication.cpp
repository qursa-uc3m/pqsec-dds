/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Authentication.h"

#include "Transcript.h"

#include <dds/DCPS/LocalObject.h>
#include <dds/DCPS/Serializer.h>
#include <dds/DCPS/RTPS/RtpsCoreC.h>
#include <dds/DCPS/RTPS/RtpsCoreTypeSupportImpl.h>
#include <dds/DCPS/security/CommonUtilities.h>
#include <dds/DCPS/security/TokenReader.h>
#include <dds/DCPS/security/TokenWriter.h>
#include <dds/DCPS/security/SSL/Utils.h>
#include <dds/DCPS/security/framework/Properties.h>

#include <cstring>
#include <cstdlib>
#include <utility>

#include <openssl/crypto.h>

namespace OpenDDS_PQSec {

namespace {

// Custom token class IDs use a project-controlled namespace instead of the
// DDS:* namespace reserved for algorithms standardized by OMG.
const char BASE_CLASS_ID[] = "pqsec-dds.auth:1.0";
const char AUTH_REQUEST_CLASS_ID[] = "pqsec-dds.auth:1.0+AuthReq";
const char REQUEST_CLASS_ID[] = "pqsec-dds.auth:1.0+Req";
const char REPLY_CLASS_ID[] = "pqsec-dds.auth:1.0+Reply";
const char FINAL_CLASS_ID[] = "pqsec-dds.auth:1.0+Final";
const char DEFAULT_KEM[] = "X25519MLKEM768";
const char KEM_PROPERTY[] = "pqsec-dds.kem";
const char PROVIDER_PROPERTY[] = "pqsec-dds.provider";
const char KEM_PUBLIC_PROPERTY[] = "pqsec-dds.kem_public";
const char KEM_CIPHERTEXT_PROPERTY[] = "pqsec-dds.kem_ciphertext";

void fail(DDS::Security::SecurityException& ex, const std::string& message) {
  OpenDDS::Security::CommonUtilities::set_security_error(ex, -1, 0, message.c_str());
}

bool class_is(const DDS::Security::Token& token, const char* expected) {
  return std::strcmp(token.class_id.in(), expected) == 0;
}

std::string string_value(const DDS::OctetSeq& value) {
  if (!value.length() || value[value.length() - 1] != 0)
    return std::string();
  return std::string(reinterpret_cast<const char*>(value.get_buffer()));
}

bool mldsa_algorithm(const std::string& value) {
  return value == "ML-DSA-44" || value == "ML-DSA-65" || value == "ML-DSA-87";
}

bool kem_algorithm(const std::string& value) {
  return value == "ML-KEM-512" || value == "ML-KEM-768" || value == "ML-KEM-1024" ||
         value == "X25519MLKEM768" || value == "SecP256r1MLKEM768" || value == "frodo640shake" ||
         value == "bikel1" || value == "hqc128";
}

bool initiator(const OpenDDS::DCPS::GUID_t& local, const OpenDDS::DCPS::GUID_t& remote) {
  return local < remote;
}

bool cert_matches_guid(const OpenDDS::Security::SSL::Certificate& certificate,
                       const OpenDDS::DCPS::GUID_t& guid) {
  std::vector<CORBA::Octet> digest;
  if (certificate.subject_name_digest(digest) || digest.size() < 6)
    return false;
  const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&guid);
  if ((bytes[0] & 0x80) != 0x80 ||
      (bytes[0] & 0x7f) != OpenDDS::Security::SSL::offset_1bit(&digest[0], 0))
    return false;
  for (size_t i = 1; i != 6; ++i) {
    if (bytes[i] != OpenDDS::Security::SSL::offset_1bit(&digest[0], i))
      return false;
  }
  return true;
}

bool participant_data_has_guid(const DDS::OctetSeq& data, const OpenDDS::DCPS::GUID_t& expected) {
  ACE_Message_Block buffer(reinterpret_cast<const char*>(data.get_buffer()), data.length());
  buffer.wr_ptr(data.length());
  OpenDDS::DCPS::Serializer serializer(&buffer, OpenDDS::DCPS::Encoding::KIND_XCDR1,
                                       OpenDDS::DCPS::ENDIAN_BIG);
  OpenDDS::RTPS::ParameterList parameters;
  if (!(serializer >> parameters))
    return false;
  for (CORBA::ULong i = 0; i != parameters.length(); ++i) {
    if (parameters[i]._d() == OpenDDS::RTPS::PID_PARTICIPANT_GUID) {
      return parameters[i].guid() == expected;
    }
  }
  return false;
}

class SharedSecret : public OpenDDS::DCPS::LocalObject<DDS::Security::SharedSecretHandle> {
public:
  SharedSecret(const DDS::OctetSeq& challenge1, const DDS::OctetSeq& challenge2,
               const DDS::OctetSeq& secret)
      : challenge1_(challenge1), challenge2_(challenge2), secret_(secret) {}

  ~SharedSecret() {
    if (secret_.length())
      OPENSSL_cleanse(secret_.get_buffer(), secret_.length());
  }

  DDS::OctetSeq* challenge1() {
    return new DDS::OctetSeq(challenge1_);
  }
  DDS::OctetSeq* challenge2() {
    return new DDS::OctetSeq(challenge2_);
  }
  DDS::OctetSeq* sharedSecret() {
    return new DDS::OctetSeq(secret_);
  }

private:
  DDS::OctetSeq challenge1_, challenge2_, secret_;
};

} // namespace

struct Authentication::LocalIdentity {
  OpenDDS::Security::LocalAuthCredentialData::shared_ptr credentials;
  OpenDDS::DCPS::GUID_t guid;
  std::string kem_algorithm;
};

struct Authentication::RemoteIdentity {
  RemoteIdentity() : local_handle(DDS::HANDLE_NIL), local_auth_request_sent(false) {}
  DDS::Security::IdentityHandle local_handle;
  OpenDDS::DCPS::GUID_t guid;
  DDS::Security::AuthRequestMessageToken local_auth_request;
  DDS::Security::AuthRequestMessageToken remote_auth_request;
  DDS::OctetSeq local_challenge;
  DDS::OctetSeq remote_challenge;
  bool local_auth_request_sent;
};

struct Authentication::Handshake {
  Handshake() : initiator(false), state(DDS::Security::VALIDATION_FAILED), kem(DEFAULT_KEM) {}
  ~Handshake() {
    if (secret.length())
      OPENSSL_cleanse(secret.get_buffer(), secret.length());
  }
  bool initiator;
  DDS::Security::ValidationResult_t state;
  DDS::Security::IdentityHandle local_handle;
  DDS::Security::IdentityHandle remote_handle;
  LocalPtr local;
  RemotePtr remote;
  Kem kem;
  DDS::Security::HandshakeMessageToken request;
  DDS::Security::HandshakeMessageToken reply;
  DDS::OctetSeq hash1, hash2, challenge1, challenge2, public_key, ciphertext, secret;
  std::unique_ptr<OpenDDS::Security::SSL::Certificate> remote_certificate;
  DDS::OctetSeq remote_permissions;
};

Authentication::Authentication() : next_handle_(1) {}

Authentication::~Authentication() {}

CORBA::Long Authentication::next_handle() {
  return next_handle_++;
}

Authentication::LocalPtr Authentication::local(DDS::Security::IdentityHandle handle) const {
  std::map<DDS::Security::IdentityHandle, LocalPtr>::const_iterator pos = locals_.find(handle);
  return pos == locals_.end() ? LocalPtr() : pos->second;
}

Authentication::RemotePtr Authentication::remote(DDS::Security::IdentityHandle handle) const {
  std::map<DDS::Security::IdentityHandle, RemotePtr>::const_iterator pos = remotes_.find(handle);
  return pos == remotes_.end() ? RemotePtr() : pos->second;
}

DDS::Security::ValidationResult_t Authentication::validate_local_identity(
    DDS::Security::IdentityHandle& handle, OpenDDS::DCPS::GUID_t& adjusted,
    DDS::Security::DomainId_t, const DDS::DomainParticipantQos& qos,
    const OpenDDS::DCPS::GUID_t& candidate, DDS::Security::SecurityException& ex) {
  OpenDDS::Security::LocalAuthCredentialData::shared_ptr credentials =
      OpenDDS::DCPS::make_rch<OpenDDS::Security::LocalAuthCredentialData>();
  if (!credentials->load_credentials(qos.property.value, ex) || !credentials->validate()) {
    fail(ex, "PQSec failed to load or validate local credentials");
    return DDS::Security::VALIDATION_FAILED;
  }
  const std::string signature_algorithm = credentials->get_participant_cert().dsign_algo();
  if (!mldsa_algorithm(signature_algorithm)) {
    fail(ex, "PQSec requires an ML-DSA identity certificate");
    return DDS::Security::VALIDATION_FAILED;
  }

  std::string selected_kem = DEFAULT_KEM;
  std::string selected_provider = "oqsprovider";
  const char* environment_provider = std::getenv("PQSEC_OPENSSL_PROVIDER");
  if (environment_provider)
    selected_provider = environment_provider;
  for (CORBA::ULong i = 0; i != qos.property.value.length(); ++i) {
    if (std::strcmp(qos.property.value[i].name.in(), KEM_PROPERTY) == 0) {
      selected_kem = qos.property.value[i].value.in();
    } else if (std::strcmp(qos.property.value[i].name.in(), PROVIDER_PROPERTY) == 0) {
      selected_provider = qos.property.value[i].value.in();
    }
  }
  std::string provider_error;
  if (!kem_algorithm(selected_kem)) {
    fail(ex, "PQSec requested an unsupported KEM algorithm: " + selected_kem);
    return DDS::Security::VALIDATION_FAILED;
  }
  if (!fallback_provider_.ensure_algorithm(selected_kem, provider_error, selected_provider)) {
    fail(ex, "PQSec requested an unavailable KEM algorithm: " + provider_error);
    return DDS::Security::VALIDATION_FAILED;
  }
  if (OpenDDS::Security::SSL::make_adjusted_guid(candidate, adjusted,
                                                 credentials->get_participant_cert())) {
    fail(ex, "PQSec failed to derive the adjusted participant GUID");
    return DDS::Security::VALIDATION_FAILED;
  }

  LocalPtr identity(new LocalIdentity);
  identity->credentials = credentials;
  identity->guid = adjusted;
  identity->kem_algorithm = selected_kem;
  std::lock_guard<std::mutex> guard(mutex_);
  handle = next_handle();
  locals_[handle] = identity;
  return DDS::Security::VALIDATION_OK;
}

CORBA::Boolean Authentication::get_identity_token(DDS::Security::IdentityToken& token,
                                                  DDS::Security::IdentityHandle handle,
                                                  DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  LocalPtr identity = local(handle);
  if (!identity) {
    fail(ex, "Unknown local identity");
    return false;
  }
  OpenDDS::Security::TokenWriter writer(token, BASE_CLASS_ID);
  std::string subject, ca_subject;
  identity->credentials->get_participant_cert().subject_name_to_str(subject);
  identity->credentials->get_ca_cert().subject_name_to_str(ca_subject);
  writer.add_property("dds.cert.sn", subject.c_str());
  writer.add_property("dds.cert.algo",
                      identity->credentials->get_participant_cert().keypair_algo());
  writer.add_property("dds.ca.sn", ca_subject.c_str());
  writer.add_property("dds.ca.algo", identity->credentials->get_ca_cert().keypair_algo());
  return true;
}

CORBA::Boolean Authentication::get_identity_status_token(DDS::Security::IdentityStatusToken&,
                                                         DDS::Security::IdentityHandle handle,
                                                         DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!local(handle)) {
    fail(ex, "Unknown local identity");
    return false;
  }
  return true;
}

CORBA::Boolean Authentication::set_permissions_credential_and_token(
    DDS::Security::IdentityHandle handle,
    const DDS::Security::PermissionsCredentialToken& credential,
    const DDS::Security::PermissionsToken&, DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  LocalPtr identity = local(handle);
  if (!identity) {
    fail(ex, "Unknown local identity");
    return false;
  }
  return identity->credentials->load_access_permissions(credential, ex);
}

DDS::Security::ValidationResult_t Authentication::validate_remote_identity(
    DDS::Security::IdentityHandle& remote_handle,
    DDS::Security::AuthRequestMessageToken& local_request,
    const DDS::Security::AuthRequestMessageToken& remote_request,
    DDS::Security::IdentityHandle local_handle, const DDS::Security::IdentityToken& identity_token,
    const OpenDDS::DCPS::GUID_t& remote_guid, DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  LocalPtr local_identity = local(local_handle);
  if (!local_identity || !class_is(identity_token, BASE_CLASS_ID)) {
    fail(ex, "Unknown local identity or incompatible remote authentication plugin");
    return DDS::Security::VALIDATION_FAILED;
  }

  RemotePtr identity;
  if (remote_handle != DDS::HANDLE_NIL)
    identity = remote(remote_handle);
  if (identity && (identity->local_handle != local_handle || identity->guid != remote_guid)) {
    fail(ex, "Remote identity handle does not match the supplied participants");
    return DDS::Security::VALIDATION_FAILED;
  }
  if (!identity) {
    identity.reset(new RemoteIdentity);
    identity->local_handle = local_handle;
    identity->guid = remote_guid;
    if (OpenDDS::Security::SSL::make_nonce_256(identity->local_challenge)) {
      fail(ex, "Failed to generate PQSec AuthRequest challenge");
      return DDS::Security::VALIDATION_FAILED;
    }
    OpenDDS::Security::TokenWriter writer(identity->local_auth_request, AUTH_REQUEST_CLASS_ID);
    writer.add_bin_property("future_challenge", identity->local_challenge);
    remote_handle = next_handle();
    remotes_[remote_handle] = identity;
  }
  identity->remote_auth_request = remote_request;
  OpenDDS::Security::TokenReader remote_reader(remote_request);
  if (!remote_reader.is_nil() && !class_is(remote_request, AUTH_REQUEST_CLASS_ID)) {
    fail(ex, "Incompatible PQSec AuthRequest token");
    return DDS::Security::VALIDATION_FAILED;
  }
  identity->remote_challenge = remote_reader.get_bin_property_value("future_challenge");
  if (!remote_reader.is_nil() && identity->remote_challenge.length() != 32) {
    fail(ex, "PQSec AuthRequest challenge must contain 256 bits");
    return DDS::Security::VALIDATION_FAILED;
  }
  if (remote_reader.is_nil()) {
    identity->local_auth_request_sent = true;
    local_request = identity->local_auth_request;
  } else {
    local_request = DDS::Security::Token();
  }

  return initiator(local_identity->guid, remote_guid)
             ? DDS::Security::VALIDATION_PENDING_HANDSHAKE_REQUEST
             : DDS::Security::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
}

DDS::Security::ValidationResult_t Authentication::begin_handshake_request(
    DDS::Security::HandshakeHandle& handle, DDS::Security::HandshakeMessageToken& message,
    DDS::Security::IdentityHandle initiator_handle, DDS::Security::IdentityHandle replier_handle,
    const DDS::OctetSeq& participant_data, DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  LocalPtr local_identity = local(initiator_handle);
  RemotePtr remote_identity = remote(replier_handle);
  if (!local_identity || !remote_identity || participant_data.length() == 0) {
    fail(ex, "Invalid identities or participant data for PQSec handshake request");
    return DDS::Security::VALIDATION_FAILED;
  }

  HandshakePtr hs(new Handshake);
  hs->initiator = true;
  hs->state = DDS::Security::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
  hs->local_handle = initiator_handle;
  hs->remote_handle = replier_handle;
  hs->local = local_identity;
  hs->remote = remote_identity;
  hs->kem = Kem(local_identity->kem_algorithm);
  std::string error;
  std::vector<unsigned char> key;
  if (!hs->kem.generate(error) || !hs->kem.public_key(key, error)) {
    fail(ex, error);
    return DDS::Security::VALIDATION_FAILED;
  }
  hs->public_key = octets(key);
  if (remote_identity->local_auth_request_sent) {
    hs->challenge1 = remote_identity->local_challenge;
  } else if (OpenDDS::Security::SSL::make_nonce_256(hs->challenge1)) {
    fail(ex, "Failed to generate PQSec request challenge");
    return DDS::Security::VALIDATION_FAILED;
  }

  const OpenDDS::Security::SSL::Certificate& certificate =
      local_identity->credentials->get_participant_cert();
  if (credential_hash(certificate.original_bytes(),
                      local_identity->credentials->get_access_permissions(), participant_data,
                      certificate.dsign_algo(), local_identity->kem_algorithm, hs->hash1)) {
    fail(ex, "Failed to hash PQSec request credentials");
    return DDS::Security::VALIDATION_FAILED;
  }
  OpenDDS::Security::TokenWriter writer(message, REQUEST_CLASS_ID);
  writer.add_bin_property("c.id", certificate.original_bytes());
  writer.add_bin_property("c.perm", local_identity->credentials->get_access_permissions());
  writer.add_bin_property("c.pdata", participant_data);
  writer.add_bin_property("c.dsign_algo", certificate.dsign_algo());
  writer.add_bin_property("c.kagree_algo", local_identity->kem_algorithm);
  writer.add_bin_property(KEM_PUBLIC_PROPERTY, hs->public_key);
  writer.add_bin_property("challenge1", hs->challenge1);
  hs->request = message;
  if (handle == DDS::HANDLE_NIL)
    handle = next_handle();
  handshakes_[handle] = hs;
  return DDS::Security::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
}

bool Authentication::validate_remote_credentials(Handshake& hs, const DDS::Security::Token& token,
                                                 DDS::OctetSeq& hash,
                                                 DDS::Security::SecurityException& ex) {
  OpenDDS::Security::TokenReader reader(token);
  const DDS::OctetSeq& certificate_data = reader.get_bin_property_value("c.id");
  const DDS::OctetSeq& permissions = reader.get_bin_property_value("c.perm");
  const DDS::OctetSeq& participant_data = reader.get_bin_property_value("c.pdata");
  const std::string signature_algorithm =
      string_value(reader.get_bin_property_value("c.dsign_algo"));
  const std::string selected_kem = string_value(reader.get_bin_property_value("c.kagree_algo"));
  if (!mldsa_algorithm(signature_algorithm) || selected_kem != hs.local->kem_algorithm) {
    fail(ex, "Unsupported or mismatched PQSec algorithms");
    return false;
  }
  std::unique_ptr<OpenDDS::Security::SSL::Certificate> certificate(
      new OpenDDS::Security::SSL::Certificate);
  if (certificate->deserialize(certificate_data) ||
      certificate->validate(hs.local->credentials->get_ca_cert()) != X509_V_OK ||
      certificate->dsign_algo() != signature_algorithm ||
      !cert_matches_guid(*certificate, hs.remote->guid) ||
      !participant_data_has_guid(participant_data, hs.remote->guid)) {
    fail(ex, "Remote ML-DSA certificate, adjusted GUID, or participant data is invalid");
    return false;
  }
  if (credential_hash(certificate_data, permissions, participant_data, signature_algorithm,
                      selected_kem, hash)) {
    fail(ex, "Failed to hash remote PQSec credentials");
    return false;
  }
  hs.remote_certificate = std::move(certificate);
  hs.remote_permissions = permissions;
  return true;
}

DDS::Security::ValidationResult_t Authentication::begin_handshake_reply(
    DDS::Security::HandshakeHandle& handle, DDS::Security::HandshakeMessageToken& message,
    DDS::Security::IdentityHandle initiator_handle, DDS::Security::IdentityHandle replier_handle,
    const DDS::OctetSeq& participant_data, DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  const DDS::Security::HandshakeMessageToken request = message;
  message = DDS::Security::Token();
  LocalPtr local_identity = local(replier_handle);
  RemotePtr remote_identity = remote(initiator_handle);
  if (!local_identity || !remote_identity || !class_is(request, REQUEST_CLASS_ID)) {
    fail(ex, "Invalid PQSec handshake request");
    return DDS::Security::VALIDATION_FAILED;
  }

  HandshakePtr hs(new Handshake);
  hs->local_handle = replier_handle;
  hs->remote_handle = initiator_handle;
  hs->local = local_identity;
  hs->remote = remote_identity;
  hs->kem = Kem(local_identity->kem_algorithm);
  hs->request = request;
  if (!validate_remote_credentials(*hs, request, hs->hash1, ex))
    return DDS::Security::VALIDATION_FAILED;
  OpenDDS::Security::TokenReader request_reader(request);
  hs->challenge1 = request_reader.get_bin_property_value("challenge1");
  hs->public_key = request_reader.get_bin_property_value(KEM_PUBLIC_PROPERTY);
  if (remote_identity->remote_challenge.length() &&
      !equal(hs->challenge1, remote_identity->remote_challenge)) {
    fail(ex, "PQSec request challenge does not match AuthRequest");
    return DDS::Security::VALIDATION_FAILED;
  }

  std::string error;
  std::vector<unsigned char> ciphertext, secret;
  if (!hs->kem.import_public(bytes(hs->public_key), error) ||
      !hs->kem.encapsulate(ciphertext, secret, error)) {
    fail(ex, error);
    return DDS::Security::VALIDATION_FAILED;
  }
  hs->ciphertext = octets(ciphertext);
  hs->secret = octets(secret);
  if (!secret.empty())
    OPENSSL_cleanse(&secret[0], secret.size());
  if (remote_identity->local_auth_request_sent) {
    hs->challenge2 = remote_identity->local_challenge;
  } else if (OpenDDS::Security::SSL::make_nonce_256(hs->challenge2)) {
    fail(ex, "Failed to generate PQSec reply challenge");
    return DDS::Security::VALIDATION_FAILED;
  }
  const OpenDDS::Security::SSL::Certificate& certificate =
      local_identity->credentials->get_participant_cert();
  if (credential_hash(certificate.original_bytes(),
                      local_identity->credentials->get_access_permissions(), participant_data,
                      certificate.dsign_algo(), local_identity->kem_algorithm, hs->hash2)) {
    fail(ex, "Failed to hash PQSec reply credentials");
    return DDS::Security::VALIDATION_FAILED;
  }

  DDS::BinaryPropertySeq transcript = reply_transcript(hs->hash2, hs->challenge2, hs->ciphertext,
                                                       hs->challenge1, hs->public_key, hs->hash1);
  DDS::OctetSeq signature;
  if (OpenDDS::Security::SSL::sign_serialized(
          transcript, local_identity->credentials->get_participant_private_key(), signature)) {
    fail(ex, "ML-DSA reply signature failed");
    return DDS::Security::VALIDATION_FAILED;
  }
  OpenDDS::Security::TokenWriter writer(message, REPLY_CLASS_ID);
  writer.add_bin_property("c.id", certificate.original_bytes());
  writer.add_bin_property("c.perm", local_identity->credentials->get_access_permissions());
  writer.add_bin_property("c.pdata", participant_data);
  writer.add_bin_property("c.dsign_algo", certificate.dsign_algo());
  writer.add_bin_property("c.kagree_algo", local_identity->kem_algorithm);
  writer.add_bin_property(KEM_CIPHERTEXT_PROPERTY, hs->ciphertext);
  writer.add_bin_property("challenge1", hs->challenge1);
  writer.add_bin_property("challenge2", hs->challenge2);
  writer.add_bin_property("signature", signature);
  hs->reply = message;
  hs->state = DDS::Security::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
  if (handle == DDS::HANDLE_NIL)
    handle = next_handle();
  handshakes_[handle] = hs;
  return DDS::Security::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
}

DDS::Security::ValidationResult_t Authentication::process_handshake(
    DDS::Security::HandshakeMessageToken& output, const DDS::Security::HandshakeMessageToken& input,
    DDS::Security::HandshakeHandle handle, DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::map<DDS::Security::HandshakeHandle, HandshakePtr>::iterator pos = handshakes_.find(handle);
  if (pos == handshakes_.end()) {
    fail(ex, "Unknown PQSec handshake handle");
    return DDS::Security::VALIDATION_FAILED;
  }
  Handshake& hs = *pos->second;
  output = DDS::Security::Token();

  if (hs.initiator && class_is(input, REPLY_CLASS_ID)) {
    if (!validate_remote_credentials(hs, input, hs.hash2, ex))
      return DDS::Security::VALIDATION_FAILED;
    OpenDDS::Security::TokenReader reader(input);
    hs.challenge2 = reader.get_bin_property_value("challenge2");
    hs.ciphertext = reader.get_bin_property_value(KEM_CIPHERTEXT_PROPERTY);
    if (!equal(reader.get_bin_property_value("challenge1"), hs.challenge1) ||
        (hs.remote->remote_challenge.length() &&
         !equal(hs.challenge2, hs.remote->remote_challenge))) {
      fail(ex, "PQSec reply challenge mismatch");
      return DDS::Security::VALIDATION_FAILED;
    }
    DDS::BinaryPropertySeq reply_data = reply_transcript(hs.hash2, hs.challenge2, hs.ciphertext,
                                                         hs.challenge1, hs.public_key, hs.hash1);
    if (OpenDDS::Security::SSL::verify_serialized(reply_data, *hs.remote_certificate,
                                                  reader.get_bin_property_value("signature"))) {
      fail(ex, "ML-DSA reply signature verification failed");
      return DDS::Security::VALIDATION_FAILED;
    }
    std::string error;
    std::vector<unsigned char> secret;
    if (!hs.kem.decapsulate(bytes(hs.ciphertext), secret, error)) {
      fail(ex, error);
      return DDS::Security::VALIDATION_FAILED;
    }
    hs.secret = octets(secret);
    if (!secret.empty())
      OPENSSL_cleanse(&secret[0], secret.size());
    DDS::BinaryPropertySeq final_data = final_transcript(hs.hash1, hs.challenge1, hs.public_key,
                                                         hs.challenge2, hs.ciphertext, hs.hash2);
    DDS::OctetSeq signature;
    if (OpenDDS::Security::SSL::sign_serialized(
            final_data, hs.local->credentials->get_participant_private_key(), signature)) {
      fail(ex, "ML-DSA final signature failed");
      return DDS::Security::VALIDATION_FAILED;
    }
    OpenDDS::Security::TokenWriter writer(output, FINAL_CLASS_ID);
    writer.add_bin_property("signature", signature);
    hs.reply = input;
    hs.state = DDS::Security::VALIDATION_OK_FINAL_MESSAGE;
    return hs.state;
  }

  if (!hs.initiator && class_is(input, FINAL_CLASS_ID)) {
    OpenDDS::Security::TokenReader reader(input);
    DDS::BinaryPropertySeq final_data = final_transcript(hs.hash1, hs.challenge1, hs.public_key,
                                                         hs.challenge2, hs.ciphertext, hs.hash2);
    if (!hs.remote_certificate ||
        OpenDDS::Security::SSL::verify_serialized(final_data, *hs.remote_certificate,
                                                  reader.get_bin_property_value("signature"))) {
      fail(ex, "ML-DSA final signature verification failed");
      return DDS::Security::VALIDATION_FAILED;
    }
    hs.state = DDS::Security::VALIDATION_OK;
    return hs.state;
  }
  fail(ex, "Unexpected PQSec handshake message");
  return DDS::Security::VALIDATION_FAILED;
}

DDS::Security::SharedSecretHandle*
Authentication::get_shared_secret(DDS::Security::HandshakeHandle handle,
                                  DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::map<DDS::Security::HandshakeHandle, HandshakePtr>::iterator pos = handshakes_.find(handle);
  if (pos == handshakes_.end() ||
      (pos->second->state != DDS::Security::VALIDATION_OK &&
       pos->second->state != DDS::Security::VALIDATION_OK_FINAL_MESSAGE)) {
    fail(ex, "PQSec shared secret requested before authentication completed");
    return 0;
  }
  return new SharedSecret(pos->second->challenge1, pos->second->challenge2, pos->second->secret);
}

CORBA::Boolean Authentication::get_authenticated_peer_credential_token(
    DDS::Security::AuthenticatedPeerCredentialToken& token, DDS::Security::HandshakeHandle handle,
    DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  std::map<DDS::Security::HandshakeHandle, HandshakePtr>::iterator pos = handshakes_.find(handle);
  if (pos == handshakes_.end() || !pos->second->remote_certificate ||
      (pos->second->state != DDS::Security::VALIDATION_OK &&
       pos->second->state != DDS::Security::VALIDATION_OK_FINAL_MESSAGE)) {
    fail(ex, "PQSec peer credentials are unavailable");
    return false;
  }
  OpenDDS::Security::TokenWriter writer(token, BASE_CLASS_ID);
  writer.add_bin_property("c.id", pos->second->remote_certificate->original_bytes());
  writer.add_bin_property("c.perm", pos->second->remote_permissions);
  return true;
}

CORBA::Boolean Authentication::set_listener(DDS::Security::AuthenticationListener_ptr listener,
                                            DDS::Security::SecurityException& ex) {
  if (!listener) {
    fail(ex, "Null authentication listener");
    return false;
  }
  listener_ = DDS::Security::AuthenticationListener::_duplicate(listener);
  return true;
}

CORBA::Boolean Authentication::return_identity_token(const DDS::Security::IdentityToken&,
                                                     DDS::Security::SecurityException&) {
  return true;
}
CORBA::Boolean
Authentication::return_identity_status_token(const DDS::Security::IdentityStatusToken&,
                                             DDS::Security::SecurityException&) {
  return true;
}
CORBA::Boolean Authentication::return_authenticated_peer_credential_token(
    const DDS::Security::AuthenticatedPeerCredentialToken&, DDS::Security::SecurityException&) {
  return true;
}

CORBA::Boolean Authentication::return_handshake_handle(DDS::Security::HandshakeHandle handle,
                                                       DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (!handshakes_.erase(handle)) {
    fail(ex, "Unknown PQSec handshake handle");
    return false;
  }
  return true;
}

CORBA::Boolean Authentication::return_identity_handle(DDS::Security::IdentityHandle handle,
                                                      DDS::Security::SecurityException& ex) {
  std::lock_guard<std::mutex> guard(mutex_);
  if (locals_.erase(handle) || remotes_.erase(handle))
    return true;
  fail(ex, "Unknown PQSec identity handle");
  return false;
}

CORBA::Boolean Authentication::return_sharedsecret_handle(DDS::Security::SharedSecretHandle*,
                                                          DDS::Security::SecurityException&) {
  return true;
}

} // namespace OpenDDS_PQSec
