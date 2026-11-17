/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Authentication.h"
#include "Crypto.h"
#include "Transcript.h"

#include <dds/DCPS/GuidUtils.h>
#include <dds/DCPS/Serializer.h>
#include <dds/DCPS/RTPS/RtpsCoreC.h>
#include <dds/DCPS/RTPS/RtpsCoreTypeSupportImpl.h>
#include <dds/DCPS/security/TokenWriter.h>

#include <ace/Message_Block.h>

#include <cstring>
#include <iostream>
#include <string>

namespace {

using DDS::Security::VALIDATION_OK;
using DDS::Security::VALIDATION_OK_FINAL_MESSAGE;
using DDS::Security::VALIDATION_PENDING_HANDSHAKE_MESSAGE;
using DDS::Security::VALIDATION_PENDING_HANDSHAKE_REQUEST;

struct Participant {
  OpenDDS_PQSec::Authentication authentication;
  DDS::DomainParticipantQos qos;
  OpenDDS::DCPS::GUID_t candidate;
  OpenDDS::DCPS::GUID_t adjusted;
  DDS::Security::IdentityHandle local;
  DDS::Security::IdentityHandle remote;
  DDS::Security::IdentityToken identity_token;
  DDS::Security::AuthRequestMessageToken auth_request;
  DDS::Security::HandshakeHandle handshake;
  DDS::OctetSeq participant_data;
  DDS::Security::SecurityException exception;

  Participant(unsigned char suffix, const char* name, const char* ca_name = "identity_ca_cert.pem",
              const char* kem = "X25519MLKEM768")
      : candidate(OpenDDS::DCPS::GUID_UNKNOWN), adjusted(OpenDDS::DCPS::GUID_UNKNOWN),
        local(DDS::HANDLE_NIL), remote(DDS::HANDLE_NIL), handshake(DDS::HANDLE_NIL) {
    for (size_t i = 0; i != sizeof candidate.guidPrefix; ++i) {
      candidate.guidPrefix[i] = static_cast<unsigned char>(i + suffix);
    }
    candidate.entityId = OpenDDS::DCPS::ENTITYID_PARTICIPANT;
    add_property("dds.sec.auth.identity_ca",
                 std::string("file:") + PQSEC_TEST_CERT_DIR + "/" + ca_name);
    add_property("dds.sec.auth.private_key",
                 std::string("file:") + PQSEC_TEST_CERT_DIR + "/participant_" + name + "_key.pem");
    add_property("dds.sec.auth.identity_certificate",
                 std::string("file:") + PQSEC_TEST_CERT_DIR + "/participant_" + name + "_cert.pem");
    add_property("dds.sec.auth.password", "");
    add_property("dds.sec.auth.key_establishment_algorithm", kem);
  }

  void add_property(const char* name, const std::string& value) {
    const CORBA::ULong length = qos.property.value.length();
    qos.property.value.length(length + 1);
    qos.property.value[length].name = name;
    qos.property.value[length].value = value.c_str();
    qos.property.value[length].propagate = false;
  }
};

bool check(bool condition, const char* message, const DDS::Security::SecurityException& ex) {
  if (condition)
    return true;
  std::cerr << message;
  if (ex.message.in() && ex.message.in()[0])
    std::cerr << ": " << ex.message.in();
  std::cerr << '\n';
  return false;
}

bool initialize(Participant& participant) {
  if (!check(participant.authentication.validate_local_identity(
                 participant.local, participant.adjusted, 0, participant.qos, participant.candidate,
                 participant.exception) == VALIDATION_OK,
             "validate_local_identity failed", participant.exception))
    return false;
  if (!check(participant.authentication.get_identity_token(
                 participant.identity_token, participant.local, participant.exception),
             "get_identity_token failed", participant.exception))
    return false;

  DDS::Security::PermissionsCredentialToken credential;
  OpenDDS::Security::TokenWriter writer(credential, "DDS:Access:PermissionsCredential");
  writer.add_property("dds.perm.cert", "<permissions/>");
  DDS::Security::PermissionsToken permissions;
  if (!check(participant.authentication.set_permissions_credential_and_token(
                 participant.local, credential, permissions, participant.exception),
             "set_permissions_credential_and_token failed", participant.exception))
    return false;

  ACE_Message_Block buffer(1024);
  OpenDDS::DCPS::Serializer serializer(&buffer, OpenDDS::DCPS::Encoding::KIND_XCDR1,
                                       OpenDDS::DCPS::ENDIAN_BIG);
  OpenDDS::RTPS::ParameterList parameters;
  parameters.length(1);
  parameters[0].guid(participant.adjusted);
  parameters[0]._d(OpenDDS::RTPS::PID_PARTICIPANT_GUID);
  if (!(serializer << parameters))
    return false;
  participant.participant_data.length(static_cast<CORBA::ULong>(buffer.length()));
  std::memcpy(participant.participant_data.get_buffer(), buffer.rd_ptr(), buffer.length());
  return true;
}

DDS::OctetSeq* property(DDS::Security::Token& token, const char* name) {
  for (CORBA::ULong i = 0; i != token.binary_properties.length(); ++i) {
    if (std::strcmp(token.binary_properties[i].name.in(), name) == 0)
      return &token.binary_properties[i].value;
  }
  return 0;
}

void set_string(DDS::OctetSeq& value, const char* text) {
  const size_t size = std::strlen(text) + 1;
  value.length(static_cast<CORBA::ULong>(size));
  std::memcpy(value.get_buffer(), text, size);
}

void add(DDS::Security::Token& token, const char* name, const DDS::OctetSeq& value) {
  const CORBA::ULong length = token.binary_properties.length();
  token.binary_properties.length(length + 1);
  token.binary_properties[length].name = name;
  token.binary_properties[length].value = value;
  token.binary_properties[length].propagate = true;
}

struct Exchange {
  Participant a;
  Participant b;
  Participant* initiator;
  Participant* replier;
  DDS::Security::HandshakeMessageToken request;
  DDS::Security::HandshakeMessageToken reply;

  explicit Exchange(const char* kem = "X25519MLKEM768", const char* other_kem = 0)
      : a(1, "a", "identity_ca_cert.pem", kem),
        b(2, "b", "identity_ca_cert.pem", other_kem ? other_kem : kem), initiator(0), replier(0) {}

  bool prepare_request() {
    if (!initialize(a) || !initialize(b))
      return false;
    DDS::Security::AuthRequestMessageToken nil_request;
    const DDS::Security::ValidationResult_t a_role = a.authentication.validate_remote_identity(
        a.remote, a.auth_request, nil_request, a.local, b.identity_token, b.adjusted, a.exception);
    const DDS::Security::ValidationResult_t b_role = b.authentication.validate_remote_identity(
        b.remote, b.auth_request, nil_request, b.local, a.identity_token, a.adjusted, b.exception);
    if (!check((a_role == VALIDATION_PENDING_HANDSHAKE_REQUEST &&
                b_role == VALIDATION_PENDING_HANDSHAKE_MESSAGE) ||
                   (b_role == VALIDATION_PENDING_HANDSHAKE_REQUEST &&
                    a_role == VALIDATION_PENDING_HANDSHAKE_MESSAGE),
               "participants did not choose complementary handshake roles", a.exception))
      return false;

    DDS::Security::AuthRequestMessageToken ignored;
    if (a.authentication.validate_remote_identity(a.remote, ignored, b.auth_request, a.local,
                                                  b.identity_token, b.adjusted, a.exception) ==
            DDS::Security::VALIDATION_FAILED ||
        b.authentication.validate_remote_identity(b.remote, ignored, a.auth_request, b.local,
                                                  a.identity_token, a.adjusted,
                                                  b.exception) == DDS::Security::VALIDATION_FAILED)
      return false;
    initiator = a_role == VALIDATION_PENDING_HANDSHAKE_REQUEST ? &a : &b;
    replier = initiator == &a ? &b : &a;
    return check(initiator->authentication.begin_handshake_request(
                     initiator->handshake, request, initiator->local, initiator->remote,
                     initiator->participant_data,
                     initiator->exception) == VALIDATION_PENDING_HANDSHAKE_MESSAGE,
                 "begin_handshake_request failed", initiator->exception);
  }

  bool prepare_reply() {
    reply = request;
    return check(replier->authentication.begin_handshake_reply(
                     replier->handshake, reply, replier->remote, replier->local,
                     replier->participant_data,
                     replier->exception) == VALIDATION_PENDING_HANDSHAKE_MESSAGE,
                 "begin_handshake_reply failed", replier->exception);
  }

  bool process_reply(DDS::Security::HandshakeMessageToken& final_message) {
    return initiator->authentication.process_handshake(final_message, reply, initiator->handshake,
                                                       initiator->exception) ==
           VALIDATION_OK_FINAL_MESSAGE;
  }

  bool process_final(const DDS::Security::HandshakeMessageToken& final_message) {
    DDS::Security::HandshakeMessageToken unused;
    return replier->authentication.process_handshake(unused, final_message, replier->handshake,
                                                     replier->exception) == VALIDATION_OK;
  }
};

bool happy_path_and_replay_test(const char* kem) {
  Exchange exchange(kem);
  if (!exchange.prepare_request() || !exchange.prepare_reply())
    return false;
  DDS::Security::HandshakeMessageToken final_message;
  if (!check(exchange.initiator->authentication.process_handshake(
                 final_message, exchange.reply, exchange.initiator->handshake,
                 exchange.initiator->exception) == VALIDATION_OK_FINAL_MESSAGE,
             "reply processing failed", exchange.initiator->exception))
    return false;
  DDS::Security::HandshakeMessageToken unused;
  if (!check(exchange.replier->authentication.process_handshake(
                 unused, final_message, exchange.replier->handshake, exchange.replier->exception) ==
                 VALIDATION_OK,
             "final processing failed", exchange.replier->exception))
    return false;

  DDS::Security::SharedSecretHandle_var first =
      exchange.initiator->authentication.get_shared_secret(exchange.initiator->handshake,
                                                           exchange.initiator->exception);
  DDS::Security::SharedSecretHandle_var second = exchange.replier->authentication.get_shared_secret(
      exchange.replier->handshake, exchange.replier->exception);
  if (!check(first.in() && second.in(), "shared secret unavailable", exchange.initiator->exception))
    return false;
  DDS::OctetSeq_var first_bytes = first->sharedSecret();
  DDS::OctetSeq_var second_bytes = second->sharedSecret();
  if (!check(first_bytes->length() != 0 &&
                 OpenDDS_PQSec::equal(first_bytes.in(), second_bytes.in()),
             "KEM shared secrets differ", exchange.initiator->exception))
    return false;

  return check(exchange.initiator->authentication.process_handshake(
                   unused, exchange.reply, exchange.initiator->handshake,
                   exchange.initiator->exception) == DDS::Security::VALIDATION_FAILED,
               "completed handshake accepted a replayed reply", exchange.initiator->exception);
}

bool tampered_signature_test() {
  Exchange exchange;
  if (!exchange.prepare_request() || !exchange.prepare_reply())
    return false;
  DDS::Security::HandshakeMessageToken tampered = exchange.reply;
  DDS::OctetSeq* signature = property(tampered, "signature");
  if (!signature || !signature->length())
    return false;
  (*signature)[0] ^= 1;
  DDS::Security::HandshakeMessageToken output;
  if (!check(exchange.initiator->authentication.process_handshake(
                 output, tampered, exchange.initiator->handshake, exchange.initiator->exception) ==
                 DDS::Security::VALIDATION_FAILED,
             "tampered reply signature was accepted", exchange.initiator->exception))
    return false;
  // OpenDDS keeps the handshake after a failed message, so the genuine reply
  // must still be accepted.
  return check(exchange.initiator->authentication.process_handshake(
                   output, exchange.reply, exchange.initiator->handshake,
                   exchange.initiator->exception) == VALIDATION_OK_FINAL_MESSAGE,
               "a forged reply blocked the genuine one", exchange.initiator->exception);
}

// An attacker replaces the initiator's dh1 with its own key.  The replier
// cannot notice, but the initiator signs and checks its own dh1.
bool substituted_public_key_test() {
  Exchange exchange;
  if (!exchange.prepare_request())
    return false;
  OpenDDS_PQSec::Kem attacker("X25519MLKEM768");
  std::vector<unsigned char> attacker_key;
  std::string error;
  DDS::OctetSeq* public_key = property(exchange.request, "dh1");
  if (!public_key || !attacker.generate(error) || !attacker.public_key(attacker_key, error))
    return false;
  *public_key = OpenDDS_PQSec::octets(attacker_key);
  if (!exchange.prepare_reply())
    return false;
  DDS::Security::HandshakeMessageToken output;
  return check(exchange.initiator->authentication.process_handshake(
                   output, exchange.reply, exchange.initiator->handshake,
                   exchange.initiator->exception) == DDS::Security::VALIDATION_FAILED,
               "reply to a substituted KEM public key was accepted", exchange.initiator->exception);
}

// An attacker replaces dh2 with a valid ciphertext of its own for the
// initiator's key, so decapsulation alone would succeed.
bool substituted_ciphertext_test() {
  Exchange exchange;
  if (!exchange.prepare_request() || !exchange.prepare_reply())
    return false;
  OpenDDS_PQSec::Kem attacker("X25519MLKEM768");
  std::vector<unsigned char> ciphertext, secret;
  std::string error;
  DDS::OctetSeq* public_key = property(exchange.request, "dh1");
  DDS::OctetSeq* reply_ciphertext = property(exchange.reply, "dh2");
  if (!public_key || !reply_ciphertext ||
      !attacker.import_public(OpenDDS_PQSec::bytes(*public_key), error) ||
      !attacker.encapsulate(ciphertext, secret, error))
    return false;
  *reply_ciphertext = OpenDDS_PQSec::octets(ciphertext);
  DDS::Security::HandshakeMessageToken output;
  return check(exchange.initiator->authentication.process_handshake(
                   output, exchange.reply, exchange.initiator->handshake,
                   exchange.initiator->exception) == DDS::Security::VALIDATION_FAILED,
               "substituted KEM ciphertext was accepted", exchange.initiator->exception);
}

// c.perm is checked by nothing but the credential hash, so a change to it is
// only caught if the hash is signed.
bool credential_binding_test() {
  Exchange exchange;
  if (!exchange.prepare_request() || !exchange.prepare_reply())
    return false;
  DDS::OctetSeq* permissions = property(exchange.reply, "c.perm");
  if (!permissions)
    return false;
  set_string(*permissions, "<permissions>forged</permissions>");
  DDS::Security::HandshakeMessageToken output;
  return check(exchange.initiator->authentication.process_handshake(
                   output, exchange.reply, exchange.initiator->handshake,
                   exchange.initiator->exception) == DDS::Security::VALIDATION_FAILED,
               "reply with altered permissions was accepted", exchange.initiator->exception);
}

// The replier uses the algorithm the initiator chose, not its own setting.
bool initiator_chooses_test() {
  Exchange exchange("ML-KEM-1024", "ML-KEM-768");
  DDS::Security::HandshakeMessageToken final_message;
  if (!exchange.prepare_request() || !exchange.prepare_reply() ||
      !check(exchange.process_reply(final_message), "reply processing failed",
             exchange.initiator->exception) ||
      !check(exchange.process_final(final_message), "final processing failed",
             exchange.replier->exception))
    return false;
  const DDS::OctetSeq* requested = property(exchange.request, "c.kagree_algo");
  const DDS::OctetSeq* replied = property(exchange.reply, "c.kagree_algo");
  return check(requested && replied && OpenDDS_PQSec::equal(*requested, *replied),
               "replier did not use the initiator's algorithm", exchange.replier->exception);
}

// A request from a classical PKI-DH participant, under its 1.2 or 1.1 name.
bool classical_request_test() {
  const char* names[] = {"ECDHE-CEUM+P256", "ECDH+prime256v1-CEUM", ""};
  for (size_t i = 0; i != sizeof names / sizeof names[0]; ++i) {
    Exchange exchange;
    if (!exchange.prepare_request())
      return false;
    DDS::OctetSeq* algorithm = property(exchange.request, "c.kagree_algo");
    if (!algorithm)
      return false;
    set_string(*algorithm, names[i]);
    exchange.reply = exchange.request;
    if (!check(exchange.replier->authentication.begin_handshake_reply(
                   exchange.replier->handshake, exchange.reply, exchange.replier->remote,
                   exchange.replier->local, exchange.replier->participant_data,
                   exchange.replier->exception) == DDS::Security::VALIDATION_FAILED,
               "request with a classical key establishment algorithm was accepted",
               exchange.replier->exception))
      return false;
  }
  return true;
}

bool reply_algorithm_test() {
  Exchange exchange;
  if (!exchange.prepare_request() || !exchange.prepare_reply())
    return false;
  DDS::OctetSeq* algorithm = property(exchange.reply, "c.kagree_algo");
  if (!algorithm)
    return false;
  set_string(*algorithm, "ML-KEM-768");
  DDS::Security::HandshakeMessageToken output;
  return check(!exchange.process_reply(output),
               "reply naming another algorithm than the request was accepted",
               exchange.initiator->exception);
}

// Echoed values are optional. One that differs from the local value is
// refused; one that matches is accepted.
bool reply_echo_test() {
  Exchange exchange;
  if (!exchange.prepare_request() || !exchange.prepare_reply())
    return false;
  const DDS::OctetSeq* dh1 = property(exchange.request, "dh1");
  if (!dh1)
    return false;
  DDS::OctetSeq other(*dh1);
  other[0] ^= 1;
  const DDS::Security::HandshakeMessageToken genuine = exchange.reply;
  add(exchange.reply, "dh1", other);
  DDS::Security::HandshakeMessageToken final_message;
  if (!check(!exchange.process_reply(final_message), "reply echoing a different dh1 was accepted",
             exchange.initiator->exception))
    return false;
  exchange.reply = genuine;
  add(exchange.reply, "dh1", *dh1);
  return check(exchange.process_reply(final_message), "reply echoing the right dh1 was refused",
               exchange.initiator->exception);
}

bool final_mismatch_test() {
  Exchange exchange;
  DDS::Security::HandshakeMessageToken final_message;
  if (!exchange.prepare_request() || !exchange.prepare_reply() ||
      !exchange.process_reply(final_message))
    return false;

  DDS::Security::HandshakeMessageToken altered = final_message;
  DDS::OctetSeq* challenge1 = property(altered, "challenge1");
  if (!challenge1 || challenge1->length() != 32)
    return false;
  (*challenge1)[0] ^= 1;
  if (!check(!exchange.process_final(altered), "final with a different challenge1 was accepted",
             exchange.replier->exception))
    return false;

  altered = final_message;
  DDS::OctetSeq* challenge2 = property(altered, "challenge2");
  if (!challenge2)
    return false;
  challenge2->length(0);
  if (!check(!exchange.process_final(altered), "final without challenge2 was accepted",
             exchange.replier->exception))
    return false;

  altered = final_message;
  const DDS::OctetSeq* dh2 = property(exchange.reply, "dh2");
  if (!dh2)
    return false;
  DDS::OctetSeq other(*dh2);
  other[0] ^= 1;
  add(altered, "dh2", other);
  if (!check(!exchange.process_final(altered), "final echoing a different dh2 was accepted",
             exchange.replier->exception))
    return false;
  return check(exchange.process_final(final_message), "a refused final blocked the genuine one",
               exchange.replier->exception);
}

bool challenge_length_tests() {
  Exchange request_exchange;
  if (!request_exchange.prepare_request())
    return false;
  DDS::OctetSeq* challenge1 = property(request_exchange.request, "challenge1");
  if (!challenge1)
    return false;
  challenge1->length(0);
  request_exchange.reply = request_exchange.request;
  if (!check(request_exchange.replier->authentication.begin_handshake_reply(
                 request_exchange.replier->handshake, request_exchange.reply,
                 request_exchange.replier->remote, request_exchange.replier->local,
                 request_exchange.replier->participant_data,
                 request_exchange.replier->exception) == DDS::Security::VALIDATION_FAILED,
             "empty request challenge was accepted", request_exchange.replier->exception))
    return false;

  Exchange mismatch_exchange;
  if (!mismatch_exchange.prepare_request())
    return false;
  DDS::OctetSeq* mismatched_challenge = property(mismatch_exchange.request, "challenge1");
  if (!mismatched_challenge || mismatched_challenge->length() != 32)
    return false;
  (*mismatched_challenge)[0] ^= 1;
  mismatch_exchange.reply = mismatch_exchange.request;
  if (!check(mismatch_exchange.replier->authentication.begin_handshake_reply(
                 mismatch_exchange.replier->handshake, mismatch_exchange.reply,
                 mismatch_exchange.replier->remote, mismatch_exchange.replier->local,
                 mismatch_exchange.replier->participant_data,
                 mismatch_exchange.replier->exception) == DDS::Security::VALIDATION_FAILED,
             "mismatched request challenge was accepted", mismatch_exchange.replier->exception))
    return false;

  Exchange reply_exchange;
  if (!reply_exchange.prepare_request() || !reply_exchange.prepare_reply())
    return false;
  DDS::OctetSeq* challenge2 = property(reply_exchange.reply, "challenge2");
  if (!challenge2)
    return false;
  challenge2->length(0);
  DDS::Security::HandshakeMessageToken output;
  return check(reply_exchange.initiator->authentication.process_handshake(
                   output, reply_exchange.reply, reply_exchange.initiator->handshake,
                   reply_exchange.initiator->exception) == DDS::Security::VALIDATION_FAILED,
               "empty reply challenge was accepted", reply_exchange.initiator->exception);
}

bool different_ca_test() {
  Participant trusted(1, "a");
  Participant other(2, "other", "other_ca_cert.pem");
  if (!initialize(trusted) || !initialize(other))
    return false;
  DDS::Security::AuthRequestMessageToken nil_request;
  const DDS::Security::ValidationResult_t trusted_role =
      trusted.authentication.validate_remote_identity(
          trusted.remote, trusted.auth_request, nil_request, trusted.local, other.identity_token,
          other.adjusted, trusted.exception);
  const DDS::Security::ValidationResult_t other_role =
      other.authentication.validate_remote_identity(other.remote, other.auth_request, nil_request,
                                                    other.local, trusted.identity_token,
                                                    trusted.adjusted, other.exception);
  DDS::Security::AuthRequestMessageToken ignored;
  trusted.authentication.validate_remote_identity(trusted.remote, ignored, other.auth_request,
                                                  trusted.local, other.identity_token,
                                                  other.adjusted, trusted.exception);
  other.authentication.validate_remote_identity(other.remote, ignored, trusted.auth_request,
                                                other.local, trusted.identity_token,
                                                trusted.adjusted, other.exception);
  Participant* initiator = trusted_role == VALIDATION_PENDING_HANDSHAKE_REQUEST ? &trusted : &other;
  Participant* replier = initiator == &trusted ? &other : &trusted;
  if (other_role == trusted_role)
    return false;
  DDS::Security::HandshakeMessageToken request;
  if (initiator->authentication.begin_handshake_request(
          initiator->handshake, request, initiator->local, initiator->remote,
          initiator->participant_data,
          initiator->exception) != VALIDATION_PENDING_HANDSHAKE_MESSAGE)
    return false;
  DDS::Security::HandshakeMessageToken reply = request;
  return check(replier->authentication.begin_handshake_reply(
                   replier->handshake, reply, replier->remote, replier->local,
                   replier->participant_data,
                   replier->exception) == DDS::Security::VALIDATION_FAILED,
               "certificate from a different CA was accepted", replier->exception);
}

bool classical_ca_test() {
  Participant participant(1, "ecca", "ec_ca_cert.pem");
  return check(participant.authentication.validate_local_identity(
                   participant.local, participant.adjusted, 0, participant.qos,
                   participant.candidate,
                   participant.exception) == DDS::Security::VALIDATION_FAILED,
               "identity CA with a classical key was accepted", participant.exception);
}

bool classical_configuration_test() {
  Participant participant(1, "a", "identity_ca_cert.pem", "ECDHE-CEUM+P256");
  return check(participant.authentication.validate_local_identity(
                   participant.local, participant.adjusted, 0, participant.qos,
                   participant.candidate,
                   participant.exception) == DDS::Security::VALIDATION_FAILED,
               "a classical key establishment algorithm was configured", participant.exception);
}

} // namespace

int main() {
  return happy_path_and_replay_test("ML-KEM-768") && happy_path_and_replay_test("ML-KEM-1024") &&
                 happy_path_and_replay_test("X25519MLKEM768") &&
                 happy_path_and_replay_test("AUTO") && tampered_signature_test() &&
                 substituted_public_key_test() && substituted_ciphertext_test() &&
                 credential_binding_test() && initiator_chooses_test() &&
                 classical_request_test() && reply_algorithm_test() && reply_echo_test() &&
                 final_mismatch_test() && challenge_length_tests() && different_ca_test() &&
                 classical_ca_test() && classical_configuration_test()
             ? 0
             : 1;
}
