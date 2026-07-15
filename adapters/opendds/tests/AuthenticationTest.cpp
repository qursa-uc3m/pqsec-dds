/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#include "Authentication.h"
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

  Participant(unsigned char suffix, const char* name, const char* ca_name = "identity_ca_cert.pem")
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
    add_property("pqsec-dds.kem", "X25519MLKEM768");
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

struct Exchange {
  Participant a;
  Participant b;
  Participant* initiator;
  Participant* replier;
  DDS::Security::HandshakeMessageToken request;
  DDS::Security::HandshakeMessageToken reply;

  Exchange() : a(1, "a"), b(2, "b"), initiator(0), replier(0) {}

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
};

bool happy_path_and_replay_test() {
  Exchange exchange;
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
  return check(exchange.initiator->authentication.process_handshake(
                   output, exchange.reply, exchange.initiator->handshake,
                   exchange.initiator->exception) == DDS::Security::VALIDATION_FAILED,
               "failed handshake was retried into success", exchange.initiator->exception);
}

bool algorithm_mismatch_test() {
  Exchange exchange;
  if (!exchange.prepare_request())
    return false;
  DDS::OctetSeq* algorithm = property(exchange.request, "c.kagree_algo");
  if (!algorithm)
    return false;
  set_string(*algorithm, "ML-KEM-768");
  exchange.reply = exchange.request;
  return check(exchange.replier->authentication.begin_handshake_reply(
                   exchange.replier->handshake, exchange.reply, exchange.replier->remote,
                   exchange.replier->local, exchange.replier->participant_data,
                   exchange.replier->exception) == DDS::Security::VALIDATION_FAILED,
               "mismatched KEM algorithm was accepted", exchange.replier->exception);
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

} // namespace

int main() {
  return happy_path_and_replay_test() && tampered_signature_test() && algorithm_mismatch_test() &&
                 challenge_length_tests() && different_ca_test()
             ? 0
             : 1;
}
