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

  Participant(unsigned char suffix, const char* name)
      : candidate(OpenDDS::DCPS::GUID_UNKNOWN), adjusted(OpenDDS::DCPS::GUID_UNKNOWN),
        local(DDS::HANDLE_NIL), remote(DDS::HANDLE_NIL), handshake(DDS::HANDLE_NIL) {
    for (size_t i = 0; i != sizeof candidate.guidPrefix; ++i) {
      candidate.guidPrefix[i] = static_cast<unsigned char>(i + suffix);
    }
    candidate.entityId = OpenDDS::DCPS::ENTITYID_PARTICIPANT;
    add_property("dds.sec.auth.identity_ca",
                 std::string("file:") + PQSEC_TEST_CERT_DIR + "/identity_ca_cert.pem");
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

} // namespace

int main() {
  Participant a(1, "a"), b(2, "b");
  if (!initialize(a) || !initialize(b))
    return 1;

  DDS::Security::AuthRequestMessageToken nil_request;
  DDS::Security::ValidationResult_t a_role = a.authentication.validate_remote_identity(
      a.remote, a.auth_request, nil_request, a.local, b.identity_token, b.adjusted, a.exception);
  DDS::Security::ValidationResult_t b_role = b.authentication.validate_remote_identity(
      b.remote, b.auth_request, nil_request, b.local, a.identity_token, a.adjusted, b.exception);
  if (!check((a_role == VALIDATION_PENDING_HANDSHAKE_REQUEST &&
              b_role == VALIDATION_PENDING_HANDSHAKE_MESSAGE) ||
                 (b_role == VALIDATION_PENDING_HANDSHAKE_REQUEST &&
                  a_role == VALIDATION_PENDING_HANDSHAKE_MESSAGE),
             "participants did not choose complementary handshake roles", a.exception))
    return 1;

  DDS::Security::AuthRequestMessageToken ignored;
  if (a.authentication.validate_remote_identity(a.remote, ignored, b.auth_request, a.local,
                                                b.identity_token, b.adjusted,
                                                a.exception) == DDS::Security::VALIDATION_FAILED ||
      b.authentication.validate_remote_identity(b.remote, ignored, a.auth_request, b.local,
                                                a.identity_token, a.adjusted,
                                                b.exception) == DDS::Security::VALIDATION_FAILED) {
    std::cerr << "AuthRequest exchange failed\n";
    return 1;
  }

  Participant* initiator = a_role == VALIDATION_PENDING_HANDSHAKE_REQUEST ? &a : &b;
  Participant* replier = initiator == &a ? &b : &a;
  DDS::Security::HandshakeMessageToken request;
  if (!check(initiator->authentication.begin_handshake_request(
                 initiator->handshake, request, initiator->local, initiator->remote,
                 initiator->participant_data,
                 initiator->exception) == VALIDATION_PENDING_HANDSHAKE_MESSAGE,
             "begin_handshake_request failed", initiator->exception))
    return 1;

  DDS::Security::HandshakeMessageToken reply = request;
  if (!check(replier->authentication.begin_handshake_reply(
                 replier->handshake, reply, replier->remote, replier->local,
                 replier->participant_data,
                 replier->exception) == VALIDATION_PENDING_HANDSHAKE_MESSAGE,
             "begin_handshake_reply failed", replier->exception))
    return 1;

  DDS::Security::HandshakeMessageToken final_message;
  if (!check(initiator->authentication.process_handshake(final_message, reply, initiator->handshake,
                                                         initiator->exception) ==
                 VALIDATION_OK_FINAL_MESSAGE,
             "reply processing failed", initiator->exception))
    return 1;
  DDS::Security::HandshakeMessageToken unused;
  if (!check(replier->authentication.process_handshake(unused, final_message, replier->handshake,
                                                       replier->exception) == VALIDATION_OK,
             "final processing failed", replier->exception))
    return 1;

  DDS::Security::SharedSecretHandle_var first =
      initiator->authentication.get_shared_secret(initiator->handshake, initiator->exception);
  DDS::Security::SharedSecretHandle_var second =
      replier->authentication.get_shared_secret(replier->handshake, replier->exception);
  if (!check(first.in() && second.in(), "shared secret unavailable", initiator->exception))
    return 1;
  DDS::OctetSeq_var first_bytes = first->sharedSecret();
  DDS::OctetSeq_var second_bytes = second->sharedSecret();
  if (!check(first_bytes->length() != 0 &&
                 OpenDDS_PQSec::equal(first_bytes.in(), second_bytes.in()),
             "KEM shared secrets differ", initiator->exception))
    return 1;
  return 0;
}
