// Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
//
// OpenDDS participant of the interoperability run: "pub" writes ten samples
// once a reader matches, "sub" waits for ten.
//
//   opendds_app pub|sub <identity> <security dir> -DCPSConfigFile <ini>
#include "InteropTypeSupportImpl.h"

#include <dds/DCPS/Marked_Default_Qos.h>
#include <dds/DCPS/Service_Participant.h>
#include <dds/DCPS/security/framework/Properties.h>

#include <ace/OS_NS_unistd.h>

#include <cstdio>
#include <string>

namespace {

const int SAMPLES = 10;

void add(DDS::PropertySeq& properties, const char* name, const std::string& value) {
  const CORBA::ULong length = properties.length();
  properties.length(length + 1);
  properties[length].name = name;
  properties[length].value = value.c_str();
}

template <typename Qos> void set_qos(Qos& qos) {
  qos.reliability.kind = DDS::RELIABLE_RELIABILITY_QOS;
  qos.durability.kind = DDS::TRANSIENT_LOCAL_DURABILITY_QOS;
  qos.history.kind = DDS::KEEP_ALL_HISTORY_QOS;
}

int publish(DDS::DomainParticipant* participant, DDS::Topic* topic) {
  DDS::Publisher_var publisher =
      participant->create_publisher(PUBLISHER_QOS_DEFAULT, 0, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
  DDS::DataWriterQos qos;
  publisher->get_default_datawriter_qos(qos);
  set_qos(qos);
  DDS::DataWriter_var writer =
      publisher->create_datawriter(topic, qos, 0, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
  Interop::MsgDataWriter_var msg_writer = Interop::MsgDataWriter::_narrow(writer);
  DDS::PublicationMatchedStatus status = {};
  for (int i = 0; i < 600 && status.current_count == 0; ++i) {
    ACE_OS::sleep(ACE_Time_Value(0, 100000));
    writer->get_publication_matched_status(status);
  }
  if (status.current_count == 0) {
    std::fprintf(stderr, "opendds: no matched reader\n");
    return 1;
  }
  for (int i = 0; i < SAMPLES; ++i) {
    char text[32];
    std::snprintf(text, sizeof text, "from OpenDDS %d", i);
    Interop::Msg msg;
    msg.id = i;
    msg.text = static_cast<const char*>(text); // copies; a char* would be adopted
    msg_writer->write(msg, DDS::HANDLE_NIL);
    ACE_OS::sleep(ACE_Time_Value(0, 200000));
  }
  ACE_OS::sleep(5);
  std::printf("opendds: wrote %d samples\n", SAMPLES);
  return 0;
}

int subscribe(DDS::DomainParticipant* participant, DDS::Topic* topic) {
  DDS::Subscriber_var subscriber =
      participant->create_subscriber(SUBSCRIBER_QOS_DEFAULT, 0, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
  DDS::DataReaderQos qos;
  subscriber->get_default_datareader_qos(qos);
  set_qos(qos);
  DDS::DataReader_var reader =
      subscriber->create_datareader(topic, qos, 0, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
  Interop::MsgDataReader_var msg_reader = Interop::MsgDataReader::_narrow(reader);
  int received = 0;
  for (int i = 0; i < 600 && received < SAMPLES; ++i) {
    Interop::Msg msg;
    DDS::SampleInfo info;
    while (msg_reader->take_next_sample(msg, info) == DDS::RETCODE_OK) {
      if (info.valid_data) {
        std::printf("opendds: received %d '%s'\n", msg.id, msg.text.in());
        ++received;
      }
    }
    ACE_OS::sleep(ACE_Time_Value(0, 100000));
  }
  std::printf("opendds: received %d samples\n", received);
  return received == SAMPLES ? 0 : 1;
}

} // namespace

int main(int argc, char* argv[]) {
  DDS::DomainParticipantFactory_var factory = TheParticipantFactoryWithArgs(argc, argv);
  const std::string role = argc == 4 ? argv[1] : "";
  if (role != "pub" && role != "sub") {
    std::fprintf(stderr, "usage: opendds_app pub|sub <identity> <security dir>\n");
    return 2;
  }
  const std::string identity = argv[2];
  const std::string dir = std::string("file:") + argv[3] + "/";

  DDS::DomainParticipantQos participant_qos;
  factory->get_default_participant_qos(participant_qos);
  DDS::PropertySeq& properties = participant_qos.property.value;
  using namespace DDS::Security::Properties;
  add(properties, AuthIdentityCA, dir + "identity_ca.pem");
  add(properties, AuthIdentityCertificate, dir + identity + "_cert.pem");
  add(properties, AuthPrivateKey, dir + identity + "_key.pem");
  add(properties, AccessPermissionsCA, dir + "permissions_ca.pem");
  add(properties, AccessGovernance, dir + "governance.p7s");
  add(properties, AccessPermissions, dir + "permissions.p7s");

  DDS::DomainParticipant_var participant =
      factory->create_participant(0, participant_qos, 0, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
  if (!participant) {
    std::fprintf(stderr, "opendds: create_participant failed\n");
    return 2;
  }
  Interop::MsgTypeSupport_var type_support = new Interop::MsgTypeSupportImpl;
  type_support->register_type(participant, "Interop::Msg");
  DDS::Topic_var topic = participant->create_topic(
      "PQSecInterop", "Interop::Msg", TOPIC_QOS_DEFAULT, 0, OpenDDS::DCPS::DEFAULT_STATUS_MASK);
  const int result = role == "pub" ? publish(participant, topic) : subscribe(participant, topic);
  participant->delete_contained_entities();
  factory->delete_participant(participant);
  TheServiceParticipant->shutdown();
  return result;
}
