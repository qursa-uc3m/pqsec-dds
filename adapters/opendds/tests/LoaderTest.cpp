#include <dds/DCPS/Service_Participant.h>
#include <dds/DCPS/security/framework/SecurityConfig.h>
#include <dds/DCPS/security/framework/SecurityRegistry.h>

#include <iostream>

int main(int argc, char* argv[])
{
  DDS::DomainParticipantFactory_var factory = TheParticipantFactoryWithArgs(argc, argv);
  if (!factory) {
    std::cerr << "OpenDDS initialization failed\n";
    return 1;
  }

  OpenDDS::Security::SecurityPluginInst_rch plugin =
    TheSecurityRegistry->get_plugin_inst("PQSec", false);
  OpenDDS::Security::SecurityConfig_rch config =
    TheSecurityRegistry->default_config();
  const bool ok = plugin && config && config->name() == "pqsec" &&
    config->get_authentication() && config->get_access_control() &&
    config->get_crypto_key_factory() && config->get_crypto_key_exchange() &&
    config->get_crypto_transform() && config->get_utility();

  if (!ok) {
    std::cerr << "External PQSec authentication plus built-in companion plugins did not load\n";
  }
  TheServiceParticipant->shutdown();
  return ok ? 0 : 1;
}
