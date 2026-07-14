#include <opendds_pqsec/Plugin.h>

#include "Authentication.h"

#include <dds/DCPS/RcHandle_T.h>
#include <dds/DCPS/security/framework/SecurityPluginInst.h>
#include <dds/DCPS/security/framework/SecurityRegistry.h>

namespace {

class PQSecSecurityPluginInst : public OpenDDS::Security::SecurityPluginInst {
public:
  PQSecSecurityPluginInst()
    : authentication_(new OpenDDS_PQSec::Authentication)
  {
  }

private:
  DDS::Security::Authentication_var create_authentication()
  {
    return authentication_;
  }

  DDS::Security::AccessControl_var create_access_control()
  {
    return DDS::Security::AccessControl::_nil();
  }

  DDS::Security::CryptoKeyExchange_var create_crypto_key_exchange()
  {
    return DDS::Security::CryptoKeyExchange::_nil();
  }

  DDS::Security::CryptoKeyFactory_var create_crypto_key_factory()
  {
    return DDS::Security::CryptoKeyFactory::_nil();
  }

  DDS::Security::CryptoTransform_var create_crypto_transform()
  {
    return DDS::Security::CryptoTransform::_nil();
  }

  OpenDDS::DCPS::RcHandle<OpenDDS::Security::Utility> create_utility()
  {
    return OpenDDS::DCPS::RcHandle<OpenDDS::Security::Utility>();
  }

  void shutdown()
  {
    authentication_ = DDS::Security::Authentication::_nil();
  }

  DDS::Security::Authentication_var authentication_;
};

} // namespace

int PQSecPluginLoader::init(int, ACE_TCHAR*[])
{
  const OpenDDS::DCPS::String plugin_name("PQSec");
  OpenDDS::Security::SecurityPluginInst_rch plugin =
    TheSecurityRegistry->get_plugin_inst(plugin_name, false);
  if (!plugin) {
    plugin = OpenDDS::DCPS::make_rch<PQSecSecurityPluginInst>();
    TheSecurityRegistry->register_plugin(plugin_name, plugin);
  }
  return 0;
}

ACE_FACTORY_DEFINE(OPENDDS_PQSEC, PQSecPluginLoader)
ACE_STATIC_SVC_DEFINE(
  PQSecPluginLoader,
  ACE_TEXT("OpenDDS_PQSec"),
  ACE_SVC_OBJ_T,
  &ACE_SVC_NAME(PQSecPluginLoader),
  ACE_Service_Type::DELETE_THIS | ACE_Service_Type::DELETE_OBJ,
  0)
