/*
 * Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
 */

#ifndef OPENDDS_PQSEC_PLUGIN_H
#define OPENDDS_PQSEC_PLUGIN_H

#include "Export.h"

#include <ace/Service_Object.h>
#include <ace/Service_Config.h>

class OPENDDS_PQSEC_Export PQSecPluginLoader : public ACE_Service_Object {
public:
  int init(int argc, ACE_TCHAR* argv[]);
};

ACE_STATIC_SVC_DECLARE_EXPORT(OPENDDS_PQSEC, PQSecPluginLoader)
ACE_FACTORY_DECLARE(OPENDDS_PQSEC, PQSecPluginLoader)

#endif
