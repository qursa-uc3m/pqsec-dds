#ifndef OPENDDS_PQSEC_EXPORT_H
#define OPENDDS_PQSEC_EXPORT_H

#include <ace/config-all.h>

#if defined(ACE_AS_STATIC_LIBS)
#  define OPENDDS_PQSEC_Export
#elif defined(OPENDDS_PQSEC_BUILD_DLL)
#  define OPENDDS_PQSEC_Export ACE_Proper_Export_Flag
#else
#  define OPENDDS_PQSEC_Export ACE_Proper_Import_Flag
#endif

#endif
