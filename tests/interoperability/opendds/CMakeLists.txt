cmake_minimum_required(VERSION 3.16)
project(pqsec_interop_opendds CXX)

find_package(OpenDDS REQUIRED COMPONENTS OpenDDS::Security OpenDDS::Rtps_Udp security=TRUE)
add_executable(opendds_app app.cpp)
# Without complete type objects OpenDDS announces a TK_NONE complete type
# identifier, and CycloneDDS drops its publications and subscriptions.
opendds_target_sources(opendds_app ${CMAKE_CURRENT_SOURCE_DIR}/../Interop.idl
                       OPENDDS_IDL_OPTIONS -Gxtypes-complete)
target_link_libraries(opendds_app OpenDDS::Dcps OpenDDS::Security OpenDDS::Rtps_Udp)
