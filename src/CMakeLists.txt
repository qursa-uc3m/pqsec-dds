cmake_minimum_required(VERSION 3.10)
project(PQSec-DDS_plugin)

set(CMAKE_C_STANDARD 99)

option(ENABLE_PQ_CRYPTO "Enable Post-Quantum Cryptography support" OFF)
option(DEBUG "Plugin debug" OFF)

if(NOT CYCLONEDDS_PATH)
    message(FATAL_ERROR "CYCLONEDDS_PATH not provided. Please specify the path to CycloneDDS using -DCYCLONEDDS_PATH=/path/to/cyclonedds")
endif()

if(NOT LIBOQS_PATH)
    message(FATAL_ERROR "LIBOQS_PATH not provided. Please specify the path to liboqs using -DLIBOQS_PATH=/path/to/liboqs")
endif()

set(CMAKE_PREFIX_PATH "${CYCLONEDDS_PATH}" "${LIBOQS_PATH}")

if(OPENSSL_PATH)
    message(STATUS "Using provided OpenSSL path: ${OPENSSL_PATH}")
    set(OPENSSL_ROOT_DIR ${OPENSSL_PATH})
    #set(OPENSSL_HINT_PATH ${OPENSSL_PATH})
    #set(OPENSSL_INCLUDE_DIR ${OPENSSL_PATH}/include)
    find_package(OpenSSL REQUIRED PATHS ${OPENSSL_PATH})
else()
    message(STATUS "Using system default OpenSSL installation.")
    find_package(OpenSSL REQUIRED)
endif()

message(STATUS "OpenSSL_VERSION: ${OpenSSL_VERSION}")
message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

find_package(CycloneDDS REQUIRED)
#find_package(OpenSSL REQUIRED)
find_package(liboqs REQUIRED)

include_directories(
  ${PROJECT_SOURCE_DIR}
  "${PROJECT_SOURCE_DIR}/include"
  "${PROJECT_SOURCE_DIR}/openssl/include"
  "${CYCLONEDDS_PATH}/include"
  "${LIBOQS_PATH}/include"
  #${OPENSSL_INCLUDE_DIR}
)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_library(dds_pqsec SHARED
  authentication.c
  auth_utils.c
  openssl/src/openssl_support.c
)

target_link_libraries(dds_pqsec
  ${CycloneDDS_LIBRARIES}
  OpenSSL::SSL
  OQS::oqs
)

if(ENABLE_PQ_CRYPTO)
    target_compile_definitions(dds_pqsec PRIVATE PQ_CRYPTO)
    message(STATUS "PQ_CRYPTO is enabled.")
else()
    message(STATUS "PQ_CRYPTO is disabled.")
endif()

if(DEBUG)
    target_compile_definitions(dds_pqsec PRIVATE PLUGIN_DEBUG)
    message(STATUS "Debug mode is enabled.")
else()
    message(STATUS "Debug mode is disabled.")
endif()

set_target_properties(dds_pqsec PROPERTIES
  VERSION 1.0
  SOVERSION 1
)