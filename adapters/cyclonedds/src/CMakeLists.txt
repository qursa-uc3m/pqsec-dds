# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
# Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M)
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.16)
project(PQSecDDSCycloneDDS VERSION 1.0.0 LANGUAGES C)

include(CTest)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(ENABLE_PQ_CRYPTO "Build the ML-KEM/ML-DSA authentication plugin" ON)
option(ENABLE_PQ_LOGGING "Enable the adapter's diagnostic logging" OFF)
option(DEBUG "Enable legacy plugin diagnostics" OFF)

set(PQ_DEBUG_LEVEL "INFO" CACHE STRING "NONE|ERROR|WARN|INFO|TRACE|DATA")
set_property(CACHE PQ_DEBUG_LEVEL PROPERTY STRINGS NONE ERROR WARN INFO TRACE DATA)
set(SELECTED_KEM_ALGORITHM "mlkem768" CACHE STRING
    "OpenSSL KEM algorithm exposed by the default provider or oqs-provider")
set_property(CACHE SELECTED_KEM_ALGORITHM PROPERTY STRINGS
  mlkem512 mlkem768 mlkem1024 x25519_mlkem768 p256_mlkem768
  frodo640shake bikel1 hqc128)
set(PQSEC_FALLBACK_PROVIDER "oqsprovider" CACHE STRING
    "OpenSSL provider loaded when the selected KEM is not initially available")

set(_pq_kems
  mlkem512 mlkem768 mlkem1024
  x25519_mlkem768 p256_mlkem768
  frodo640shake bikel1 hqc128)
list(FIND _pq_kems "${SELECTED_KEM_ALGORITHM}" _kem_index)
if(ENABLE_PQ_CRYPTO AND _kem_index EQUAL -1)
  message(FATAL_ERROR
    "${SELECTED_KEM_ALGORITHM} is not a supported OpenSSL KEM name. "
    "Choose one of: ${_pq_kems}")
endif()

set(_debug_levels NONE ERROR WARN INFO TRACE DATA)
list(FIND _debug_levels "${PQ_DEBUG_LEVEL}" PQ_DEBUG_LEVEL_NUM)
if(PQ_DEBUG_LEVEL_NUM EQUAL -1)
  message(FATAL_ERROR "Invalid PQ_DEBUG_LEVEL: ${PQ_DEBUG_LEVEL}")
endif()

if(CYCLONEDDS_PATH)
  list(PREPEND CMAKE_PREFIX_PATH "${CYCLONEDDS_PATH}")
  set(CycloneDDS_DIR "${CYCLONEDDS_PATH}/${CMAKE_INSTALL_LIBDIR}/cmake/CycloneDDS"
      CACHE PATH "CycloneDDS package directory")
endif()
find_package(CycloneDDS REQUIRED)
find_package(Threads REQUIRED)
if(ENABLE_PQ_CRYPTO)
  # ML-DSA is part of OpenSSL's default provider beginning with OpenSSL 3.5.
  find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto SSL)
else()
  find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)
endif()

add_library(dds_pqsec SHARED
  authentication.c
  auth_algs.c
  auth_utils.c
  debug.c
  openssl/src/openssl_support.c
)

if(ENABLE_PQ_CRYPTO)
  target_sources(dds_pqsec PRIVATE pq_kem.c)
endif()

target_include_directories(dds_pqsec PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/openssl/include"
)

target_link_libraries(dds_pqsec PRIVATE
  CycloneDDS::ddsc
  OpenSSL::SSL
  OpenSSL::Crypto
  Threads::Threads
)
target_compile_definitions(dds_pqsec PRIVATE
  _POSIX_C_SOURCE=200809L
  SELECTED_KEM_ALGORITHM="${SELECTED_KEM_ALGORITHM}"
  PQSEC_FALLBACK_PROVIDER="${PQSEC_FALLBACK_PROVIDER}"
  PQ_LOGGING_ENABLED=$<BOOL:${ENABLE_PQ_LOGGING}>
  PQ_DEFAULT_LOG_LEVEL=${PQ_DEBUG_LEVEL_NUM}
)
if(ENABLE_PQ_CRYPTO)
  target_compile_definitions(dds_pqsec PRIVATE PQ_CRYPTO=1)
endif()
if(DEBUG)
  target_compile_definitions(dds_pqsec PRIVATE PLUGIN_DEBUG=1)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(dds_pqsec PRIVATE
    -Wall -Wextra -Wformat=2 -Wshadow
    -Wstrict-prototypes -Wmissing-prototypes
  )
endif()

set_target_properties(dds_pqsec PROPERTIES
  OUTPUT_NAME dds_pqsec
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
)

if(BUILD_TESTING AND ENABLE_PQ_CRYPTO)
  add_executable(pqsec_cyclonedds_kem_test
    tests/pq_kem_test.c
    auth_algs.c
    pq_kem.c
  )
  target_include_directories(pqsec_cyclonedds_kem_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(pqsec_cyclonedds_kem_test PRIVATE
    CycloneDDS::ddsc OpenSSL::Crypto)
  target_compile_definitions(pqsec_cyclonedds_kem_test PRIVATE
    _POSIX_C_SOURCE=200809L
    SELECTED_KEM_ALGORITHM="${SELECTED_KEM_ALGORITHM}")
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqsec_cyclonedds_kem_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cyclonedds.pq_kem COMMAND pqsec_cyclonedds_kem_test)

  add_executable(pqsec_cyclonedds_signature_test tests/pq_signature_test.c)
  target_include_directories(pqsec_cyclonedds_signature_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")
  target_link_libraries(pqsec_cyclonedds_signature_test PRIVATE
    dds_pqsec OpenSSL::Crypto CycloneDDS::ddsc)
  target_compile_definitions(pqsec_cyclonedds_signature_test PRIVATE
    _POSIX_C_SOURCE=200809L PQ_CRYPTO=1)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(pqsec_cyclonedds_signature_test PRIVATE
      -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME cyclonedds.mldsa_transcript
           COMMAND pqsec_cyclonedds_signature_test)
endif()
