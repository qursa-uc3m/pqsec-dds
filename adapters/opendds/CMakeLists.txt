cmake_minimum_required(VERSION 3.16)
project(OpenDDS_PQSec VERSION 0.1.0 LANGUAGES CXX)

option(PQSEC_BUILD_TESTS "Build PQSec tests" ON)
set(OPENDDS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../OpenDDS" CACHE PATH "OpenDDS source/build root")
set(OPENSSL_ROOT_DIR "/opt/openssl3_local/.local" CACHE PATH "OpenSSL 3.6+ installation")

set(OpenDDS_DIR "${OPENDDS_ROOT}/cmake")
set(OPENSSL_USE_STATIC_LIBS TRUE)
# CMake 3.22's FindOpenSSL can otherwise combine headers from a custom prefix
# with a system libcrypto when the custom installation uses lib64.
if(EXISTS "${OPENSSL_ROOT_DIR}/lib64")
  list(PREPEND CMAKE_LIBRARY_PATH "${OPENSSL_ROOT_DIR}/lib64")
  if(OPENSSL_USE_STATIC_LIBS AND EXISTS "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib64/libcrypto.a"
      CACHE FILEPATH "OpenSSL crypto library" FORCE)
  endif()
endif()
find_package(OpenSSL 3.6 REQUIRED COMPONENTS Crypto)
find_package(OpenDDS REQUIRED COMPONENTS NO_DEFAULTS
  OpenDDS::Dcps OpenDDS::Security OpenDDS::Rtps OpenDDS::Rtps_Udp
  security=TRUE)

add_library(OpenDDS_PQSec SHARED
  src/Authentication.cpp
  src/Crypto.cpp
  src/Plugin.cpp
  src/Transcript.cpp
)
add_library(PQSec::OpenDDS ALIAS OpenDDS_PQSec)
target_compile_features(OpenDDS_PQSec PUBLIC cxx_std_11)
target_include_directories(OpenDDS_PQSec
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(OpenDDS_PQSec
  PUBLIC OpenDDS::Dcps OpenDDS::Security
  PRIVATE OpenSSL::Crypto ACE::ACE
)
target_compile_definitions(OpenDDS_PQSec PRIVATE OPENDDS_PQSEC_BUILD_DLL)
set_target_properties(OpenDDS_PQSec PROPERTIES OUTPUT_NAME OpenDDS_PQSec)

if(PQSEC_BUILD_TESTS)
  enable_testing()
  add_executable(pqsec_crypto_test tests/CryptoTest.cpp)
  target_compile_features(pqsec_crypto_test PRIVATE cxx_std_11)
  target_include_directories(pqsec_crypto_test PRIVATE src)
  target_link_libraries(pqsec_crypto_test PRIVATE OpenDDS_PQSec OpenSSL::Crypto)
  add_test(NAME pqsec_crypto COMMAND pqsec_crypto_test)

  find_program(PQSEC_OPENSSL_EXECUTABLE openssl
    HINTS "${OPENSSL_ROOT_DIR}/bin"
    NO_DEFAULT_PATH
    REQUIRED)
  set(PQSEC_TEST_CERT_DIR "${CMAKE_CURRENT_BINARY_DIR}/test-certs")
  add_custom_command(
    OUTPUT "${PQSEC_TEST_CERT_DIR}/.generated"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${PQSEC_TEST_CERT_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E env OPENSSL_CONF=/etc/ssl/openssl.cnf
      "${CMAKE_CURRENT_SOURCE_DIR}/tests/generate_certs.sh"
      "${PQSEC_OPENSSL_EXECUTABLE}" "${PQSEC_TEST_CERT_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E touch "${PQSEC_TEST_CERT_DIR}/.generated"
    DEPENDS tests/generate_certs.sh
    VERBATIM)
  add_custom_target(pqsec_test_certificates
    DEPENDS "${PQSEC_TEST_CERT_DIR}/.generated")

  add_executable(pqsec_authentication_test tests/AuthenticationTest.cpp)
  add_dependencies(pqsec_authentication_test pqsec_test_certificates)
  target_compile_features(pqsec_authentication_test PRIVATE cxx_std_11)
  target_include_directories(pqsec_authentication_test PRIVATE src)
  target_compile_definitions(pqsec_authentication_test PRIVATE
    PQSEC_TEST_CERT_DIR="${PQSEC_TEST_CERT_DIR}")
  target_link_libraries(pqsec_authentication_test PRIVATE OpenDDS_PQSec OpenDDS::Rtps)
  add_test(NAME pqsec_authentication_handshake COMMAND pqsec_authentication_test)

  add_executable(pqsec_loader_test tests/LoaderTest.cpp)
  target_compile_features(pqsec_loader_test PRIVATE cxx_std_11)
  target_link_libraries(pqsec_loader_test PRIVATE OpenDDS::Dcps OpenDDS::Security OpenDDS::Rtps_Udp)
  add_test(NAME pqsec_external_loader COMMAND pqsec_loader_test -DCPSConfigFile ${CMAKE_CURRENT_BINARY_DIR}/pqsec_loader.ini)
  set(PQSEC_TEST_LIBRARY_PATH
    "$<TARGET_FILE_DIR:OpenDDS_PQSec>:${OPENDDS_ROOT}/lib:${OPENDDS_ROOT}/ACE_wrappers/lib:$ENV{LD_LIBRARY_PATH}")
  set_tests_properties(
    pqsec_crypto pqsec_authentication_handshake pqsec_external_loader
    PROPERTIES ENVIRONMENT "LD_LIBRARY_PATH=${PQSEC_TEST_LIBRARY_PATH}")

  set(PQSEC_PLUGIN_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}OpenDDS_PQSec")
  configure_file(config/pqsec_loader.ini pqsec_loader.ini @ONLY)
endif()

install(TARGETS OpenDDS_PQSec LIBRARY DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
