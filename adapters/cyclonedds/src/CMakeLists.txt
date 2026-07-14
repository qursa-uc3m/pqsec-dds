#
# Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
# Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M) - Initial PQ integration
#
# PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
# CMakeLists.txt - Build configuration and dependencies
#
# This authentication plugin implements Post-Quantum Cryptography algorithms
# for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
# built-in authentication plugin and DDS Security specification v1.1.
#

cmake_minimum_required(VERSION 3.10)
project(PQSec-DDS_plugin)

set(CMAKE_C_STANDARD 99)

# Options
option(ENABLE_PQ_CRYPTO "Enable Post-Quantum Cryptography support" OFF)
option(DEBUG "Plugin debug" OFF)

# ================================
# SIMPLE DEBUG CONFIGURATION
# ================================
option(ENABLE_PQ_LOGGING "Enable PQ-DDS logging system" ON)

# Debug level options (can be set via -DPQ_DEBUG_LEVEL=...)
set(PQ_DEBUG_LEVEL "TRACE" CACHE STRING "Default debug level (NONE|ERROR|WARN|INFO|TRACE|DATA)")
set_property(CACHE PQ_DEBUG_LEVEL PROPERTY STRINGS "NONE" "ERROR" "WARN" "INFO" "TRACE" "DATA")

# Validate debug level
set(VALID_DEBUG_LEVELS "NONE" "ERROR" "WARN" "INFO" "TRACE" "DATA")
list(FIND VALID_DEBUG_LEVELS "${PQ_DEBUG_LEVEL}" DEBUG_LEVEL_INDEX)
if(DEBUG_LEVEL_INDEX EQUAL -1)
    message(FATAL_ERROR 
        "Invalid debug level '${PQ_DEBUG_LEVEL}'. "
        "Valid levels: ${VALID_DEBUG_LEVELS}")
endif()

# Convert debug level to numeric value
if(PQ_DEBUG_LEVEL STREQUAL "NONE")
    set(PQ_DEBUG_LEVEL_NUM 0)
elseif(PQ_DEBUG_LEVEL STREQUAL "ERROR")
    set(PQ_DEBUG_LEVEL_NUM 1)
elseif(PQ_DEBUG_LEVEL STREQUAL "WARN")
    set(PQ_DEBUG_LEVEL_NUM 2)
elseif(PQ_DEBUG_LEVEL STREQUAL "INFO")
    set(PQ_DEBUG_LEVEL_NUM 3)
elseif(PQ_DEBUG_LEVEL STREQUAL "TRACE")
    set(PQ_DEBUG_LEVEL_NUM 4)
elseif(PQ_DEBUG_LEVEL STREQUAL "DATA")
    set(PQ_DEBUG_LEVEL_NUM 5)
endif()

message(STATUS "PQ-DDS Debug Level: ${PQ_DEBUG_LEVEL} (${PQ_DEBUG_LEVEL_NUM})")

# ================================
# KEM ALGORITHM CONFIGURATION
# ================================

# Set default if not specified
if(NOT DEFINED SELECTED_KEM_ALGORITHM)
    if(ENABLE_PQ_CRYPTO)
        set(SELECTED_KEM_ALGORITHM "mlkem768")
    else()
        set(SELECTED_KEM_ALGORITHM "ecdh_p256")
    endif()
endif()

# Define supported algorithms for validation
set(SUPPORTED_KEM_ALGORITHMS
    # Classical
    "ecdh_p256" "dh_2048"
    # ML-KEM
    "mlkem512" "mlkem768" "mlkem1024"
    # Hybrid
    "X25519MLKEM768" "p256_mlkem768"
)

# Validate the selected algorithm
list(FIND SUPPORTED_KEM_ALGORITHMS "${SELECTED_KEM_ALGORITHM}" ALGO_INDEX)
if(ALGO_INDEX EQUAL -1)
    message(FATAL_ERROR 
        "Invalid KEM algorithm '${SELECTED_KEM_ALGORITHM}'. "
        "Supported algorithms: ${SUPPORTED_KEM_ALGORITHMS}")
endif()

message(STATUS "Selected KEM Algorithm: ${SELECTED_KEM_ALGORITHM}")

# ================================
# PATH CONFIGURATION
# ================================

# Required paths
if(NOT CYCLONEDDS_PATH)
    message(FATAL_ERROR "CYCLONEDDS_PATH not provided. Please specify the path to CycloneDDS using -DCYCLONEDDS_PATH=/path/to/cyclonedds")
endif()

if(NOT LIBOQS_PATH)
    message(FATAL_ERROR "LIBOQS_PATH not provided. Please specify the path to liboqs using -DLIBOQS_PATH=/path/to/liboqs")
endif()

# Set CMAKE_PREFIX_PATH to help find packages
list(APPEND CMAKE_PREFIX_PATH "${CYCLONEDDS_PATH}")
list(APPEND CMAKE_PREFIX_PATH "${LIBOQS_PATH}")

# Set CycloneDDS_DIR explicitly to help find the config files
set(CycloneDDS_DIR "${CYCLONEDDS_PATH}/lib/cmake/CycloneDDS")

# OQS Provider configuration
set(OQS_PROVIDER_PATH "/opt/oqs_openssl3" CACHE PATH "Path to OQS Provider installation")
set(OQS_PROVIDER_NAME "oqsprovider" CACHE STRING "Name of the OQS provider")

# OpenSSL configuration
if(OPENSSL_PATH)
    message(STATUS "Using provided OpenSSL path: ${OPENSSL_PATH}")
    set(OPENSSL_ROOT_DIR ${OPENSSL_PATH})
    list(APPEND CMAKE_PREFIX_PATH "${OPENSSL_PATH}")
    set(OQS_OPENSSL_CONF "${OPENSSL_PATH}/.local/ssl/openssl.cnf" CACHE PATH "Path to OpenSSL configuration file")
else()
    message(STATUS "Using system default OpenSSL installation.")
    set(OQS_OPENSSL_CONF "" CACHE PATH "Path to OpenSSL configuration file")
endif()

# ================================
# FIND PACKAGES
# ================================

find_package(OpenSSL REQUIRED)
find_package(CycloneDDS REQUIRED)

# Try to use modern CycloneDDS targets first
if(TARGET CycloneDDS::ddsc)
    message(STATUS "✓ Using CycloneDDS modern CMake targets")
    set(CYCLONEDDS_TARGET CycloneDDS::ddsc)
    
    # Get include directories from the target (if available)
    get_target_property(CYCLONEDDS_INCLUDES CycloneDDS::ddsc INTERFACE_INCLUDE_DIRECTORIES)
    if(CYCLONEDDS_INCLUDES)
        set(CycloneDDS_INCLUDE_DIRS ${CYCLONEDDS_INCLUDES})
        message(STATUS "Got include dirs from target: ${CycloneDDS_INCLUDE_DIRS}")
    else()
        # Fallback to manual path
        set(CycloneDDS_INCLUDE_DIRS "${CYCLONEDDS_PATH}/include")
        message(STATUS "Using manual CycloneDDS include path: ${CycloneDDS_INCLUDE_DIRS}")
    endif()
    
else()
    message(STATUS "CycloneDDS modern targets not found, using manual detection")
    
    # Manual fallback approach
    set(CycloneDDS_INCLUDE_DIRS "${CYCLONEDDS_PATH}/include")
    message(STATUS "Using manual CycloneDDS include path: ${CycloneDDS_INCLUDE_DIRS}")
    
    find_library(DDSC_LIBRARY ddsc PATHS "${CYCLONEDDS_PATH}/lib" NO_DEFAULT_PATH)
    if(DDSC_LIBRARY)
        set(CycloneDDS_LIBRARIES ${DDSC_LIBRARY})
        set(CYCLONEDDS_TARGET ${DDSC_LIBRARY})
        message(STATUS "Found CycloneDDS library manually: ${DDSC_LIBRARY}")
    else()
        message(FATAL_ERROR "Could not find CycloneDDS library at ${CYCLONEDDS_PATH}/lib")
    endif()
endif()

# Find liboqs
find_path(LIBOQS_INCLUDE_DIR 
    NAMES oqs/oqs.h
    PATHS ${LIBOQS_PATH}/include
    NO_DEFAULT_PATH
)

find_library(LIBOQS_LIBRARY
    NAMES oqs
    PATHS ${LIBOQS_PATH}/lib ${LIBOQS_PATH}/lib64
    NO_DEFAULT_PATH
)

# If not found in the provided path, try the OQS provider path
if(NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
    if(OQS_PROVIDER_PATH)
        find_path(LIBOQS_INCLUDE_DIR 
            NAMES oqs/oqs.h
            PATHS ${OQS_PROVIDER_PATH}/.local/include
            NO_DEFAULT_PATH
        )
        
        find_library(LIBOQS_LIBRARY
            NAMES oqs
            PATHS ${OQS_PROVIDER_PATH}/.local/lib ${OQS_PROVIDER_PATH}/.local/lib64
            NO_DEFAULT_PATH
        )
    endif()
endif()

if(NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
    message(FATAL_ERROR "liboqs not found. Tried paths: ${LIBOQS_PATH} and ${OQS_PROVIDER_PATH}/.local")
endif()

# Debug output
message(STATUS "OpenSSL_VERSION: ${OpenSSL_VERSION}")
message(STATUS "OpenSSL include directory: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "CycloneDDS include directories: ${CycloneDDS_INCLUDE_DIRS}")
if(DEFINED CYCLONEDDS_TARGET)
    message(STATUS "CycloneDDS target: ${CYCLONEDDS_TARGET}")
endif()
if(DEFINED CycloneDDS_LIBRARIES)
    message(STATUS "CycloneDDS libraries: ${CycloneDDS_LIBRARIES}")
endif()
message(STATUS "liboqs include: ${LIBOQS_INCLUDE_DIR}")
message(STATUS "liboqs library: ${LIBOQS_LIBRARY}")
message(STATUS "OQS Provider path: ${OQS_PROVIDER_PATH}")
message(STATUS "OQS Provider name: ${OQS_PROVIDER_NAME}")
message(STATUS "OQS OpenSSL config: ${OQS_OPENSSL_CONF}")

# Verify CycloneDDS headers exist
if(EXISTS "${CycloneDDS_INCLUDE_DIRS}/dds/ddsrt/heap.h")
    message(STATUS "✓ Found CycloneDDS heap.h header")
else()
    message(FATAL_ERROR "✗ CycloneDDS heap.h header not found at ${CycloneDDS_INCLUDE_DIRS}/dds/ddsrt/heap.h")
endif()

# Set library output directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ================================
# CREATE LIBRARY
# ================================

# Create the shared library
add_library(dds_pqsec SHARED
    authentication.c
    auth_algs.c
    auth_utils.c
    bench_hook.c
    debug.c                              # Use correct filename
    openssl/src/openssl_support.c
)

# Set include directories
target_include_directories(dds_pqsec PRIVATE
    ${PROJECT_SOURCE_DIR}
    "${PROJECT_SOURCE_DIR}/include" 
    "${PROJECT_SOURCE_DIR}/openssl/include"
    ${CycloneDDS_INCLUDE_DIRS}
    ${LIBOQS_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries - use modern targets when available
target_link_libraries(dds_pqsec
    ${CYCLONEDDS_TARGET}  # This will be either CycloneDDS::ddsc or the library path
    OpenSSL::SSL
    OpenSSL::Crypto
    ${LIBOQS_LIBRARY}
    pthread                               # Add pthread for debug system
)

# ================================
# COMPILE DEFINITIONS
# ================================

# Core definitions
target_compile_definitions(dds_pqsec PRIVATE
    SELECTED_KEM_ALGORITHM="${SELECTED_KEM_ALGORITHM}"
    OQS_PROVIDER_NAME="${OQS_PROVIDER_NAME}"
    MEASURE_HANDSHAKE_TIME=1
    
    # Ensure proper macro definitions
    _GNU_SOURCE=1
)

# OpenSSL config
if(OQS_OPENSSL_CONF)
    target_compile_definitions(dds_pqsec PRIVATE
        OQS_OPENSSL_CONF="${OQS_OPENSSL_CONF}"
    )
endif()

# Post-quantum crypto
if(ENABLE_PQ_CRYPTO)
    target_compile_definitions(dds_pqsec PRIVATE PQ_CRYPTO)
    message(STATUS "PQ_CRYPTO is enabled.")
else()
    message(STATUS "PQ_CRYPTO is disabled.")
endif()

# Legacy debug mode
if(DEBUG)
    target_compile_definitions(dds_pqsec PRIVATE PLUGIN_DEBUG)
    message(STATUS "Legacy debug mode is enabled.")
else()
    message(STATUS "Legacy debug mode is disabled.")
endif()

# Simple PQ debug system
if(ENABLE_PQ_LOGGING)
    target_compile_definitions(dds_pqsec PRIVATE
        PQ_LOGGING_ENABLED=1
        PQ_DEFAULT_LOG_LEVEL=${PQ_DEBUG_LEVEL_NUM}
    )
    message(STATUS "PQ-DDS logging enabled (default level: ${PQ_DEBUG_LEVEL})")
else()
    target_compile_definitions(dds_pqsec PRIVATE PQ_LOGGING_ENABLED=0)
    message(STATUS "PQ-DDS logging disabled")
endif()

# Add compiler warnings for unused functions and variables
#if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
#    target_compile_options(dds_pqsec PRIVATE
#        -Wunused-function
#        -Wunused-variable  
#        -Wunused-parameter
#        -Wunused-but-set-variable
#        -Wunreachable-code
#        -Wall
#        -Wextra
#    )
#    message(STATUS "Added unused function detection warnings")
#endif()

# Set library properties
set_target_properties(dds_pqsec PROPERTIES
    VERSION 1.0
    SOVERSION 1
)

# Environment setup target
add_custom_target(set_env
    COMMAND ${CMAKE_COMMAND} -E echo "Setting environment variables for OQS provider:"
    COMMAND ${CMAKE_COMMAND} -E echo "export OPENSSL_MODULES=${OQS_PROVIDER_PATH}/.local/lib64/ossl-modules"
    COMMAND ${CMAKE_COMMAND} -E echo "export OPENSSL_CONF=${OQS_OPENSSL_CONF}"
    COMMAND ${CMAKE_COMMAND} -E echo "export OQS_PROVIDER_NAME=${OQS_PROVIDER_NAME}"
    COMMAND ${CMAKE_COMMAND} -E echo "export LD_LIBRARY_PATH=${OQS_PROVIDER_PATH}/.local/lib64:\$LD_LIBRARY_PATH"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Debug environment variables (optional):"
    COMMAND ${CMAKE_COMMAND} -E echo "export PQ_DEBUG_LEVEL=${PQ_DEBUG_LEVEL}    # Override compile-time default"
    COMMAND ${CMAKE_COMMAND} -E echo "export PQ_DEBUG_LEVEL=TRACE               # Set to TRACE level"
    COMMAND ${CMAKE_COMMAND} -E echo "export PQ_DEBUG_LEVEL=INFO                # Set to INFO level"
    COMMAND ${CMAKE_COMMAND} -E echo "export PQ_DEBUG_LEVEL=NONE                # Disable debug output"
)

# Debug configuration summary
add_custom_target(debug_info
    COMMAND ${CMAKE_COMMAND} -E echo "═══ PQ-DDS Debug Configuration ═══"
    COMMAND ${CMAKE_COMMAND} -E echo "Logging enabled: ${ENABLE_PQ_LOGGING}"
    COMMAND ${CMAKE_COMMAND} -E echo "Default level: ${PQ_DEBUG_LEVEL} (${PQ_DEBUG_LEVEL_NUM})"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "To change debug level at runtime:"
    COMMAND ${CMAKE_COMMAND} -E echo "export PQ_DEBUG_LEVEL=TRACE"
    COMMAND ${CMAKE_COMMAND} -E echo "export PQ_DEBUG_LEVEL=6      # or use numbers 0-5"
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "Debug levels (higher includes lower):"
    COMMAND ${CMAKE_COMMAND} -E echo "  0=NONE  1=ERROR  2=WARN  3=INFO  4=TRACE  5=DATA"
)