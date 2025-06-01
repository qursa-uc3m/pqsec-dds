#!/bin/bash
#
# setup_env.sh — Set environment variables
# Copyright (C) 2023-2025 Javier Blanco-Romero
#

echo "=== Setting up PQSec DDS Environment ==="

# Step 1: Set up OQS environment
echo "1. Setting up OQS environment..."
if [ -f "./setup_oqs_env.sh" ]; then
    source ./setup_oqs_env.sh
elif [ -f "/opt/oqs_openssl3/setup_env.sh" ]; then
    source /opt/oqs_openssl3/setup_env.sh
else
    echo "⚠ Warning: OQS setup script not found, setting up manually..."
    export OPENSSL_ROOT_DIR="/opt/oqs_openssl3/.local"
    export OPENSSL_CONF="/opt/oqs_openssl3/.local/ssl/openssl.cnf"
    export OPENSSL_MODULES="/opt/oqs_openssl3/.local/lib64/ossl-modules"
    export LD_LIBRARY_PATH="/opt/oqs_openssl3/.local/lib64:$LD_LIBRARY_PATH"
    export OQS_PROVIDER_NAME="oqsprovider"
    export OQS_PROVIDER_PATH="/opt/oqs_openssl3"
fi

echo ""

# Step 2: Set up DDS environment
echo "2. Setting up DDS environment..."
if [ -f "./setup_dds_env.sh" ]; then
    source ./setup_dds_env.sh
else
    echo "⚠ Warning: DDS setup script not found, setting up with defaults..."
    # Default DDS setup - use local installation first
    if [ -d "./cyclonedds_install/lib" ]; then
        export LD_LIBRARY_PATH="./cyclonedds_install/lib:$LD_LIBRARY_PATH"
        echo "✓ CycloneDDS (local): ./cyclonedds_install/lib"
    elif [ -d "/opt/cyclonedds/lib" ]; then
        export LD_LIBRARY_PATH="/opt/cyclonedds/lib:$LD_LIBRARY_PATH"
        echo "✓ CycloneDDS (system): /opt/cyclonedds/lib"
    else
        echo "⚠ Warning: CycloneDDS not found. Build with: ./scripts/build_cyclonedds.sh"
    fi
    if [ -d "/opt/liboqs/lib64" ]; then
        export LD_LIBRARY_PATH="/opt/liboqs/lib64:$LD_LIBRARY_PATH"
    elif [ -d "/opt/liboqs/lib" ]; then
        export LD_LIBRARY_PATH="/opt/liboqs/lib:$LD_LIBRARY_PATH"
    fi
    # Look for plugin library in common locations
    if [ -d "./src/build/lib" ]; then
        export LD_LIBRARY_PATH="./src/build/lib:$LD_LIBRARY_PATH"
        echo "✓ Plugin library: ./src/build/lib"
    elif [ -d "./build/lib" ]; then
        export LD_LIBRARY_PATH="./build/lib:$LD_LIBRARY_PATH"
        echo "✓ Plugin library: ./build/lib"
    else
        echo "⚠ Warning: Plugin library not found. Build with: ./scripts/build_plugin.sh"
    fi
    if [ -f "./config/cyclonedds/custom_auth_plugin.xml" ]; then
        export CYCLONEDDS_URI="./config/cyclonedds/custom_auth_plugin_mldsa44.xml"
    fi
fi

echo ""
echo "=== Environment Setup Complete ==="
echo "You can now run your DDS applications:"
echo "  ./cyclonedds_install/bin/HelloworldPublisher"
echo "  ./cyclonedds_install/bin/HelloworldSubscriber"