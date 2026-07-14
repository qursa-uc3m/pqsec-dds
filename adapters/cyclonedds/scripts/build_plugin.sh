#!/bin/bash
#
# build_plugin.sh — Build PQSec-DDS plugin
# Copyright (C) 2023-2025 Javier Blanco-Romero
#

set -e  # Exit on any error

# Default values
CYCLONEDDS_PATH="./cyclonedds_install"
LIBOQS_PATH="/opt/oqs_openssl3/.local"  # liboqs is built as part of OQS provider
OQS_PROVIDER_PATH="/opt/oqs_openssl3"
BUILD_TYPE="Debug"
PARALLEL_JOBS=$(nproc)

# Default plugin options
ENABLE_PQ_CRYPTO="ON"
PQ_DEBUG_LEVEL="INFO" # Default to INFO
SELECTED_KEM_ALGORITHM="mlkem512" # Default to ML-KEM-768 for PQ builds

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -c DIR              CycloneDDS path (default: ./cyclonedds_install)
    -l DIR              liboqs path (default: /opt/oqs_openssl3/.local)
    -o DIR              OQS provider path (default: /opt/oqs_openssl3)
    -t TYPE             Build type: Debug|Release (default: Debug)
    -j JOBS             Parallel build jobs (default: $(nproc))
    --pq                Enable PQ crypto (default)
    --no-pq             Disable PQ crypto (use traditional DH)
    --kem ALGORITHM     Select KEM algorithm (see list below)
    --debug-level LEVEL Set debug level: NONE|ERROR|WARN|INFO|TRACE|DATA (default: INFO)
    -f                  Force clean rebuild
    -h                  Show this help message

KEM ALGORITHMS:
    Classical (traditional):
        ecdh_p256       ECDH P-256 (default for --no-pq)
        dh_2048         Diffie-Hellman 2048-bit

    Post-Quantum (ML-KEM):
        mlkem512        ML-KEM-512 (128-bit security)
        mlkem768        ML-KEM-768 (192-bit security, default for --pq)
        mlkem1024       ML-KEM-1024 (256-bit security)

    Hybrid:
        X25519MLKEM768  X25519 + ML-KEM-768
        p256_mlkem768   P-256 + ML-KEM-768

DEBUG LEVELS:
    NONE                No debug output
    ERROR               Error messages only
    WARN                Warnings and errors
    INFO                General information + above (default)
    TRACE               Detailed tracing + above
    DATA                Data dumps and hex output + above

EXAMPLES:
    # Default PQ build with ML-KEM-768
    $0

    # Use ML-KEM-1024 for maximum security
    $0 --kem mlkem1024

    # Traditional ECDH build
    $0 --no-pq --kem ecdh_p256

    # Production build with ML-KEM-512 and minimal logging
    $0 -t Release --kem mlkem512 --debug-level INFO

    # Development build with maximum verbosity
    $0 --kem mlkem768 --debug-level DATA

    # Custom paths
    $0 -c /custom/cyclonedds -l /custom/liboqs --kem mlkem768

    # Force clean rebuild with specific algorithm
    $0 -f --kem mlkem1024

EOF
}

# Parse command line arguments
FORCE_CLEAN=0
while [[ $# -gt 0 ]]; do
    case $1 in
        -c)
            CYCLONEDDS_PATH="$2"
            shift 2
            ;;
        -l)
            LIBOQS_PATH="$2"
            shift 2
            ;;
        -o)
            OQS_PROVIDER_PATH="$2"
            shift 2
            ;;
        -t)
            BUILD_TYPE="$2"
            shift 2
            ;;
        -j)
            PARALLEL_JOBS="$2"
            shift 2
            ;;
        --pq)
            ENABLE_PQ_CRYPTO="ON"
            shift
            ;;
        --no-pq)
            ENABLE_PQ_CRYPTO="OFF"
            shift
            ;;
        --kem)
            SELECTED_KEM_ALGORITHM="$2"
            shift 2
            ;;
        --debug-level)
            PQ_DEBUG_LEVEL="$2"
            shift 2
            ;;
        -f)
            FORCE_CLEAN=1
            shift
            ;;
        -h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option $1"
            usage
            exit 1
            ;;
    esac
done

# Override default KEM algorithm if not specified explicitly
if [ -z "$SELECTED_KEM_ALGORITHM" ] || [ "$SELECTED_KEM_ALGORITHM" = "mlkem768" ]; then
    if [ "$ENABLE_PQ_CRYPTO" = "ON" ]; then
        SELECTED_KEM_ALGORITHM="mlkem768"
    else
        SELECTED_KEM_ALGORITHM="ecdh_p256"
    fi
fi

# Validate KEM algorithm
CLASSICAL_ALGS="ecdh_p256 dh_2048"
PQ_ALGS="mlkem512 mlkem768 mlkem1024"
HYBRID_ALGS="X25519MLKEM768 p256_mlkem768"
ALL_ALGS="$CLASSICAL_ALGS $PQ_ALGS $HYBRID_ALGS"

if [[ ! " $ALL_ALGS " =~ " $SELECTED_KEM_ALGORITHM " ]]; then
    echo "Error: Invalid KEM algorithm '$SELECTED_KEM_ALGORITHM'"
    echo "Valid algorithms: $ALL_ALGS"
    exit 1
fi

# Check algorithm compatibility with PQ setting
if [ "$ENABLE_PQ_CRYPTO" = "OFF" ]; then
    if [[ " $PQ_ALGS $HYBRID_ALGS " =~ " $SELECTED_KEM_ALGORITHM " ]]; then
        echo "Error: PQ algorithm '$SELECTED_KEM_ALGORITHM' requires --pq flag"
        echo "Use --pq or select a classical algorithm: $CLASSICAL_ALGS"
        exit 1
    fi
elif [ "$ENABLE_PQ_CRYPTO" = "ON" ]; then
    if [[ " $CLASSICAL_ALGS " =~ " $SELECTED_KEM_ALGORITHM " ]]; then
        echo "Warning: Using classical algorithm '$SELECTED_KEM_ALGORITHM' with PQ crypto enabled"
        echo "Consider using a PQ algorithm: $PQ_ALGS"
    fi
fi

# Convert paths to absolute paths
CYCLONEDDS_PATH=$(realpath "$CYCLONEDDS_PATH")
LIBOQS_PATH=$(realpath "$LIBOQS_PATH")
OQS_PROVIDER_PATH=$(realpath "$OQS_PROVIDER_PATH")

# Validate build type
if [[ ! "$BUILD_TYPE" =~ ^(Debug|Release)$ ]]; then
    echo "Error: Build type must be Debug or Release"
    exit 1
fi

# Validate debug level
VALID_DEBUG_LEVELS="NONE ERROR WARN INFO TRACE DATA"
if [[ ! " $VALID_DEBUG_LEVELS " =~ " $PQ_DEBUG_LEVEL " ]]; then
    echo "Error: Invalid debug level '$PQ_DEBUG_LEVEL'"
    echo "Valid levels: $VALID_DEBUG_LEVELS"
    exit 1
fi

# Display configuration
echo "=== PQSec DDS Plugin Build Configuration ==="
echo "CycloneDDS path: $CYCLONEDDS_PATH"
echo "liboqs path: $LIBOQS_PATH"
echo "OQS provider path: $OQS_PROVIDER_PATH"
echo "Build type: $BUILD_TYPE"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "PQ Crypto: $ENABLE_PQ_CRYPTO"
echo "KEM Algorithm: $SELECTED_KEM_ALGORITHM"
echo "PQ Debug level: $PQ_DEBUG_LEVEL"
echo "Force clean: $FORCE_CLEAN"
echo "==============================="

# Check if required paths exist
echo "Checking dependencies..."

if [ ! -d "$CYCLONEDDS_PATH" ]; then
    echo "Error: CycloneDDS not found at $CYCLONEDDS_PATH"
    echo "Build CycloneDDS first with: ./scripts/build_cyclonedds.sh"
    exit 1
fi

# Check for CMake config files specifically
if [ ! -f "$CYCLONEDDS_PATH/lib/cmake/CycloneDDS/CycloneDDSConfig.cmake" ]; then
    echo "Error: CycloneDDS CMake config not found at $CYCLONEDDS_PATH/lib/cmake/CycloneDDS/"
    echo "Please rebuild CycloneDDS with: ./scripts/build_cyclonedds.sh -f"
    exit 1
fi
echo "✓ CycloneDDS found"

if [ "$ENABLE_PQ_CRYPTO" = "ON" ]; then
    if [ ! -d "$OQS_PROVIDER_PATH" ]; then
        echo "Error: OQS provider not found at $OQS_PROVIDER_PATH"
        echo "Build OQS first with: ./scripts/build_oqs_enhanced.sh"
        exit 1
    fi
    echo "✓ OQS provider found"

    if [ ! -d "$LIBOQS_PATH" ] && [ ! -d "$OQS_PROVIDER_PATH/.local" ]; then
        echo "Error: liboqs not found at $LIBOQS_PATH or $OQS_PROVIDER_PATH/.local"
        echo "liboqs should be installed as part of the OQS provider build"
        echo "Build OQS first with: ./scripts/build_oqs_enhanced.sh"
        exit 1
    fi
    echo "✓ liboqs found"
else
    echo "ℹ PQ crypto disabled - skipping OQS checks"
fi

# Determine source directory (script is in scripts/, CMakeLists.txt is in src/)
if [ -f "../src/CMakeLists.txt" ]; then
    SRC_DIR="../src"
elif [ -f "src/CMakeLists.txt" ]; then
    SRC_DIR="src"
else
    echo "Error: Cannot find src/CMakeLists.txt. Expected structure: scripts/build_plugin.sh and src/CMakeLists.txt"
    exit 1
fi

BUILD_DIR="$SRC_DIR/build"

# Handle existing build
if [ "$FORCE_CLEAN" -eq 1 ] && [ -d "$BUILD_DIR" ]; then
    echo "Force clean requested - removing existing build..."
    rm -rf "$BUILD_DIR"
elif [ -d "$BUILD_DIR" ] && [ "$(ls -A $BUILD_DIR 2>/dev/null)" ]; then
    read -p "Build directory exists. Clean and rebuild? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        rm -rf "$BUILD_DIR"
    fi
fi

# Create build directory
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo ""
echo "=== BUILDING PQSEC DDS PLUGIN ==="

# Set up OpenSSL path for PQ builds
OPENSSL_PATH=""
if [ "$ENABLE_PQ_CRYPTO" = "ON" ]; then
    if [ -d "$OQS_PROVIDER_PATH/.local" ]; then
        OPENSSL_PATH="$OQS_PROVIDER_PATH/.local"
    else
        OPENSSL_PATH="$OQS_PROVIDER_PATH"
    fi
fi

# Configure the plugin
echo "Configuring plugin with KEM algorithm: $SELECTED_KEM_ALGORITHM, debug level: $PQ_DEBUG_LEVEL..."
cmake_args=(
    "-DCYCLONEDDS_PATH=$CYCLONEDDS_PATH"
    "-DLIBOQS_PATH=$LIBOQS_PATH"
    "-DENABLE_PQ_CRYPTO=$ENABLE_PQ_CRYPTO"
    "-DSELECTED_KEM_ALGORITHM=$SELECTED_KEM_ALGORITHM"
    "-DPQ_DEBUG_LEVEL=$PQ_DEBUG_LEVEL"
)

# Add OpenSSL path if PQ crypto is enabled
if [ "$ENABLE_PQ_CRYPTO" = "ON" ] && [ -n "$OPENSSL_PATH" ]; then
    cmake_args+=("-DOPENSSL_PATH=$OPENSSL_PATH")
fi

# Add OQS provider path
cmake_args+=("-DOQS_PROVIDER_PATH=$OQS_PROVIDER_PATH")

# Add CMAKE_PREFIX_PATH to help find CycloneDDS
cmake_args+=("-DCMAKE_PREFIX_PATH=$CYCLONEDDS_PATH")

# Run cmake
echo "Running cmake with args: ${cmake_args[@]}"
cmake "${cmake_args[@]}" ..

# Build the plugin
echo "Building plugin (using $PARALLEL_JOBS parallel jobs)..."
cmake --build . -j"$PARALLEL_JOBS"

# Verify build
echo ""
echo "=== VERIFYING BUILD ==="

if [ -f "lib/libdds_pqsec.so" ]; then
    echo "✓ Plugin library built: lib/libdds_pqsec.so"
    
    # Check plugin dependencies
    echo "Checking plugin dependencies..."
    if command -v ldd >/dev/null 2>&1; then
        missing_deps=$(ldd lib/libdds_pqsec.so | grep "not found" || true)
        if [ -n "$missing_deps" ]; then
            echo "⚠ Warning: Missing dependencies:"
            echo "$missing_deps"
        else
            echo "✓ All dependencies satisfied"
        fi
    fi
else
    echo "✗ Plugin library not found"
    exit 1
fi

echo ""
echo "=== BUILD COMPLETED SUCCESSFULLY ==="
echo ""
echo "Plugin library: $(pwd)/lib/libdds_pqsec.so"
echo "Build type: $BUILD_TYPE"
echo "Configuration:"
echo "  PQ Crypto: $ENABLE_PQ_CRYPTO"
echo "  KEM Algorithm: $SELECTED_KEM_ALGORITHM"
echo "  PQ Debug Level: $PQ_DEBUG_LEVEL (compile-time default)"
echo ""

# Display algorithm information
case $SELECTED_KEM_ALGORITHM in
    mlkem512)
        echo "KEM Info: ML-KEM-512 (128-bit security, smallest keys/ciphertexts)"
        ;;
    mlkem768)
        echo "KEM Info: ML-KEM-768 (192-bit security, NIST Level 3, recommended default)"
        ;;
    mlkem1024)
        echo "KEM Info: ML-KEM-1024 (256-bit security, largest keys/ciphertexts)"
        ;;
    ecdh_p256)
        echo "KEM Info: ECDH P-256 (classical, 128-bit security equivalent)"
        ;;
    dh_2048)
        echo "KEM Info: DH-2048 (classical, 112-bit security)"
        ;;
    X25519MLKEM768)
        echo "KEM Info: X25519MLKEM768 (hybrid classical+PQ)"
        ;;
    p256_mlkem768)
        echo "KEM Info: P-256+ML-KEM-768 (hybrid classical+PQ)"
        ;;
    *)
        echo "KEM Info: $SELECTED_KEM_ALGORITHM"
        ;;
esac

# Display debug usage information
echo ""
echo "=== DEBUG CONFIGURATION ==="
echo "Compile-time debug level: $PQ_DEBUG_LEVEL"
echo ""
echo "Runtime debug control (can override compile-time default):"
echo "  export PQ_DEBUG_LEVEL=TRACE    # Set to TRACE level"
echo "  export PQ_DEBUG_LEVEL=INFO     # Set to INFO level"
echo "  export PQ_DEBUG_LEVEL=ERROR    # Set to ERROR level only"
echo "  export PQ_DEBUG_LEVEL=NONE     # Disable all debug output"
echo ""
echo "Debug level hierarchy (higher includes lower):"
echo "  NONE < ERROR < WARN < INFO < TRACE < DATA"
echo ""

echo "To test the plugin:"
echo "  1. Set up environment:"
if [ "$ENABLE_PQ_CRYPTO" = "ON" ]; then
    echo "     source $OQS_PROVIDER_PATH/setup_env.sh"
fi
echo "     export LD_LIBRARY_PATH=$CYCLONEDDS_PATH/lib:\$LD_LIBRARY_PATH"
echo "     export LD_LIBRARY_PATH=$(pwd)/lib:\$LD_LIBRARY_PATH"
echo ""
echo "  2. Set debug level (optional):"
echo "     export PQ_DEBUG_LEVEL=TRACE"
echo ""
echo "  3. Set CycloneDDS config:"
echo "     export CYCLONEDDS_URI=path/to/custom_auth_plugin.xml"
echo ""
echo "  4. Run your DDS applications"