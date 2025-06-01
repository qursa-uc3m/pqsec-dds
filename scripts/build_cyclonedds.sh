#!/bin/bash
#
# build_cyclonedds.sh — Build CycloneDDS
# Copyright (C) 2023-2025 onment variables
# Copyright (C) 2023-2025 Javier Blanco-Romero
#

# Simple CycloneDDS build script

set -e  # Exit on any error

# Default values - install locally for development
INSTALL_DIR="./cyclonedds_install"
VERSION="0.10.5"
BUILD_TYPE="Debug"
PARALLEL_JOBS=$(nproc)

# Get absolute path for installation directory
INSTALL_DIR=$(realpath "$INSTALL_DIR")

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -p DIR              Installation directory (default: ./cyclonedds_install)
    -v VERSION          CycloneDDS version (default: 0.10.5)
    -t TYPE             Build type: Debug|Release (default: Debug)
    -j JOBS             Parallel build jobs (default: $(nproc))
    -f                  Force clean rebuild
    -h                  Show this help message

EXAMPLES:
    # Default build
    $0

    # Custom installation directory
    $0 -p ./my_cyclonedds

    # System-wide installation (requires sudo)
    $0 -p /opt/cyclonedds

    # Release build with specific version
    $0 -t Release -v 0.11.0

    # Force clean rebuild
    $0 -f

EOF
}

# Parse command line arguments
FORCE_CLEAN=0
while getopts "p:v:t:j:fh" flag; do
    case "${flag}" in
        p) INSTALL_DIR=${OPTARG};;
        v) VERSION=${OPTARG};;
        t) BUILD_TYPE=${OPTARG};;
        j) PARALLEL_JOBS=${OPTARG};;
        f) FORCE_CLEAN=1;;
        h) usage; exit 0;;
        *) echo "Invalid option. Use -h for help."; exit 1;;
    esac
done

# Validate build type
if [[ ! "$BUILD_TYPE" =~ ^(Debug|Release)$ ]]; then
    echo "Error: Build type must be Debug or Release"
    exit 1
fi

# Display configuration
echo "=== CycloneDDS Build Configuration ==="
echo "Installation directory: $INSTALL_DIR"
echo "Version: $VERSION"
echo "Build type: $BUILD_TYPE"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "Force clean: $FORCE_CLEAN"
echo "==============================="

# Handle existing installation
if [ "$FORCE_CLEAN" -eq 1 ] && [ -d "$INSTALL_DIR" ]; then
    echo "Force clean requested - removing existing installation..."
    sudo rm -rf "$INSTALL_DIR"
elif [ -d "$INSTALL_DIR" ] && [ "$(ls -A $INSTALL_DIR 2>/dev/null)" ]; then
    read -p "Directory $INSTALL_DIR exists. Remove and rebuild? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Build cancelled by user."
        exit 1
    fi
    sudo rm -rf "$INSTALL_DIR"
fi

# Create installation directory (no sudo needed for local install)
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Create temporary build directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

echo ""
echo "=== BUILDING CYCLONEDDS $VERSION ==="

# Clone CycloneDDS
echo "Cloning CycloneDDS..."
git clone --depth 1 --branch "$VERSION" https://github.com/eclipse-cyclonedds/cyclonedds.git
cd cyclonedds

# Create build directory
mkdir build
cd build

# Configure CycloneDDS
echo "Configuring CycloneDDS..."
cmake \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DBUILD_EXAMPLES=ON \
    -DBUILD_TESTING=ON \
    -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
    ..

# Build CycloneDDS
echo "Building CycloneDDS (using $PARALLEL_JOBS parallel jobs)..."
cmake --build . -j"$PARALLEL_JOBS"

# Install CycloneDDS (no sudo needed for local install)
echo "Installing CycloneDDS..."
cmake --build . --target install

# Build HelloWorld example by default
echo ""
echo "=== BUILDING HELLOWORLD EXAMPLE ==="
cd "$TEMP_DIR/cyclonedds"

# Copy and build the HelloWorld example
if [ -d "$INSTALL_DIR/share/CycloneDDS/examples/helloworld" ]; then
    echo "Building HelloWorld example..."
    cp -r "$INSTALL_DIR/share/CycloneDDS/examples/helloworld" .
    cd helloworld
    
    mkdir -p build_example
    cd build_example
    
    # Set up environment for building examples
    export LD_LIBRARY_PATH="$INSTALL_DIR/lib:$LD_LIBRARY_PATH"
    export PATH="$INSTALL_DIR/bin:$PATH"
    
    # Configure and build the example
    cmake -DCMAKE_PREFIX_PATH="$INSTALL_DIR" ..
    make -j"$PARALLEL_JOBS"
    
    # Install the example binaries to CycloneDDS bin directory (no sudo needed)
    echo "Installing HelloWorld example binaries..."
    cp HelloworldPublisher HelloworldSubscriber "$INSTALL_DIR/bin/"
    
    echo "✓ HelloWorld example built and installed"
else
    echo "⚠ Warning: HelloWorld example source not found"
fi

# Verify installation
echo ""
echo "=== VERIFYING INSTALLATION ==="

if [ -f "$INSTALL_DIR/lib/libddsc.so" ]; then
    echo "✓ CycloneDDS library installed"
else
    echo "⚠ Warning: Main library not found"
fi

if [ -d "$INSTALL_DIR/include/dds" ]; then
    echo "✓ Headers installed"
else
    echo "⚠ Warning: Headers not found"
fi

if [ -f "$INSTALL_DIR/bin/HelloworldPublisher" ]; then
    echo "✓ HelloWorld example installed"
else
    echo "⚠ Warning: HelloWorld example not found"
fi

if [ -f "$INSTALL_DIR/bin/ddsperf" ]; then
    echo "✓ Performance tools installed"
else
    echo "⚠ Warning: Performance tools not found"
fi

# Clean up temporary directory
cd /
rm -rf "$TEMP_DIR"

echo ""
echo "=== BUILD COMPLETED SUCCESSFULLY ==="
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "Library path: $INSTALL_DIR/lib"
echo "Headers path: $INSTALL_DIR/include"
echo "Tools path: $INSTALL_DIR/bin"
echo ""
echo "To test CycloneDDS:"
echo "  export LD_LIBRARY_PATH=$INSTALL_DIR/lib:\$LD_LIBRARY_PATH"
echo "  $INSTALL_DIR/bin/HelloworldPublisher &"
echo "  $INSTALL_DIR/bin/HelloworldSubscriber"
echo ""
echo "For CMake projects:"
echo "  -DCYCLONEDDS_PATH=$INSTALL_DIR"
echo ""
echo "Version installed: $VERSION"