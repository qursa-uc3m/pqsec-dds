#!/bin/bash
#
# build_oqs.sh — Build liboqs and OQS provider
# Copyright (C) 2023-2025 onment variables
# Copyright (C) 2023-2025 Javier Blanco-Romero
#

set -e  # Exit on any error

# Default values
INSTALL_DIR="/opt/oqs_openssl3"
DEBUG=0

# Version defaults (fixed versions for reproducible builds)
OPENSSL_VERSION="openssl-3.5.0"
LIBOQS_VERSION="0.13.0"
OQS_PROVIDER_VERSION="0.9.0"

# Build configuration
PARALLEL_JOBS=$(nproc)
ENABLE_SHARED="ON"

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS]

OPTIONS:
    -p DIR              Installation directory (default: /opt/oqs_openssl3)
    -d 0|1              Debug mode (default: 0)
    -o VERSION          OpenSSL version (default: openssl-3.5.0)
    -l VERSION          liboqs version (default: 0.13.0)
    -q VERSION          OQS provider version (default: 0.9.0)
    -j JOBS             Parallel build jobs (default: $(nproc))
    -f                  Force clean rebuild (removes existing installation)
    -h                  Show this help message

EXAMPLES:
    # Default build
    $0

    # Custom installation directory with debug
    $0 -p /custom/path -d 1

    # Specific versions
    $0 -o openssl-3.4.0 -l 0.12.0 -q 0.8.0

    # Force clean rebuild
    $0 -f

EOF
}

# Parse command line arguments
FORCE_CLEAN=0
while getopts "p:d:o:l:q:j:fh" flag; do
    case "${flag}" in
        p) INSTALL_DIR=${OPTARG};;
        d) DEBUG=${OPTARG};;
        o) OPENSSL_VERSION=${OPTARG};;
        l) LIBOQS_VERSION=${OPTARG};;
        q) OQS_PROVIDER_VERSION=${OPTARG};;
        j) PARALLEL_JOBS=${OPTARG};;
        f) FORCE_CLEAN=1;;
        h) usage; exit 0;;
        *) echo "Invalid option. Use -h for help."; exit 1;;
    esac
done

# Validate inputs
if ! [[ "$DEBUG" =~ ^[01]$ ]]; then
    echo "Error: Debug flag must be 0 or 1"
    exit 1
fi

if ! [[ "$PARALLEL_JOBS" =~ ^[0-9]+$ ]] || [ "$PARALLEL_JOBS" -lt 1 ]; then
    echo "Error: Parallel jobs must be a positive integer"
    exit 1
fi

# Display configuration
echo "=== Enhanced OQS Build Configuration ==="
echo "Installation directory: $INSTALL_DIR"
echo "OpenSSL version: $OPENSSL_VERSION"
echo "liboqs version: $LIBOQS_VERSION"
echo "OQS provider version: $OQS_PROVIDER_VERSION"
echo "Debug mode: $DEBUG"
echo "Parallel jobs: $PARALLEL_JOBS"
echo "Force clean: $FORCE_CLEAN"
echo "==============================="

# Set up library extension based on OS
if [[ "$OSTYPE" == "darwin"* ]]; then
   SHLIBEXT="dylib"
   STATLIBEXT="dylib"
else
   SHLIBEXT="so"
   STATLIBEXT="a"
fi

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

# Create installation directory structure
echo "Creating installation directories..."
sudo mkdir -p "$INSTALL_DIR"
sudo chown -R $USER:$USER "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Set up environment variables
export OSSL_PREFIX="$INSTALL_DIR/.local"
export MAKE_PARAMS="-j$PARALLEL_JOBS"
export LIBOQS_BRANCH="$LIBOQS_VERSION"
export OPENSSL_BRANCH="$OPENSSL_VERSION"

# Set build type
if [ "$DEBUG" -eq 1 ]; then
    export CMAKE_PARAMS="-DCMAKE_BUILD_TYPE=Debug"
    export OSSL_CONFIG="enable-trace enable-ssl-trace --debug"
else
    export CMAKE_PARAMS="-DCMAKE_BUILD_TYPE=Release"
    export OSSL_CONFIG=""
fi

# Build OpenSSL
echo ""
echo "=== BUILDING OPENSSL $OPENSSL_VERSION ==="

if [ ! -d "openssl" ]; then
    echo "Cloning OpenSSL..."
    git clone --depth 1 --branch "$OPENSSL_VERSION" https://github.com/openssl/openssl.git
fi

cd openssl
echo "Configuring OpenSSL..."
LDFLAGS="-Wl,-rpath -Wl,${OSSL_PREFIX}/lib64" ./config $OSSL_CONFIG \
    --prefix="$OSSL_PREFIX" \
    --openssldir="$OSSL_PREFIX/ssl" \
    shared \
    enable-fips

echo "Building OpenSSL..."
make $MAKE_PARAMS

echo "Installing OpenSSL..."
make install_sw install_ssldirs

cd ..

# Create lib symlink if needed (some cmake versions need this)
if [ -d "$OSSL_PREFIX/lib64" ] && [ ! -L "$OSSL_PREFIX/lib" ]; then
    cd "$OSSL_PREFIX" && ln -s lib64 lib && cd "$INSTALL_DIR"
fi

export OPENSSL_INSTALL="$OSSL_PREFIX"

# Build liboqs
echo ""
echo "=== BUILDING LIBOQS $LIBOQS_VERSION ==="

# Check if we need to build liboqs
if [ ! -f "$OSSL_PREFIX/lib/liboqs.$STATLIBEXT" ] && [ ! -f "$OSSL_PREFIX/lib64/liboqs.$SHLIBEXT" ]; then
    echo "Building liboqs..."
    
    if [ ! -d "liboqs" ]; then
        echo "Cloning liboqs..."
        git clone --depth 1 --branch "$LIBOQS_VERSION" https://github.com/open-quantum-safe/liboqs.git
    fi
    
    cd liboqs
    
    # Configure liboqs to use our OpenSSL
    echo "Configuring liboqs..."
    cmake -GNinja $CMAKE_PARAMS \
        -DOPENSSL_ROOT_DIR="$OPENSSL_INSTALL" \
        -DCMAKE_INSTALL_PREFIX="$OSSL_PREFIX" \
        -DBUILD_SHARED_LIBS=$ENABLE_SHARED \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_DIST_BUILD=ON \
        -DOQS_USE_OPENSSL=ON \
        -S . -B _build
    
    echo "Building liboqs..."
    cd _build && ninja && ninja install && cd ../..
else
    echo "liboqs already built, skipping..."
fi

export liboqs_DIR="$OSSL_PREFIX"

# Clone OQS provider repository
echo ""
echo "=== BUILDING OQS PROVIDER $OQS_PROVIDER_VERSION ==="

if [ ! -d "oqs-provider" ]; then
    echo "Cloning OQS provider..."
    git clone --depth 1 --branch "$OQS_PROVIDER_VERSION" https://github.com/open-quantum-safe/oqs-provider.git
fi

cd oqs-provider

# Check if provider needs building
if [ ! -f "_build/lib/oqsprovider.$SHLIBEXT" ]; then
    echo "Building OQS provider..."
    
    # Configure OQS provider
    echo "Configuring OQS provider..."
    cmake $CMAKE_PARAMS \
        -DOPENSSL_ROOT_DIR="$OPENSSL_INSTALL" \
        -DCMAKE_PREFIX_PATH="$OSSL_PREFIX" \
        -DCMAKE_INSTALL_PREFIX="$OSSL_PREFIX" \
        -S . -B _build
    
    echo "Building..."
    cmake --build _build
    
    echo "Installing OQS provider..."
    cmake --build _build --target install
else
    echo "OQS provider already built, skipping..."
fi

cd ..

# Create OpenSSL configuration file
echo ""
echo "=== CONFIGURING OPENSSL FOR DDS ==="
mkdir -p "$OSSL_PREFIX/ssl"
cat > "$OSSL_PREFIX/ssl/openssl.cnf" << 'EOF'
# OpenSSL configuration for DDS with OQS provider

openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
EOF

chmod 644 "$OSSL_PREFIX/ssl/openssl.cnf"

# Create environment setup script
echo "Creating environment setup script..."
cat > setup_env.sh << EOF
#!/bin/bash
# Environment setup for OQS OpenSSL DDS plugin

export OPENSSL_ROOT_DIR="$OSSL_PREFIX"
export OPENSSL_CONF="$OSSL_PREFIX/ssl/openssl.cnf"
export OPENSSL_MODULES="$OSSL_PREFIX/lib64/ossl-modules"
export LD_LIBRARY_PATH="$OSSL_PREFIX/lib64:\$LD_LIBRARY_PATH"
export PKG_CONFIG_PATH="$OSSL_PREFIX/lib64/pkgconfig:\$PKG_CONFIG_PATH"
export PATH="$OSSL_PREFIX/bin:\$PATH"

# DDS-specific environment variables
export OQS_PROVIDER_NAME="oqsprovider"
export OQS_PROVIDER_PATH="$INSTALL_DIR"

echo "OQS environment configured for: $INSTALL_DIR"
echo "Provider: \$OQS_PROVIDER_NAME"

# Test if OQS provider works
if [ -f "$OSSL_PREFIX/bin/openssl" ]; then
    if "$OSSL_PREFIX/bin/openssl" list -providers 2>/dev/null | grep -q "oqsprovider"; then
        echo "✓ OQS provider loaded successfully"
    else
        echo "⚠ Warning: OQS provider not loaded"
    fi
else
    echo "⚠ Warning: OpenSSL binary not found"
fi
EOF

chmod +x setup_env.sh

# Create symbolic link for easy access
echo "Creating symbolic links..."
sudo ln -sf "$OSSL_PREFIX/bin/openssl" /usr/local/bin/oqs_openssl3

# Verify installation
echo ""
echo "=== VERIFYING INSTALLATION ==="
source ./setup_env.sh

echo "Testing OpenSSL installation..."
"$OSSL_PREFIX/bin/openssl" version

echo ""
echo "Testing OQS provider..."
if "$OSSL_PREFIX/bin/openssl" list -providers | grep -q oqsprovider; then
    echo "✓ OQS provider loaded successfully!"
    echo ""
    echo "Available KEM algorithms (first 5):"
    "$OSSL_PREFIX/bin/openssl" list -kem-algorithms | head -5
else
    echo "⚠ Warning: OQS provider not loaded"
    echo "Available providers:"
    "$OSSL_PREFIX/bin/openssl" list -providers
fi

echo ""
echo "=== BUILD COMPLETED SUCCESSFULLY ==="
echo ""
echo "Installation directory: $INSTALL_DIR"
echo "OpenSSL binary: $OSSL_PREFIX/bin/openssl"
echo "Configuration file: $OSSL_PREFIX/ssl/openssl.cnf"
echo ""
echo "To use this installation:"
echo "  source $INSTALL_DIR/setup_env.sh"
echo ""
echo "For DDS plugin build:"
echo "  -DOQS_PROVIDER_PATH=$INSTALL_DIR"
echo "  -DOPENSSL_PATH=$OSSL_PREFIX"
echo ""
echo "Versions installed:"
echo "  OpenSSL: $OPENSSL_VERSION"
echo "  liboqs: $LIBOQS_VERSION"
echo "  OQS Provider: $OQS_PROVIDER_VERSION"