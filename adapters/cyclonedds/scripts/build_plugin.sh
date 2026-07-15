#!/usr/bin/env bash
#
# build_plugin.sh — Build the CycloneDDS PQSec authentication plugin
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
adapter_dir=$(cd "$script_dir/.." && pwd)

cyclonedds_path="$adapter_dir/cyclonedds_install"
openssl_root="${OPENSSL_ROOT_DIR:-/opt/openssl3_local/.local}"
build_dir="$adapter_dir/build"
build_type=Debug
jobs=$(nproc)
kem=mlkem768
provider=oqsprovider
debug_level=INFO
enable_pq=ON
clean=0

usage() {
  cat <<EOF
Usage: $0 [options]

  -c DIR                 CycloneDDS installation
  -s DIR                 OpenSSL 3.5+ installation prefix
  -b DIR                 Build directory
  -t Debug|Release       Build type (default: Debug)
  -j N                   Parallel build jobs
  --kem NAME             KEM selection (default: mlkem768)
  --provider NAME        Fallback OpenSSL provider (default: oqsprovider)
  --debug-level LEVEL    NONE|ERROR|WARN|INFO|TRACE|DATA
  --no-pq                Build the classical PKI-DH variant
  --clean                Remove the build directory before configuring
  -h, --help             Show this help

Native OpenSSL KEMs:
  mlkem512 mlkem768 mlkem1024 x25519_mlkem768 p256_mlkem768

Experimental oqs-provider KEMs:
  frodo640shake bikel1 hqc128

The plugin uses OpenSSL EVP exclusively.  It never links to liboqs.  For an
experimental KEM, build oqs-provider against the same OpenSSL installation and
set OPENSSL_MODULES to the directory containing oqsprovider.so at run time.
EOF
}

while (($#)); do
  case "$1" in
    -c) cyclonedds_path=$2; shift 2 ;;
    -s) openssl_root=$2; shift 2 ;;
    -b) build_dir=$2; shift 2 ;;
    -t) build_type=$2; shift 2 ;;
    -j) jobs=$2; shift 2 ;;
    --kem) kem=$2; shift 2 ;;
    --provider) provider=$2; shift 2 ;;
    --debug-level) debug_level=$2; shift 2 ;;
    --no-pq) enable_pq=OFF; kem=ecdh_p256; shift ;;
    --clean) clean=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$build_type" in Debug|Release) ;; *) echo "Invalid build type" >&2; exit 2 ;; esac
case "$debug_level" in NONE|ERROR|WARN|INFO|TRACE|DATA) ;;
  *) echo "Invalid debug level" >&2; exit 2 ;;
esac

if ((clean)); then
  cmake -E remove_directory "$build_dir"
fi

cmake -S "$adapter_dir/src" -B "$build_dir" \
  -DCYCLONEDDS_PATH="$cyclonedds_path" \
  -DOPENSSL_ROOT_DIR="$openssl_root" \
  -DENABLE_PQ_CRYPTO="$enable_pq" \
  -DSELECTED_KEM_ALGORITHM="$kem" \
  -DPQSEC_FALLBACK_PROVIDER="$provider" \
  -DPQ_DEBUG_LEVEL="$debug_level" \
  -DCMAKE_BUILD_TYPE="$build_type" \
  -DBUILD_TESTING=ON

cmake --build "$build_dir" --parallel "$jobs"
ctest --test-dir "$build_dir" --output-on-failure

echo "Built: $build_dir/libdds_pqsec.so"
