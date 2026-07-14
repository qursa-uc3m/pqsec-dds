#!/usr/bin/env bash
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
adapter_dir=$(cd "$script_dir/.." && pwd)

prepend_library_path() {
  if [ -d "$1" ]; then
    LD_LIBRARY_PATH="$1${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
}

prepend_library_path "$adapter_dir/cyclonedds_install/lib"
prepend_library_path "$adapter_dir/build"
export LD_LIBRARY_PATH

# Native ML-KEM/ML-DSA and hybrid KEMs need no external provider setup. For an
# experimental oqs-provider KEM, point this at the directory containing the
# provider module before sourcing this script.
if [ -n "${PQSEC_OPENSSL_MODULES:-}" ]; then
  export OPENSSL_MODULES="$PQSEC_OPENSSL_MODULES"
fi

if [ -z "${CYCLONEDDS_URI:-}" ] &&
   [ -f "$adapter_dir/config/cyclonedds/custom_auth_plugin_mldsa44.xml" ]; then
  export CYCLONEDDS_URI="$adapter_dir/config/cyclonedds/custom_auth_plugin_mldsa44.xml"
fi

echo "CycloneDDS: $adapter_dir/cyclonedds_install/lib"
echo "PQSec plugin: $adapter_dir/build/libdds_pqsec.so"
if [ -n "${OPENSSL_MODULES:-}" ]; then
  echo "OpenSSL modules: $OPENSSL_MODULES"
fi
