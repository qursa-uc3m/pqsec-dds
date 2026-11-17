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

if [ -z "${CYCLONEDDS_URI:-}" ] &&
   [ -f "$adapter_dir/config/cyclonedds/custom_auth_plugin.xml" ]; then
  export CYCLONEDDS_URI="$adapter_dir/config/cyclonedds/custom_auth_plugin.xml"
fi

echo "CycloneDDS: $adapter_dir/cyclonedds_install/lib"
echo "PQSec plugin: $adapter_dir/build/libdds_pqsec.so"
