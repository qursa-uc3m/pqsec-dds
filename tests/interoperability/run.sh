#!/bin/sh
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
#
# CycloneDDS against OpenDDS, both with the PQSec authentication plugin:
#
#   run.sh <security directory> <CycloneDDS plugin> <OpenDDS plugin> <log directory>
#
# Runs four cases: each implementation publishing, each as handshake
# initiator. The initiator follows from the identities, whose subject names
# give the adjusted GUIDs. Expects cyclonedds/build/cyclonedds_app,
# opendds/build/opendds_app, and the libraries of both on the library path.

set -u

here=$(cd "$(dirname "$0")" && pwd)
security=$1 logs=$4
mkdir -p "$logs"
sed "s|@PQSEC_OPENDDS_LIB@|${3%.so}|" "$here/opendds.ini" > "$logs/opendds.ini"
export CYCLONEDDS_URI="file://$here/cyclonedds.xml" PQSEC_SECURITY="$security" PQSEC_CYCLONEDDS_LIB="$2"

failed=0
run() {
  name=$1 cyclonedds_role=$2 cyclonedds_id=$3 opendds_role=$4 opendds_id=$5
  # OpenDDS starts first. With unicast discovery, a CycloneDDS participant
  # that starts first announces itself before OpenDDS listens, and later
  # only to OpenDDS's metatraffic port, where OpenDDS ignores announcements.
  timeout 90 "$here/opendds/build/opendds_app" "$opendds_role" "$opendds_id" "$security" \
    -DCPSConfigFile "$logs/opendds.ini" > "$logs/$name.opendds.log" 2>&1 &
  opendds=$!
  sleep 1
  PQSEC_IDENTITY=$cyclonedds_id PQSEC_TRACE="$logs/$name.cyclonedds.trace" \
    timeout 90 "$here/cyclonedds/build/cyclonedds_app" "$cyclonedds_role" > "$logs/$name.cyclonedds.log" 2>&1
  cyclonedds_status=$?
  wait $opendds
  opendds_status=$?
  if [ $cyclonedds_status -eq 0 ] && [ $opendds_status -eq 0 ]; then
    echo "PASS $name"
  else
    echo "FAIL $name (see $logs/$name.*)"
    failed=1
  fi
}

run cyclonedds-pub-alice pub alice sub bob
run cyclonedds-pub-bob pub bob sub alice
run opendds-pub-alice sub bob pub alice
run opendds-pub-bob sub alice pub bob
exit $failed
