#!/usr/bin/env bash
# generate_certs.sh — Generate native OpenSSL identity certificates
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)

set -euo pipefail

openssl=${OPENSSL:-openssl}
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$script_dir"

if ! "$openssl" list -signature-algorithms | grep -q 'ML-DSA-44'; then
  echo "OpenSSL does not expose native ML-DSA (OpenSSL 3.5+ required)" >&2
  exit 1
fi

mkdir -p mldsa traditional

generate_identity() {
  local algorithm=$1
  local directory=$2
  local prefix=$3
  local serial=$4
  local root_key="$directory/${prefix}_root_key.pem"
  local root_cert="$directory/${prefix}_root_cert.pem"
  local entity_key="$directory/${prefix}_entity_key.pem"
  local request="$directory/${prefix}_entity_req.pem"
  local entity_cert="$directory/${prefix}_entity_cert.pem"

  if [ "$algorithm" = "EC" ]; then
    "$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$root_key"
    "$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$entity_key"
  else
    "$openssl" genpkey -algorithm "$algorithm" -out "$root_key"
    "$openssl" genpkey -algorithm "$algorithm" -out "$entity_key"
  fi

  "$openssl" req -new -x509 -key "$root_key" -days 1095 -set_serial "$serial" \
    -subj "/C=ES/O=UC3M/OU=PQSec-DDS/CN=PQSec Test Root ${prefix}" \
    -addext 'basicConstraints=critical,CA:true' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -out "$root_cert"

  "$openssl" req -new -key "$entity_key" \
    -subj "/C=ES/O=UC3M/OU=PQSec-DDS/CN=PQSec Test Participant ${prefix}" \
    -out "$request"

  "$openssl" x509 -req -in "$request" -CA "$root_cert" -CAkey "$root_key" \
    -days 1095 -set_serial "$((serial + 1))" \
    -extfile <(printf '%s\n' \
      'basicConstraints=critical,CA:false' \
      'keyUsage=critical,digitalSignature' \
      'extendedKeyUsage=serverAuth,clientAuth' \
      'subjectAltName=IP:127.0.0.1') \
    -out "$entity_cert"

  "$openssl" verify -no-CApath -check_ss_sig -CAfile "$root_cert" "$entity_cert"
}

generate_identity ML-DSA-44 mldsa mldsa44 512
generate_identity ML-DSA-65 mldsa mldsa65 514
generate_identity ML-DSA-87 mldsa mldsa87 516
generate_identity EC traditional ecdsa_p256 600

echo "Generated native ML-DSA and ECDSA test identities in $script_dir"
