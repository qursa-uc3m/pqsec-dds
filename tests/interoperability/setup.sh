#!/bin/sh
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
#
# Security material for run.sh:  setup.sh <openssl> <directory> [ML-DSA-65 | EC]
#
# Identities alice and bob under one Identity CA, all ML-DSA-65 by default
# or ECDSA P-256 with EC (the handshake still uses ML-KEM). The Permissions
# CA is ECDSA, because both access control plugins verify governance and
# permissions with OpenSSL's PKCS#7 functions, which cannot check ML-DSA.
# The documents are signed without the CA certificate (see
# protocol/pkidh-mlkem-sizes.md).

set -eu

openssl=$1
algorithm=${3:-ML-DSA-65}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$2"
cd "$2"

key() {
  if [ "$algorithm" = EC ]; then
    "$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"
  else
    "$openssl" genpkey -algorithm "$algorithm" -out "$1"
  fi
}

key identity_ca_key.pem
"$openssl" req -new -x509 -key identity_ca_key.pem -subj "/C=ES/O=PQSec/CN=PQSec Identity CA" \
  -days 365 -out identity_ca.pem
for id in alice bob; do
  key "${id}_key.pem"
  "$openssl" req -new -key "${id}_key.pem" -subj "/C=ES/O=PQSec/CN=$id" -out "$id.csr"
  "$openssl" x509 -req -in "$id.csr" -CA identity_ca.pem -CAkey identity_ca_key.pem \
    -CAcreateserial -days 365 -out "${id}_cert.pem"
done

"$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out permissions_ca_key.pem
"$openssl" req -new -x509 -key permissions_ca_key.pem -subj "/C=ES/O=PQSec/CN=PQSec Permissions CA" \
  -days 365 -out permissions_ca.pem
for document in governance permissions; do
  "$openssl" smime -sign -nocerts -text -in "$here/$document.xml" -signer permissions_ca.pem \
    -inkey permissions_ca_key.pem -out "$document.p7s"
done
