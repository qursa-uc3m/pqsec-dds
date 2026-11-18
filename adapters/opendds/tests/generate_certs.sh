#!/bin/sh
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)

set -eu

openssl=$1
output=$2

"$openssl" genpkey -algorithm ML-DSA-65 -out "$output/identity_ca_key.pem"
"$openssl" req -new -x509 -key "$output/identity_ca_key.pem" \
  -subj /CN=OpenDDS-PQSec-Test-CA -days 2 -out "$output/identity_ca_cert.pem"

for participant in a b; do
  "$openssl" genpkey -algorithm ML-DSA-65 -out "$output/participant_${participant}_key.pem"
  "$openssl" req -new -key "$output/participant_${participant}_key.pem" \
    -subj "/CN=OpenDDS-PQSec-Participant-${participant}" \
    -out "$output/participant_${participant}.csr"
  "$openssl" x509 -req -in "$output/participant_${participant}.csr" \
    -CA "$output/identity_ca_cert.pem" -CAkey "$output/identity_ca_key.pem" \
    -CAcreateserial -days 2 -out "$output/participant_${participant}_cert.pem"
done

"$openssl" verify -CAfile "$output/identity_ca_cert.pem" \
  "$output/participant_a_cert.pem" "$output/participant_b_cert.pem"

"$openssl" genpkey -algorithm ML-DSA-65 -out "$output/other_ca_key.pem"
"$openssl" req -new -x509 -key "$output/other_ca_key.pem" \
  -subj /CN=OpenDDS-PQSec-Other-Test-CA -days 2 -out "$output/other_ca_cert.pem"
"$openssl" genpkey -algorithm ML-DSA-65 -out "$output/participant_other_key.pem"
"$openssl" req -new -key "$output/participant_other_key.pem" \
  -subj /CN=OpenDDS-PQSec-Other-Participant -out "$output/participant_other.csr"
"$openssl" x509 -req -in "$output/participant_other.csr" \
  -CA "$output/other_ca_cert.pem" -CAkey "$output/other_ca_key.pem" \
  -CAcreateserial -days 2 -out "$output/participant_other_cert.pem"
"$openssl" verify -CAfile "$output/other_ca_cert.pem" "$output/participant_other_cert.pem"
#!/usr/bin/env bash
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
# Copyright (C) 2023 Adrián Serrano Navarro @100429115 (UC3M)
# SPDX-License-Identifier: Apache-2.0

"$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$output/ec_ca_key.pem"
"$openssl" req -new -x509 -key "$output/ec_ca_key.pem" \
  -subj /CN=OpenDDS-PQSec-EC-Test-CA -days 2 -out "$output/ec_ca_cert.pem"
"$openssl" genpkey -algorithm ML-DSA-65 -out "$output/participant_ecca_key.pem"
"$openssl" req -new -key "$output/participant_ecca_key.pem" \
  -subj /CN=OpenDDS-PQSec-EC-CA-Participant -out "$output/participant_ecca.csr"
"$openssl" x509 -req -in "$output/participant_ecca.csr" \
  -CA "$output/ec_ca_cert.pem" -CAkey "$output/ec_ca_key.pem" \
  -CAcreateserial -days 2 -out "$output/participant_ecca_cert.pem"

# ECDSA P-256 participants under the EC CA and under the ML-DSA CA, and a
# P-384 CA and participant, which the plugin refuses.
participant() {
  name=$1 ca=$2
  shift 2
  "$openssl" genpkey "$@" -out "$output/participant_${name}_key.pem"
  "$openssl" req -new -key "$output/participant_${name}_key.pem" \
    -subj "/CN=OpenDDS-PQSec-Participant-$name" -out "$output/participant_$name.csr"
  "$openssl" x509 -req -in "$output/participant_$name.csr" \
    -CA "$output/${ca}_cert.pem" -CAkey "$output/${ca}_key.pem" \
    -CAcreateserial -days 2 -out "$output/participant_${name}_cert.pem"
}
participant eca ec_ca -algorithm EC -pkeyopt ec_paramgen_curve:P-256
participant ecb ec_ca -algorithm EC -pkeyopt ec_paramgen_curve:P-256
participant ecleaf identity_ca -algorithm EC -pkeyopt ec_paramgen_curve:P-256

"$openssl" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$output/p384_ca_key.pem"
"$openssl" req -new -x509 -key "$output/p384_ca_key.pem" \
  -subj /CN=OpenDDS-PQSec-P384-Test-CA -days 2 -out "$output/p384_ca_cert.pem"
participant p384 p384_ca -algorithm EC -pkeyopt ec_paramgen_curve:P-384
