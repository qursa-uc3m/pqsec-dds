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
