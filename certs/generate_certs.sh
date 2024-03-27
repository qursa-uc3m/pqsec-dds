#!/bin/bash

# Set variables for easy changes
ROOT_CA_KEY="example_id_ca_priv_key.pem"
ROOT_CA_CERT="example_id_ca_cert.pem"
PERM_CA_KEY="example_perm_ca_priv_key.pem"
PERM_CA_CERT="example_perm_ca_cert.pem"
ALICE_KEY="example_alice_priv_key.pem"
ALICE_CSR="example_alice.csr"
ALICE_CERT="example_alice_cert.pem"
DAYS=3650
ID_CA_SUBJ="/C=NL/ST=OV/L=Locality Name/OU=Example OU/O=Example ID CA Organization/CN=Example ID CA/emailAddress=authority@cycloneddssecurity.adlinktech.com"
PERM_CA_SUBJ="/C=NL/ST=OV/L=Locality Name/OU=Example OU/O=Example CA Organization/CN=Example Permissions CA/emailAddress=authority@cycloneddssecurity.adlinktech.com"
ALICE_SUBJ="/C=NL/ST=OV/L=Locality Name/OU=Organizational Unit Name/O=Example Organization/CN=Alice Example/emailAddress=alice@cycloneddssecurity.adlinktech.com"

# Generate CA for identity management
openssl genrsa -out "$ROOT_CA_KEY" 2048
openssl req -x509 -key "$ROOT_CA_KEY" -out "$ROOT_CA_CERT" -days $DAYS -subj "$ID_CA_SUBJ"

# Generate CA for permissions management
openssl genrsa -out "$PERM_CA_KEY" 2048
openssl req -x509 -key "$PERM_CA_KEY" -out "$PERM_CA_CERT" -days $DAYS -subj "$PERM_CA_SUBJ"

# Generate private key for Alice
openssl genrsa -out "$ALICE_KEY" 2048

# Create a CSR for Alice
openssl req -new -key "$ALICE_KEY" -out "$ALICE_CSR" -subj "$ALICE_SUBJ"

# Sign Alice's CSR with the identity CA to get her certificate
openssl x509 -req -CA "$ROOT_CA_CERT" -CAkey "$ROOT_CA_KEY" -CAcreateserial -days $DAYS -in "$ALICE_CSR" -out "$ALICE_CERT"