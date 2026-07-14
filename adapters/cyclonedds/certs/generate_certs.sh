#!/bin/bash
#
# generate_certs.sh — Generate post-quantum certificates
# Copyright (C) 2023-2025 Javier Blanco
#
# Updated to use ML-DSA (formerly Dilithium) and organized output folders.

if [ "$OPENSSL" = "" ]; then
   OPENSSL=/usr/local/bin/oqs_openssl3
fi
# add provider path if not defined
if [ "$PROVIDER_PATH" = "" ]; then
   PROVIDER_PATH=/opt/oqs_openssl3/oqs-provider/_build/lib
fi

# Common provider arguments - IMPORTANT: Always include both providers
PROVIDER_ARGS="-provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default"

# Test if OQS provider is working
echo "Testing OQS provider availability..."
${OPENSSL} list -providers ${PROVIDER_ARGS} | grep -q "oqsprovider"
if [ $? -ne 0 ]; then
    echo "ERROR: OQS provider not found or not loading properly!"
    exit 1
fi
echo "OQS provider is available."

# Create organized folder structure
echo "Creating certificate folders..."
mkdir -p traditional mldsa falcon rsa
echo "Folders created: traditional/, mldsa/, falcon/, rsa/"

# Generate conf files.
printf "\
[ req ]\n\
prompt                 = no\n\
distinguished_name     = req_distinguished_name\n\
\n\
[ req_distinguished_name ]\n\
C                      = CA\n\
ST                     = ON\n\
L                      = Waterloo\n\
O                      = UC3M\n\
OU                     = Engineering\n\
CN                     = Root Certificate\n\
emailAddress           = root@uc3m.com\n\
\n\
[ ca_extensions ]\n\
subjectKeyIdentifier   = hash\n\
authorityKeyIdentifier = keyid:always,issuer:always\n\
keyUsage               = critical, keyCertSign\n\
basicConstraints       = critical, CA:true\n" > root.conf

printf "\
[ req ]\n\
prompt                 = no\n\
distinguished_name     = req_distinguished_name\n\
\n\
[ req_distinguished_name ]\n\
C                      = CA\n\
ST                     = ON\n\
L                      = Waterloo\n\
O                      = UC3M\n\
OU                     = Engineering\n\
CN                     = Entity Certificate\n\
emailAddress           = entity@uc3m.com\n\
\n\
[ x509v3_extensions ]\n\
subjectAltName = IP:127.0.0.1\n\
subjectKeyIdentifier   = hash\n\
authorityKeyIdentifier = keyid:always,issuer:always\n\
keyUsage               = critical, digitalSignature\n\
extendedKeyUsage       = critical, serverAuth,clientAuth\n\
basicConstraints       = critical, CA:false\n" > entity.conf

###############################################################################
# ML-DSA (formerly Dilithium) - Level 2 security (mldsa44)
###############################################################################

echo "Generating ML-DSA44 (Level 2) keys..."
${OPENSSL} genpkey -algorithm mldsa44 -outform pem -out mldsa/mldsa44_root_key.pem ${PROVIDER_ARGS}
${OPENSSL} genpkey -algorithm mldsa44 -outform pem -out mldsa/mldsa44_entity_key.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA44 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 512 -key mldsa/mldsa44_root_key.pem -out mldsa/mldsa44_root_cert.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA44 entity CSR..."
${OPENSSL} req -new -config entity.conf -key mldsa/mldsa44_entity_key.pem -out mldsa/mldsa44_entity_req.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA44 entity certificate..."
${OPENSSL} x509 -req -in mldsa/mldsa44_entity_req.pem -CA mldsa/mldsa44_root_cert.pem -CAkey mldsa/mldsa44_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 513 -out mldsa/mldsa44_entity_cert.pem ${PROVIDER_ARGS}

###############################################################################
# ML-DSA (formerly Dilithium) - Level 3 security (mldsa65)
###############################################################################

echo "Generating ML-DSA65 (Level 3) keys..."
${OPENSSL} genpkey -algorithm mldsa65 -outform pem -out mldsa/mldsa65_root_key.pem ${PROVIDER_ARGS}
${OPENSSL} genpkey -algorithm mldsa65 -outform pem -out mldsa/mldsa65_entity_key.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA65 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 514 -key mldsa/mldsa65_root_key.pem -out mldsa/mldsa65_root_cert.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA65 entity CSR..."
${OPENSSL} req -new -config entity.conf -key mldsa/mldsa65_entity_key.pem -out mldsa/mldsa65_entity_req.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA65 entity certificate..."
${OPENSSL} x509 -req -in mldsa/mldsa65_entity_req.pem -CA mldsa/mldsa65_root_cert.pem -CAkey mldsa/mldsa65_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 515 -out mldsa/mldsa65_entity_cert.pem ${PROVIDER_ARGS}

###############################################################################
# ML-DSA (formerly Dilithium) - Level 5 security (mldsa87)
###############################################################################

echo "Generating ML-DSA87 (Level 5) keys..."
${OPENSSL} genpkey -algorithm mldsa87 -outform pem -out mldsa/mldsa87_root_key.pem ${PROVIDER_ARGS}
${OPENSSL} genpkey -algorithm mldsa87 -outform pem -out mldsa/mldsa87_entity_key.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA87 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 516 -key mldsa/mldsa87_root_key.pem -out mldsa/mldsa87_root_cert.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA87 entity CSR..."
${OPENSSL} req -new -config entity.conf -key mldsa/mldsa87_entity_key.pem -out mldsa/mldsa87_entity_req.pem ${PROVIDER_ARGS}

echo "Generating ML-DSA87 entity certificate..."
${OPENSSL} x509 -req -in mldsa/mldsa87_entity_req.pem -CA mldsa/mldsa87_root_cert.pem -CAkey mldsa/mldsa87_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 517 -out mldsa/mldsa87_entity_cert.pem ${PROVIDER_ARGS}

###############################################################################
# Falcon NIST Level 1 (falcon512)
###############################################################################

echo "Generating Falcon NIST Level 1 (falcon512) keys..."
${OPENSSL} genpkey -algorithm falcon512 -outform pem -out falcon/falcon512_root_key.pem ${PROVIDER_ARGS}
${OPENSSL} genpkey -algorithm falcon512 -outform pem -out falcon/falcon512_entity_key.pem ${PROVIDER_ARGS}

echo "Generating Falcon512 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 518 -key falcon/falcon512_root_key.pem -out falcon/falcon512_root_cert.pem ${PROVIDER_ARGS}

echo "Generating Falcon512 entity CSR..."
${OPENSSL} req -new -config entity.conf -key falcon/falcon512_entity_key.pem -out falcon/falcon512_entity_req.pem ${PROVIDER_ARGS}

echo "Generating Falcon512 entity certificate..."
${OPENSSL} x509 -req -in falcon/falcon512_entity_req.pem -CA falcon/falcon512_root_cert.pem -CAkey falcon/falcon512_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 519 -out falcon/falcon512_entity_cert.pem ${PROVIDER_ARGS}

###############################################################################
# Falcon NIST Level 5 (falcon1024)
###############################################################################

echo "Generating Falcon NIST Level 5 (falcon1024) keys..."
${OPENSSL} genpkey -algorithm falcon1024 -outform pem -out falcon/falcon1024_root_key.pem ${PROVIDER_ARGS}
${OPENSSL} genpkey -algorithm falcon1024 -outform pem -out falcon/falcon1024_entity_key.pem ${PROVIDER_ARGS}

echo "Generating Falcon1024 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 520 -key falcon/falcon1024_root_key.pem -out falcon/falcon1024_root_cert.pem ${PROVIDER_ARGS}

echo "Generating Falcon1024 entity CSR..."
${OPENSSL} req -new -config entity.conf -key falcon/falcon1024_entity_key.pem -out falcon/falcon1024_entity_req.pem ${PROVIDER_ARGS}

echo "Generating Falcon1024 entity certificate..."
${OPENSSL} x509 -req -in falcon/falcon1024_entity_req.pem -CA falcon/falcon1024_root_cert.pem -CAkey falcon/falcon1024_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 521 -out falcon/falcon1024_entity_cert.pem ${PROVIDER_ARGS}

###############################################################################
# Traditional RSA 2048
###############################################################################

echo "Generating RSA 2048 keys..."
${OPENSSL} genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa/rsa2048_root_key.pem
${OPENSSL} genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa/rsa2048_entity_key.pem

echo "Generating RSA 2048 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 522 -key rsa/rsa2048_root_key.pem -out rsa/rsa2048_root_cert.pem

echo "Generating RSA 2048 entity CSR..."
${OPENSSL} req -new -config entity.conf -key rsa/rsa2048_entity_key.pem -out rsa/rsa2048_entity_req.pem

echo "Generating RSA 2048 entity certificate..."
${OPENSSL} x509 -req -in rsa/rsa2048_entity_req.pem -CA rsa/rsa2048_root_cert.pem -CAkey rsa/rsa2048_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 523 -out rsa/rsa2048_entity_cert.pem

###############################################################################
# Traditional ECDSA P-256
###############################################################################

echo "Generating ECDSA P-256 keys..."
${OPENSSL} genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out traditional/ecdsa_p256_root_key.pem
${OPENSSL} genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out traditional/ecdsa_p256_entity_key.pem

echo "Generating ECDSA P-256 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 524 -key traditional/ecdsa_p256_root_key.pem -out traditional/ecdsa_p256_root_cert.pem

echo "Generating ECDSA P-256 entity CSR..."
${OPENSSL} req -new -config entity.conf -key traditional/ecdsa_p256_entity_key.pem -out traditional/ecdsa_p256_entity_req.pem

echo "Generating ECDSA P-256 entity certificate..."
${OPENSSL} x509 -req -in traditional/ecdsa_p256_entity_req.pem -CA traditional/ecdsa_p256_root_cert.pem -CAkey traditional/ecdsa_p256_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 525 -out traditional/ecdsa_p256_entity_cert.pem

###############################################################################
# Verify all generated certificates.
###############################################################################
echo "Verifying certificates..."

echo "Verifying ML-DSA certificates..."
${OPENSSL} verify -no-CApath -check_ss_sig ${PROVIDER_ARGS} -CAfile mldsa/mldsa44_root_cert.pem mldsa/mldsa44_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig ${PROVIDER_ARGS} -CAfile mldsa/mldsa65_root_cert.pem mldsa/mldsa65_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig ${PROVIDER_ARGS} -CAfile mldsa/mldsa87_root_cert.pem mldsa/mldsa87_entity_cert.pem

echo "Verifying Falcon certificates..."
${OPENSSL} verify -no-CApath -check_ss_sig ${PROVIDER_ARGS} -CAfile falcon/falcon512_root_cert.pem falcon/falcon512_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig ${PROVIDER_ARGS} -CAfile falcon/falcon1024_root_cert.pem falcon/falcon1024_entity_cert.pem

echo "Verifying traditional certificates..."
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile rsa/rsa2048_root_cert.pem rsa/rsa2048_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile traditional/ecdsa_p256_root_cert.pem traditional/ecdsa_p256_entity_cert.pem

# Clean up config files
rm -f root.conf entity.conf

echo ""
echo "Certificate generation completed successfully!"
echo ""
echo "Generated certificates are organized in folders:"
echo "  mldsa/     - ML-DSA (formerly Dilithium) certificates"
echo "  falcon/    - Falcon certificates"
echo "  rsa/       - RSA certificates"
echo "  traditional/ - ECDSA certificates"
echo ""
echo "Each folder contains:"
echo "  *_root_key.pem     - Root CA private key"
echo "  *_root_cert.pem    - Root CA certificate"
echo "  *_entity_key.pem   - Entity private key"
echo "  *_entity_cert.pem  - Entity certificate"
echo "  *_entity_req.pem   - Entity certificate signing request"