# PQSec-DDS for CycloneDDS

This adapter is an external DDS Security Authentication plugin for CycloneDDS.
It is based on CycloneDDS's built-in PKI-DH plugin, with the experimental
post-quantum handshake [`pqsec-dds.auth:1.1`](../../protocol/pqsec-auth-v1.md)
shared with the OpenDDS adapter.

The implementation was originally developed by Javier Blanco-Romero and Adrián
Serrano Navarro. Earlier experimental releases called liboqs directly. The
current implementation deliberately does not: all key generation,
encapsulation, decapsulation, signing, verification, and key serialization go
through OpenSSL EVP.

## Algorithms

OpenSSL's default provider supplies every algorithm the plugin uses:
ML-KEM-768, ML-KEM-1024 and X25519MLKEM768 for key establishment, and
ML-DSA-65 and ML-DSA-87 for identities. No other provider is loaded, and the
plugin has no liboqs headers, symbols, or link dependency.

## Build

Requirements are CycloneDDS with Security enabled and OpenSSL 3.5 or newer.
OpenSSL 3.6 is needed for the tested native hybrid KEMs.

```sh
./scripts/build_plugin.sh \
  -c /path/to/cyclonedds-install \
  -s /path/to/openssl-prefix \
  --kem mlkem768
```

KEM selections are `mlkem768`, `mlkem1024` and `x25519_mlkem768`.

## Certificates

Identity certificates and the identity CA must use native ML-DSA; the plugin
rejects classical keys. Run `certs/generate_certs.sh` with an OpenSSL 3.5+
executable:

```sh
OPENSSL=/path/to/openssl certs/generate_certs.sh
```

## Tests

The CTest suite covers the three KEMs, OpenSSL's rejection of malformed or
invalid encapsulation keys and of hybrid X25519 shares, ML-DSA transcript signing and tamper rejection, and the
shared protocol vectors. The handshake test drives two plugin instances through
a complete handshake and checks that they derive the same secret, that a
substituted KEM public key or ciphertext, altered credentials, a tampered Final
and classical identities are rejected, and that a repeated Request is handled
correctly.

Both peers must use the same KEM selection. The OpenDDS adapter implements the
same protocol and passes the same vectors, but the two adapters have not yet
been run against each other. Note that this adapter defaults to `mlkem768` and
the OpenDDS adapter to `X25519MLKEM768`.

## Attribution

Preliminary results were published in “PQSec-DDS: Integrating Post-Quantum
Cryptography into DDS Security for Robotic Applications” at JNIC 2024. The
initial Kyber/Dilithium integration also includes work from Adrián Serrano
Navarro's master's thesis.
