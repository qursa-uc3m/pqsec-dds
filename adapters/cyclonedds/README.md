# PQSec-DDS for CycloneDDS

This adapter is an external DDS Security Authentication plugin for CycloneDDS.
It is based on CycloneDDS's built-in PKI-DH plugin and implements
DDS:Auth:PKI-DH with ML-KEM and ML-DSA as additional algorithms, as described
in [protocol/pkidh-mlkem.md](../../protocol/pkidh-mlkem.md). The OpenDDS
adapter implements the same profile.

The implementation was originally developed by Javier Blanco-Romero and Adrián
Serrano Navarro. Earlier experimental releases called liboqs directly. The
current implementation deliberately does not: all key generation,
encapsulation, decapsulation, signing, verification, and key serialization go
through OpenSSL EVP.

## Algorithms

OpenSSL's default provider supplies every algorithm the plugin uses:
ML-KEM-768, ML-KEM-1024 and X25519MLKEM768 for key establishment, and
ML-DSA-65, ML-DSA-87 and ECDSA P-256 for identities. No other provider is loaded, and the
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

`--kem` sets the KEM used when this participant initiates and the value of
`AUTO`: `mlkem768`, `mlkem1024` or `x25519_mlkem768`. The participant QoS
property `dds.sec.auth.key_establishment_algorithm` (DDS Security 1.2,
10.3.1.4) overrides it at run time with `ML-KEM-768`, `ML-KEM-1024` or
`X25519MLKEM768`.

## Protocol

Tokens, class ids, properties and signed transcripts are those of PKI-DH.
`dh1` carries the initiator's encapsulation key and `dh2` the replier's
ciphertext, and `SharedSecret` is SHA-256 of the KEM secret. The initiator
chooses the KEM; the replier answers with the same one. By default the replier
accepts all three. The participant QoS property
`pqsec.auth.accepted_key_establishment_algorithms`, a comma-separated list such
as `X25519MLKEM768, ML-KEM-1024`, restricts the ones it accepts. A classical algorithm in `c.kagree_algo` is refused. Echoed `dh1`, `dh2`,
`hash_c1` and `hash_c2` are optional, and must equal the local values when
present.

## Certificates

Identity certificates and the identity CA use ML-DSA-65, ML-DSA-87 or ECDSA
P-256, in any combination; other keys are refused. An ECDSA identity still
gets an ML-KEM handshake. `certs/generate_certs.sh` makes ML-DSA and ECDSA
examples. Run `certs/generate_certs.sh` with an OpenSSL 3.5+
executable:

```sh
OPENSSL=/path/to/openssl certs/generate_certs.sh
```

## Tests

The CTest suite covers the three KEMs, OpenSSL's rejection of malformed or
invalid encapsulation keys and of hybrid X25519 shares, ML-DSA and ECDSA transcript signing and tamper rejection, and the
shared protocol vectors. The handshake test drives two plugin instances through
complete handshakes for each KEM and checks that they derive the same secret,
that the replier follows the initiator's KEM, that a substituted `dh1` or
`dh2`, altered credentials, a tampered or mismatched Final, echoes that differ
from the local values, classical key establishment and identities on other
curves are rejected, that ECDSA P-256 identities work alone and mixed with
ML-DSA, and that a repeated Request is handled correctly.

The OpenDDS adapter implements the same profile and passes the same vectors;
`tests/interoperability` runs the two against each other. This adapter
defaults to `mlkem768` and the OpenDDS adapter to `X25519MLKEM768`; since the
initiator chooses, mixed defaults still interoperate.

## Attribution

Preliminary results were published in “PQSec-DDS: Integrating Post-Quantum
Cryptography into DDS Security for Robotic Applications” at JNIC 2024. The
initial Kyber/Dilithium integration also includes work from Adrián Serrano
Navarro's master's thesis.
