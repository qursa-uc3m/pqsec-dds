# OpenDDS PQSec authentication plugin

This directory contains an external C++ DDS Security Authentication plugin for
OpenDDS.  It uses the native provider implementations in OpenSSL 3.6 or newer:

- X25519MLKEM768 (default), or pure ML-KEM-512/768/1024, for the shared secret
- ML-DSA-44, ML-DSA-65, or ML-DSA-87 X.509 identity certificates for mutual
  authentication

It deliberately implements only `DDS::Security::Authentication`.  OpenDDS
composes it with its built-in Access Control, Cryptographic, and Utility plugins.
This keeps governance, permissions, RTPS protection, and key exchange after
authentication on the existing, tested OpenDDS implementation.

## OpenDDS dependency

The plugin currently requires the accompanying `feature/external-security-plugins`
branch in an OpenDDS checkout.  That branch adds:

1. INI-driven dynamic security-plugin registration.
2. Selection of a global named security configuration at startup.
3. Per-interface composition, including the Utility interface.
4. Digestless ML-DSA support in OpenDDS's X.509 signing helpers.

These are generic OpenDDS changes.  No PQSec-specific library or protocol name is
hard-coded in the fork.

## Protocol

The complete experimental wire format is documented in
[the shared protocol directory](../../protocol/pqsec-auth-v1.md).

The wire class identifier is
`pqsec-dds.auth:1.0`.  It is an experimental extension, not
the standard `DDS:Auth:PKI-DH:1.0` mechanism, so both peers must use this plugin.
The project identifier avoids claiming an OMG-reserved `DDS:*` class identifier.
It is provisional; a stable standards-strict release should replace it with a
prefix derived from an ICANN domain owned by the project.

The request contains one ephemeral KEM public key.  The replier encapsulates once
and returns the ciphertext.  With the default, OpenSSL performs the X25519 and
ML-KEM-768 hybrid internally using its TLS hybrid implementation.  The reply and
final messages carry ML-DSA
signatures over the complete credential hashes, both challenges, the KEM public
key, and ciphertext.  Signed material also includes a fixed protocol/version and
message-role domain separator.  This gives explicit key confirmation in both
directions without generating a redundant second KEM keypair.

The resulting KEM secret and both challenges are returned through the standard
DDS Security `SharedSecretHandle`.  OpenDDS's built-in cryptographic
plugin then performs the normal DDS Security key derivation and RTPS protection.

## Build and test

First build the security-enabled OpenDDS fork.  Then configure this project with
the same OpenSSL installation used for OpenDDS:

```sh
cd OpenDDS
./configure --security --openssl=/path/to/openssl-prefix
make -j
cd ..
```

The MPC build expects OpenSSL libraries below `<prefix>/lib`.  If an OpenSSL
installation contains only `lib64`, provide a compatibility prefix whose `lib`
symlink points at that directory; otherwise the linker can silently select the
system OpenSSL instead.

```sh
cmake -S adapters/opendds -B adapters/opendds/build \
  -DOPENDDS_ROOT="$PWD/OpenDDS" \
  -DOPENSSL_ROOT_DIR=/path/to/openssl-3.6-or-newer
cmake --build adapters/opendds/build -j
ctest --test-dir adapters/opendds/build --output-on-failure
```

The tests cover all three native ML-KEM parameter sets, X25519MLKEM768, all three
native ML-DSA parameter sets, a complete two-peer Authentication handshake using
ML-DSA X.509 certificates and the hybrid KEM, shared-secret equality, and loading
the plugin from an INI file without linking it into the test executable.

## Configuration

Register the shared library and compose the named configuration:

```ini
[common]
DCPSSecurity=1
DCPSGlobalSecurityConfig=pqsec

[security_plugin/PQSec]
Library=/absolute/path/to/libOpenDDS_PQSec
Loader=PQSecPluginLoader

[security/pqsec]
AuthConfig=PQSec
AccessCtrlConfig=BuiltIn
CryptoConfig=BuiltIn
UtilityConfig=BuiltIn
```

Configure the ordinary DDS Security certificate, permissions, and governance QoS
properties on each participant.  The identity certificate and its private key
must use the same ML-DSA parameter set; the identity CA only needs to form a chain
accepted by OpenSSL.  The permissions CA and signed governance/permissions
documents can continue to use an algorithm supported by OpenDDS's built-in Access
Control plugin.

The optional participant QoS property
`pqsec-dds.kem` selects `X25519MLKEM768` (the default),
`ML-KEM-512`, `ML-KEM-768`, or `ML-KEM-1024`.  `X25519MLKEM768` is OpenSSL's
native TLS-style hybrid KEM and combines X25519 with ML-KEM-768 inside the
provider.  Both peers must select the same value; mismatches fail closed.

## Current boundaries

- There is no negotiation or downgrade to PKI-DH.  Mixed built-in/PQSec peers do
  not authenticate.
- The protocol identifier and transcript layout need a shared specification
  before interoperability with a CycloneDDS implementation can be claimed.
- The implementation uses pure ML-DSA, not the pre-hash variants, and buffers the
  serialized transcript because OpenSSL exposes pure ML-DSA as a one-shot
  signature operation.
- ML-KEM and ML-DSA are native in OpenSSL 3.5.  This plugin requires OpenSSL
  3.6 because its tested default is the native `X25519MLKEM768` hybrid KEM.
