# OpenDDS PQSec authentication plugin

This directory contains an external C++ DDS Security Authentication plugin for
OpenDDS. It uses OpenSSL EVP with the native provider implementations in
OpenSSL 3.6 or newer:

- X25519MLKEM768 (default), ML-KEM-768 or ML-KEM-1024 for the shared secret
- ML-DSA-65 or ML-DSA-87 X.509 identity certificates for mutual
  authentication

No other OpenSSL provider is loaded.

It deliberately implements only `DDS::Security::Authentication`.  OpenDDS
composes it with its built-in Access Control, Cryptographic, and Utility plugins.
This keeps governance, permissions, RTPS protection, and key exchange after
authentication on the existing, tested OpenDDS implementation.

## OpenDDS dependency

The plugin currently requires the `security-1.2-algorithms` branch of the
OpenDDS fork.  That branch adds:

1. INI-driven dynamic security-plugin registration.
2. Selection of a global named security configuration at startup.
3. Per-interface composition, including the Utility interface.
4. Digestless ML-DSA support in OpenDDS's X.509 signing helpers.
5. The DDS Security 1.2 participant algorithm negotiation, including the
   Authentication operation `set_participant_security_config`, which every
   Authentication plugin must implement.

These are generic OpenDDS changes.  No PQSec-specific library or protocol name is
hard-coded in the fork.

The adapter also consumes OpenDDS-internal C++ helpers, notably
`SSL::Certificate`, `LocalAuthCredentialData`, and the security token utilities;
these are not a stable external plugin ABI and may require adapter changes when
OpenDDS changes them.  The external-loader changes, the digestless ML-DSA
helper support and the 1.2 negotiation should therefore be reviewed and
upstreamed as separate OpenDDS changes before this adapter can build against an
unmodified release.

## Protocol

The plugin implements DDS:Auth:PKI-DH of DDS Security 1.2 with ML-KEM and
ML-DSA as additional algorithms, as described in
[protocol/pkidh-mlkem.md](../../protocol/pkidh-mlkem.md). Tokens, class ids
(`DDS:Auth:PKI-DH:1.0+Req` and so on), properties and signed transcripts are
those of PKI-DH. The key establishment properties carry the KEM values: `dh1`
is the initiator's encapsulation key and `dh2` the replier's ciphertext.
`SharedSecret` is SHA-256 of the KEM secret, and OpenDDS's built-in
Cryptographic plugin derives its keys from it as for PKI-DH.

The initiator chooses the KEM. The replier accepts any of the three and
answers with the same one. A classical algorithm in `c.kagree_algo` is
refused, so a classical PKI-DH peer does not authenticate with this plugin.

Optional echoes of `dh1`, `dh2`, `hash_c1` and `hash_c2` are not sent. If a
peer sends them, they must equal the local values, which are the ones used.

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

The tests cover the three KEMs and two ML-DSA parameter sets above, OpenSSL's
rejection of invalid encapsulation keys and hybrid X25519 shares, the shared protocol vectors, a complete two-peer
Authentication handshake using ML-DSA X.509 certificates for each KEM,
shared-secret equality, tampered signatures, a substituted `dh1` or `dh2`,
altered credentials, the initiator's choice of KEM, classical or mismatched
algorithms, echoes that differ from the local value, challenge mismatches, certificates from
an unrelated CA, a classical identity CA, replay rejection, and loading the
plugin from an INI file without linking it into the test executable.

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
must use the same ML-DSA parameter set, and the identity CA must also use
ML-DSA.  The permissions CA and signed governance/permissions
documents can continue to use an algorithm supported by OpenDDS's built-in Access
Control plugin.

The optional participant QoS property
`dds.sec.auth.key_establishment_algorithm` (DDS Security 1.2, 10.3.1.4)
selects the KEM this participant uses when it initiates: `X25519MLKEM768`,
`ML-KEM-768` or `ML-KEM-1024`. `AUTO`, or no property, means
`X25519MLKEM768`. `X25519MLKEM768` is OpenSSL's native TLS-style hybrid KEM
and combines X25519 with ML-KEM-768 inside the provider.

Through `set_participant_security_config` the plugin announces in discovery
the three KEMs and both ML-DSA levels as supported, and its own KEM and ML-DSA
levels as required, using the provisional vendor-range bits of the protocol
document. A participant configuration that removes a KEM from the supported
set also stops the plugin from accepting it as replier. Vendor-range bits are
interpreted per RTPS vendor, so this negotiation only works between OpenDDS
participants.

The governance document must keep `allow_unauthenticated_participants` disabled.
Classical PKI-DH peers fail authentication with this plugin; allowing them to
remain in the domain would bypass the post-quantum authentication guarantee.

## Current boundaries

- There is no downgrade to a classical algorithm.  Mixed classical/PQ peers do
  not authenticate.
- The CycloneDDS adapter has not moved to PKI-DH yet.
- The implementation uses pure ML-DSA, not the pre-hash variants, and buffers the
  serialized transcript because OpenSSL exposes pure ML-DSA as a one-shot
  signature operation.
- ML-KEM and ML-DSA are native in OpenSSL 3.5.  This plugin requires OpenSSL
  3.6 because its tested default is the native `X25519MLKEM768` hybrid KEM.
