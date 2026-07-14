# PQSec-DDS for CycloneDDS

This adapter is an external DDS Security Authentication plugin for CycloneDDS.
It is based on CycloneDDS's built-in PKI-DH plugin, with an experimental
post-quantum handshake identified as `pqsec-dds.auth:1.0`.

The implementation was originally developed by Javier Blanco-Romero and Adrián
Serrano Navarro. Earlier experimental releases called liboqs directly. The
current implementation deliberately does not: all key generation,
encapsulation, decapsulation, signing, verification, and key serialization go
through OpenSSL EVP.

## OpenSSL provider model

- OpenSSL's default provider supplies ML-KEM-512/768/1024, ML-DSA-44/65/87,
  X25519MLKEM768, and SecP256r1MLKEM768.
- oqs-provider can optionally supply experimental KEMs such as FrodoKEM, BIKE,
  and HQC. liboqs remains behind that provider boundary.
- The plugin has no liboqs headers, symbols, or link dependency.

The selected KEM is checked during plugin initialization. If it is already
available, no fallback provider is loaded. Otherwise, the plugin loads
`PQSEC_FALLBACK_PROVIDER` (normally `oqsprovider`). The environment variable
`PQSEC_OPENSSL_PROVIDER` can override that provider name. Standard OpenSSL
configuration and `OPENSSL_MODULES` control where provider modules are found.

An external provider must be built against the same OpenSSL installation used
by CycloneDDS and this plugin. Mixing provider and application OpenSSL builds is
unsupported and can crash inside the provider ABI.

## Build

Requirements are CycloneDDS with Security enabled and OpenSSL 3.5 or newer.
OpenSSL 3.6 is needed for the tested native hybrid KEMs.

```sh
./scripts/build_plugin.sh \
  -c /path/to/cyclonedds-install \
  -s /path/to/openssl-prefix \
  --kem mlkem768
```

Native KEM selections are `mlkem512`, `mlkem768`, `mlkem1024`,
`x25519_mlkem768`, and `p256_mlkem768`. Experimental selections are
`frodo640shake`, `bikel1`, and `hqc128`.

For an experimental provider algorithm:

```sh
export OPENSSL_MODULES=/path/to/openssl-prefix/lib64/ossl-modules
./scripts/build_plugin.sh --kem frodo640shake --provider oqsprovider
```

`scripts/build_oqs.sh` remains as a convenience for building OpenSSL, liboqs,
and oqs-provider together. liboqs produced by that script is a private
dependency of oqs-provider, not of this plugin.

## Certificates

Identity certificates use native ML-DSA. Run `certs/generate_certs.sh` with an
OpenSSL 3.5+ executable:

```sh
OPENSSL=/path/to/openssl certs/generate_certs.sh
```

## Tests

The CTest suite covers pure ML-KEM, native X25519/P-256 hybrid KEMs, malformed
public-key rejection, and ML-DSA transcript signing and tamper rejection.
Experimental oqs-provider KEMs can be included explicitly:

```sh
OPENSSL_MODULES=/path/to/ossl-modules \
PQSEC_TEST_OQS_PROVIDER=1 \
ctest --test-dir build --output-on-failure
```

Both peers must use the same plugin and KEM selection. Interoperability with the
OpenDDS adapter is planned but is not yet claimed.

## Attribution

Preliminary results were published in “PQSec-DDS: Integrating Post-Quantum
Cryptography into DDS Security for Robotic Applications” at JNIC 2024. The
initial Kyber/Dilithium integration also includes work from Adrián Serrano
Navarro's master's thesis.
