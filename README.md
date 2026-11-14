# PQSec-DDS

PQSec-DDS is a multi-DDS project for experimenting with post-quantum and
hybrid authentication through the DDS Security Authentication SPI.

## Repository layout

```text
pqsec-dds/
  protocol/                 Shared experimental wire-protocol documents
  core/                     Future DDS-neutral OpenSSL core
  adapters/
    cyclonedds/             External CycloneDDS authentication plugin
    opendds/                External OpenDDS authentication plugin
  tests/
    vectors/                Shared protocol-vector area
    interoperability/       Reserved for future cross-DDS tests
```

The adapters are separate because CycloneDDS exposes a C plugin ABI while
OpenDDS exposes IDL-generated C++ interfaces and an ACE service loader.  They
can eventually share algorithms, transcript construction, protocol documents,
and test vectors, but they cannot share one plugin binary.

## Adapters

### CycloneDDS

The implementation has been cleaned up and retained at
[adapters/cyclonedds](adapters/cyclonedds/README.md). Cryptographic operations
use OpenSSL EVP: native OpenSSL providers for standardized algorithms and an
optional oqs-provider fallback for experiments. Neither adapter calls liboqs
directly.

```sh
cd adapters/cyclonedds
./scripts/build_cyclonedds.sh
./scripts/build_plugin.sh
```

### OpenDDS

The experimental OpenDDS adapter is documented in
[adapters/opendds](adapters/opendds/README.md).  It requires the OpenDDS fork's
`feature/external-security-plugins` branch while the external-loader changes
are being proposed upstream.

```sh
cmake -S adapters/opendds -B adapters/opendds/build \
  -DOPENDDS_ROOT=/path/to/OpenDDS \
  -DOPENSSL_ROOT_DIR=/path/to/openssl-3.6
cmake --build adapters/opendds/build -j
ctest --test-dir adapters/opendds/build --output-on-failure
```

## Shared work

Both adapters implement [protocol 1.1](protocol/pqsec-auth-v1.md) and test
against the same byte-for-byte [vectors](tests/vectors).  Each still has its
own crypto wrapper and transcript code; moving those into `core/` is future
work, as is running the two adapters against each other.

## License

See [LICENSE.txt](LICENSE.txt).
