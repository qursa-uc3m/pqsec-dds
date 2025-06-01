# PQSec-DDS

This is a (work in progress) DDS security plugin C/C++ library integrating Post-Quantum Cryptography (PQC) algorithms trough Open Quantum Safe's [liboqs](https://github.com/open-quantum-safe/liboqs) library and [oqs-provider](https://github.com/open-quantum-safe/oqs-provider).

It follows the [DDS Security specification (v1.1)](https://www.omg.org/spec/DDS-SECURITY/1.1/About-DDS-SECURITY) and it has been designed to be compatible with the following DDS implementations:

- [Eclipse Cyclone DDS](https://github.com/eclipse-cyclonedds/cyclonedds)

The dinamical loading of external plugins is well documented in Cyclone DDS. See *External Plugin Development* [here](https://cyclonedds.io/docs/cyclonedds/0.8.2/security.html#external-plugin-developmentl).

## About this project

Preliminary ideas and results of this project were presented at the [IX Jornadas Nacionales de Investigación en Ciberseguridad](https://2024.jnic.es/) held from 27-29th May in Sevilla, Spain. The conference paper

- ***PQSec-DDS: Integrating Post-Quantum Cryptography into DDS Security for Robotic Applications*** by F. J. Blanco-Romero, V. Lorenzo, F. Almenares, D. Dı́az-Sánchez and A. Serrano Navarro

was presented on 29th May. You can find the paper at pages 396-403 of the proceedings [Actas de las IX Jornadas Nacionales de Investigación en Ciberseguridad](https://idus.us.es/handle/11441/159179).

This project includes contributions from Adrián Serrano Navarro's master's thesis ***Integrating post quantum criptography on a publisher-consumer communication over CycloneDDS***, with the integration of the Kyber768 KEM and Dilithium3 signature via liboqs.

### Contributors

The code of this project has been developed by

- [Javier Blanco-Romero](https://github.com/fj-blanco)
- [Adrián Serrano Navarro](https://github.com/100429115)

## Project History

- **v0.0.1 (Experimental)**: Initial implementation using [liboqs](https://github.com/open-quantum-safe/liboqs) directly for post-quantum cryptographic operations.

- **Current (v0.1.0+)**: Migrated to OpenSSL-based implementation using the [oqs-provider](https://github.com/open-quantum-safe/oqs-provider), providing better integration with standard OpenSSL workflows and improved compatibility.

## Requirements

### OpenSSL Version Requirements

- **Minimum**: OpenSSL 3.0
- **Latest**: OpenSSL 3.5+ includes native ML-KEM and ML-DSA support

PQSec-DDS inherits the same OpenSSL version requirements and behaviors as the [oqs-provider](https://github.com/open-quantum-safe/oqs-provider):

### Dependencies

- **OpenSSL 3.0+** with development headers
- **liboqs 0.13.0+** (built automatically by oqs-provider)
- **Eclipse CycloneDDS** (built by provided scripts)

**Note**: When using OpenSSL 3.5+, some algorithms will automatically use OpenSSL's native implementations instead of oqs-provider.

## Quick Start

The easiest way to build PQSec-DDS is using the provided build scripts:

```bash
# 1. Build OQS (OpenSSL with Post-Quantum support)
./scripts/build_oqs.sh

# 2. Build CycloneDDS
./scripts/build_cyclonedds.sh

# 3. Build the PQSec-DDS plugin
./scripts/build_plugin.sh

# 4. Set up environment and test
source setup_env.sh
```

## Automated Build Scripts

### Building OQS Provider and OpenSSL (`build_oqs.sh`)

This script builds OpenSSL 3.x with OQS provider for post-quantum cryptography support.
bash

```bash
./scripts/build_oqs.sh [OPTIONS]
```

Options:

- `-p DIR` - Installation directory (default: /opt/oqs_openssl3)
- `-d` 0|1 - Debug mode (default: 0)
- `-o` VERSION - OpenSSL version (default: openssl-3.5.0)
- `-l` VERSION - liboqs version (default: 0.13.0)
- `-q` VERSION - OQS provider version (default: 0.9.0)
- `-j` JOBS - Parallel build jobs (default: $(nproc))
- `-f` - Force clean rebuild
- `-h` - Show help

### Building CycloneDDS (build_cyclonedds.sh)

This script builds Eclipse CycloneDDS with examples and testing enabled.


```bash
./scripts/build_cyclonedds.sh [OPTIONS]
```

Options:

- `-p` DIR` - Installation directory (default: ./cyclonedds_install)
- `-v` VERSION - CycloneDDS version (default: 0.10.5)
- `-t` TYPE - Build type: Debug|Release (default: Debug)
- `-j` JOBS - Parallel build jobs (default: $(nproc))
- `-f` - Force clean rebuild
- `-h` - Show help

### Building PQSec-DDS Plugin (build_plugin.sh)

This script builds the PQSec-DDS authentication plugin with configurable cryptographic algorithms.

```bash
./scripts/build_plugin.sh [OPTIONS]
```

Options:

- `-c` DIR - CycloneDDS path (default: ./cyclonedds_install)
- `-l` DIR - liboqs path (default: /opt/oqs_openssl3/.local)
- `-o` DIR - OQS provider path (default: /opt/oqs_openssl3)
- `-t` TYPE - Build type: Debug|Release (default: Debug)
- `-j` JOBS - Parallel build jobs (default: $(nproc))
- `--pq` - Enable PQ crypto (default)
- `--no-pq` - Disable PQ crypto (use traditional DH)
- `--kem` ALGORITHM - Select KEM algorithm (see below)
- `--debug-level` LEVEL - Set debug level (NONE|ERROR|WARN|INFO|TRACE|DATA)
- `-f` - Force clean rebuild
- `-h` - Show help

#### Supported KEM Algorithms:

Classical (traditional):

- `ecdh_p256` - ECDH P-256 (default for --no-pq)
- `dh_2048` - Diffie-Hellman 2048-bit

Post-Quantum (ML-KEM):

- `mlkem512` - ML-KEM-512 (128-bit security)
- `mlkem768` - ML-KEM-768 (192-bit security, recommended default)
- `mlkem1024` - ML-KEM-1024 (256-bit security)

Hybrid:

- `X25519MLKEM768` - X25519 + ML-KEM-768
- `p256_mlkem768` - P-256 + ML-KEM-768

#### Debug Levels:

- `NONE` - No debug output
- `ERROR` - Error messages only
- `WARN` - Warnings and errors
- `INFO` - General information + above (default)
- `TRACE` - Detailed tracing + above
- `DATA` - Data dumps and hex output + above

## Plugin Environment Setup

### Certificate Generation

Generate DDS security certificates for testing:

```bash
cd certs
./generate_certs.sh
```

This script generates a set of certificates for different algorithms and levels of security, including:

- ML-DSA: mldsa44 (Level 2), mldsa65 (Level 3), mldsa87 (Level 5)
- Falcon: falcon512 (Level 1), falcon1024 (Level 5)
- Traditional: RSA 2048, ECDSA P-256 for comparison
- Organized in folders: `mldsa/`, `falcon/`, `rsa/`, `traditional/`

Each certificate set includes CA certificates, entity certificates, and private keys required for DDS security authentication.

## Configuration Files

Three CycloneDDS XML configuration files are available in `config/cyclonedds/`:

- `custom_auth_plugin.xml` - PQSec-DDS plugin with traditional ECDSA certificates
- `custom_auth_plugin_mldsa44.xml` - PQSec-DDS plugin with post-quantum ML-DSA44 certificates (default)
- `test_auth_config.xml` - Built-in CycloneDDS authentication for baseline testing

Set the configuration, for example, for the post-quantum ML-DSA44 plugin, you can use:

```bash
export CYCLONEDDS_URI=./config/cyclonedds/custom_auth_plugin_mldsa44.xml
```

## Environment Setup

You can use the provided environment setup script to configure all necessary environment variables:

```bash
source setup_env.sh
```

This script automatically:

- Sets up OQS provider environment (uses `/opt/oqs_openssl3` - default from `build_oqs_enhanced.sh`)
- Configures DDS library paths (uses `./cyclonedds_install` - default from `build_cyclonedds.sh`)
- Sets the plugin configuration (uses `./src/build/lib` - default from `build_plugin.sh`)
- Verifies all components are found

Note: The environment setup uses the default installation paths from the build scripts above. If you used custom paths with the `-p`, `-c`, `-l`, or `-o` options in the build scripts, you'll need to either modify `setup_env.sh` accordingly or use manual environment setup.

## Testing the Plugin

You can have a quick test running the test application with

```bash
source setup_env.sh
./bin/HelloworldSubscriber
```

and

```bash
source setup_env.sh
./bin/HelloworldPublisher
```

You should see the debug messages from the custom plugin and the publisher/subscriber exchanging messages:

```text
=== [Publisher]  Writing : Message (1, Hello World)
```

and

```text
=== [Subscriber] Received : Message (1, Hello World)
```

## Contributing

Contributions are welcome!