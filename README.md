# PQSec-DDS

This is a (work in progress) DDS security plugin C/C++ library integrating Post-Quantum Cryptography (PQC) algorithms trough Open Quantum Safe's [liboqs](https://github.com/open-quantum-safe/liboqs) library and [oqs-provider](https://github.com/open-quantum-safe/oqs-provider).

It follows the [DDS Security specification (v1.1)](https://www.omg.org/spec/DDS-SECURITY/1.1/About-DDS-SECURITY) and it has been designed to be compatible with the following DDS implementations:

- [Eclipse Cyclone DDS](https://github.com/eclipse-cyclonedds/cyclonedds)
- [OpenDDS](https://github.com/OpenDDS/OpenDDS)

## About this project

Preliminary ideas and results of this project were presented at the [IX Jornadas Nacionales de Investigación en Ciberseguridad](https://2024.jnic.es/) held from 27-29th May in Sevilla, Spain. The conference paper

- ***PQSec-DDS: Integrating Post-Quantum Cryptography into DDS Security for Robotic Applications*** by F. J. Blanco-Romero, V. Lorenzo, F. Almenares, D. Dı́az-Sánchez and A. Serrano Navarro

was presented on 29th May. You can find the paper at pages 396-403 of the proceedings [Actas de las IX Jornadas Nacionales de Investigación en Ciberseguridad](https://idus.us.es/handle/11441/159179).

This project includes contributions from Adrián Serrano Navarro's master's thesis ***Integrating post quantum criptography on a publisher-consumer communication over CycloneDDS***, with the integration of the Kyber768 KEM and Dilithium3 signature via liboqs.

### Contributors

The code of this project has been developed by

- [Javier Blanco-Romero](https://github.com/fj-blanco)
- [Adrián Serrano Navarro](https://github.com/100429115)

## Building dependencies

We need to build the `liboqs` library and enable PQ cryptography in OpenSSL trough the `oqs-provider` library.

### Building `liboqs`

You can follow the instructions in the official repository [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs) to build the library. Here is a quick guide to build the library in a custom directory

```bash
cd /tmp
sudo rm -rf liboqs
git clone --branch main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
sudo mkdir -p <path_to_liboqs>
cmake -GNinja -DCMAKE_INSTALL_PREFIX=<path_to_liboqs> ..
ninja
sudo ninja install
```

Ensure the `liboqs` library is correctly build under the `<path_to_liboqs>` directory.

### Building `oqs-provider`

You can also follow the instructions in the official repository [open-quantum-safe/oqs-provider](https://github.com/open-quantum-safe/oqs-provider) to build the provider.

First we build a separate installation of OpenSSL 3.*

```bash
cd <oqs-provider-install-dir>
git clone git://git.openssl.org/openssl.git
cd openssl
./config --prefix=$(echo $(pwd)/../.local) && make && make install_sw
cd ..
```

Building the provider. Run this in the `<oqs-provider-install-dir>` directory:

```bash
cd <oqs-provider-install-dir>
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -DOPENSSL_ROOT_DIR=$(pwd)/../.local -DCMAKE_PREFIX_PATH=$(pwd)/../.local -S . -B _build
cmake --build _build
cd ..
```

Add the provider to the `LD_LIBRARY_PATH` environment variable

```text
export LD_LIBRARY_PATH="<oqs-provider-install-dir>/.local/lib64:$LD_LIBRARY_PATH"
```

### Adding `openssl.cnf` file enabling the oqs-provider

First check the location of the OpenSSL `openssl.cnf` configuration file with

```bash
<oqs-provider-install-dir>/.local/bin/openssl version -d
```

Make sure that the obtained directory contains a `openssl.cnf` file containing the following lines

```text
[openssl_init]
providers = provider_sect

# List of providers to load
[provider_sect]
oqsprovider = oqsprovider_section
default = default_sect

[oqsprovider_section]
activate = 1
module = <oqs-provider-install-dir>/oqs-provider/_build/lib/oqsprovider.so
[default_sect]
activate = 1
[legacy_sect]
activate = 1
```

Notice that you have to point to the `oqsprovider.so` file location, in this case in the `oqs-provider` build directory.

Check that the providers habe been corretly loaded with

```bash
<oqs-provider-install-dir>/.local/bin/openssl list -providers -verbose
```

## CycloneDDS

The dinamical loading of external plugins is well documented in Cyclone DDS. See *External Plugin Development* [here](https://cyclonedds.io/docs/cyclonedds/0.8.2/security.html#external-plugin-developmentl).

### Building Cyclone DDS

```bash
git clone https://github.com/eclipse-cyclonedds/cyclonedds.git
cd cyclonedds
mkdir build
cd build
```

and then build it and install it in the `<path_to_cyclonedds>` directory

```bash
sudo mkdir <path_to_cyclonedds>
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=ON -DBUILD_TESTING=ON -DCMAKE_INSTALL_PREFIX=<path_to_cyclonedds> ..
sudo cmake --build . --target install
```

## Building the external plugin pqsec-dds for CycloneDDS

We can build the plugin with the following commands

```bash
cd src/
mkdir build
cd build
cmake -DCYCLONEDDS_PATH=<path_to_cyclonedds> -DLIBOQS_PATH=<path_to_liboqs> -DOPENSSL_PATH=<path_to_openssl> ..
cmake --build .
```

### Setting the configuration for the custom authentication plugin

The configuration file can be found at `config/cyclonedds/custom_auth_plugin.xml` (note, see [Configuration guide](https://cyclonedds.io/docs/cyclonedds/latest/config/index.html#configuration-guide) for more information about configuration files). Go to the `cyclonedds/build` and export the `CYCLONEDDS_URI` environment variable to point to this file

```bash
export CYCLONEDDS_URI=<path_to_workdir>/config/cyclonedds/custom_auth_plugin.xml
```

This configuration file contains the paths to the certificates and keys used for the authentication process. You can generate these certificates by executing the script `generate_certs.sh` in the `certs` directory.

Then link the custom plugin dynamic libraries to the `LD_LIBRARY_PATH` environment variable

```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:<path_to_workdir>/src/build/lib
```

You can have a quick test running the test application with

```bash
./bin/HelloworldSubscriber
```

and

```bash
./bin/HelloworldPublisher
```

You should see the debug messages from the custom plugin.