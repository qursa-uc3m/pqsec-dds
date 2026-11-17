# Interoperability tests

A CycloneDDS participant and an OpenDDS participant, both with the PQSec
authentication plugin, authenticate each other and exchange ten samples
over a reliable topic with encrypted data, metadata and discovery. Access
control and cryptography are each implementation's built-in plugins.

`run.sh` runs four cases: each side publishing, and each side as handshake
initiator. The initiator is decided by the adjusted GUIDs, which come from
the subject names, so swapping alice and bob swaps the initiator.

## Running

```sh
./setup.sh <openssl> <security dir>
cmake -S cyclonedds -B cyclonedds/build -DCMAKE_PREFIX_PATH=<CycloneDDS install>
cmake --build cyclonedds/build
cmake -S opendds -B opendds/build      # with OpenDDS's setenv.sh sourced
cmake --build opendds/build
./run.sh <security dir> <libdds_pqsec.so> <libOpenDDS_PQSec.so> <log dir>
```

OpenSSL, CycloneDDS, OpenDDS and both plugins must be on the library path.
The identities use ML-DSA-65 and the handshake X25519MLKEM768. The
Permissions CA is ECDSA: both access control plugins check signed
documents with OpenSSL's PKCS#7 functions, which cannot verify ML-DSA.

## Results

All four cases pass with CycloneDDS 11.1.0 and OpenDDS 3.35.0-dev with
external security plugin support and the fixes for 1 and 2 below, using
the OpenDDS plugin as it was before "Announce the OpenDDS adapter's
algorithms through DDS Security 1.2".

From that commit on, the OpenDDS plugin announces its algorithms through
the DDS Security 1.2 negotiation, with bits from the vendor range. 1.2
interprets those bits per vendor, so OpenDDS refuses the CycloneDDS
participant before the handshake starts, as it should. Cross-vendor runs
with negotiation need the bits assigned by the specification (see
`protocol/pkidh-mlkem.md`), and a CycloneDDS that implements the 1.2
negotiation.

Getting there found four problems. None comes from PQSec: each one
reproduces with the built-in authentication plugins and ECDSA identities.
The post-quantum handshake makes the first one certain, because its
messages are always fragmented.

1. **OpenDDS reassembles fragments with trailing submessages.** OpenDDS
   builds each received sample from the rest of the datagram instead of
   its own submessage. When a datagram holds several `DATA_FRAG` and
   `HEARTBEAT_FRAG` submessages, as CycloneDDS sends them, the
   reassembled sample is longer than `sampleSize` and does not
   deserialize. Handshake messages from CycloneDDS never arrive. The fix
   is proposed in OpenDDS pull request
   [5342](https://github.com/OpenDDS/OpenDDS/pull/5342). Without it, run
   with `PQSEC_MAX_MESSAGE=1400B`, which makes CycloneDDS send one
   fragment per datagram.
2. **OpenDDS leaves the padding out of protected payloads.** The
   encapsulation options of a serialized payload declare its padding, but
   OpenDDS encrypts the payload without those bytes. CycloneDDS subtracts
   the declared padding from the decrypted length and fails to deserialize
   every sample whose size is not a multiple of four. This hits every
   protected payload from OpenDDS to CycloneDDS (tested with
   `data_protection_kind` ENCRYPT). OpenDDS fixed it in pull request
   [5306](https://github.com/OpenDDS/OpenDDS/pull/5306), which writes the
   declared padding; it is not in a release yet.
3. **CycloneDDS rejects OpenDDS's type information.** Unless the IDL is
   compiled with `-Gxtypes-complete`, OpenDDS announces `TK_NONE` as the
   complete type identifier in `TYPE_INFORMATION`. CycloneDDS requires a
   complete hash and drops the publication or subscription. The OpenDDS
   build here passes the option; `UseXTypes=no` in the OpenDDS
   configuration also works.
4. **Unicast discovery depends on start order.** A CycloneDDS participant
   that starts first announces itself to OpenDDS's well-known SPDP port
   before OpenDDS listens there. Once it learns OpenDDS's locators, it
   sends announcements only to OpenDDS's metatraffic port, where OpenDDS
   does not accept them, and OpenDDS never discovers it. `run.sh` starts
   OpenDDS first.

The two access control plugins accept governance and permissions signed
without the CA certificate, which `setup.sh` uses; see
`protocol/pkidh-mlkem-sizes.md` for why that matters.
