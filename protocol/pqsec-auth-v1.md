# PQSec DDS authentication protocol 1.1

## Status

This is an experimental custom Authentication SPI protocol built on the DDS
Security 1.2 authentication state machine and token types.  It is not the
built-in `DDS:Auth:PKI-DH:1.0` protocol.  Its token class identifier is:

```
pqsec-dds.auth:1.1
```

The `+AuthReq`, `+Req`, `+Reply`, and `+Final` suffixes identify the four token
formats.  Peers must implement exactly the same version: a 1.1 peer rejects
1.0 tokens and the reverse.  DDS Security does not standardize plugin
instantiation, so each DDS implementation needs its own adapter even when the
on-wire protocol is shared.

This project-based identifier is provisional.  Before a stable release it
should be replaced by a reverse-domain prefix owned by the project, as required
by DDS Security for custom token identifiers.

## Changes from 1.0

- Both signatures always cover both credential hashes.
- Nothing a peer echoes back is used as input to a signature or to the key
  derivation.  The Reply no longer echoes the KEM public key and the Final
  carries only the signature.
- The shared secret is derived with HKDF over the KEM output and a hash of the
  final transcript instead of being the raw or hashed KEM output.
- Identity certificates and the identity CA must both use ML-DSA.
- The algorithm identifiers and the string encoding are fixed below.

## Encoding

All hashed and signed data is the XCDR1 big-endian serialization of a
`BinaryPropertySeq`: a 32-bit element count followed, for each element, by the
property name as a CDR string and the value as a CDR octet sequence.  The
`propagate` flag is not serialized.  This is the encoding used by PKI-DH.

String-valued binary properties (`c.dsign_algo`, `c.kagree_algo`,
`pqsec-dds.protocol`, `pqsec-dds.role`) hold the ASCII characters followed by
exactly one NUL byte.  A receiver rejects any other encoding, including an
embedded NUL.

## Algorithms

The identifiers below are defined by this document.  They happen to be the
names OpenSSL uses, but a provider mapping a name to something else does not
change their meaning.

Signatures, for both the identity certificate and the identity CA:

| Identifier  | Algorithm                               |
|-------------|-----------------------------------------|
| `ML-DSA-44` | FIPS 204 ML-DSA-44, pure, empty context |
| `ML-DSA-65` | FIPS 204 ML-DSA-65, pure, empty context |
| `ML-DSA-87` | FIPS 204 ML-DSA-87, pure, empty context |

Key establishment:

| Identifier          | Algorithm                          | Public key | Ciphertext |
|---------------------|------------------------------------|-----------:|-----------:|
| `ML-KEM-512`        | FIPS 203 ML-KEM-512                |        800 |        768 |
| `ML-KEM-768`        | FIPS 203 ML-KEM-768                |       1184 |       1088 |
| `ML-KEM-1024`       | FIPS 203 ML-KEM-1024               |       1568 |       1568 |
| `X25519MLKEM768`    | TLS hybrid group, ML-KEM-768 first |       1216 |       1120 |
| `SecP256r1MLKEM768` | TLS hybrid group, P-256 first      |       1249 |       1153 |

Sizes are in bytes.  The hybrid encodings are those of the TLS groups of the
same name: the two component values concatenated, and the KEM shared secret is
the concatenation of the two component secrets.

`frodo640shake`, `bikel1`, and `hqc128` are reserved for experiments with
oqs-provider.  Their encodings are whatever the provider produces, so they are
only meaningful between peers using the same provider build.

There is no algorithm negotiation.  The initiator states the configured KEM
and the replier fails closed unless its own configuration is identical.  There
is no downgrade to PKI-DH.

## Credentials

The Request and Reply carry the DDS Security credential fields `c.id`,
`c.perm`, `c.pdata`, `c.dsign_algo`, and `c.kagree_algo` with their usual
meanings.  The receiver validates the certificate in `c.id` against its
configured identity CA, checks that `c.dsign_algo` names the certificate's
ML-DSA parameter set, that the certificate subject derives the adjusted
participant GUID, and that `c.pdata` contains that same GUID.

The credential hash of a peer is SHA-256 over the serialization of:

```
pqsec-dds.protocol = "pqsec-dds.auth:1.1"
pqsec-dds.role     = "credential-hash"
c.id, c.perm, c.pdata, c.dsign_algo, c.kagree_algo
```

`hash_c1` is the initiator's credential hash and `hash_c2` the replier's.

## Messages

The initiator generates one ephemeral KEM key pair and sends:

```
Request = c.id, c.perm, c.pdata, c.dsign_algo, c.kagree_algo,
          pqsec-dds.kem_public, challenge1
```

The replier validates the request, encapsulates once to `kem_public`, and
sends:

```
Reply = c.id, c.perm, c.pdata, c.dsign_algo, c.kagree_algo,
        pqsec-dds.kem_ciphertext, challenge1, challenge2, signature
```

After validating the Reply and decapsulating, the initiator sends:

```
Final = signature
```

Challenges are independent 256-bit random values.  If an AuthRequest was
exchanged, the challenge of the corresponding side must equal its
`future_challenge`.  Receivers ignore properties they do not use.  A sender may
add `hash_c1` and `hash_c2`; if present they must equal the locally computed
values.

## Signed transcripts

Each node builds both transcripts from its own state: the key pair it
generated or the public key it received in the Request, the ciphertext it
produced or received in the Reply, the challenges it sent or received, and
the credential hashes it computed.  It never takes a field from the peer's
echo of it.

The Reply signature, made with the replier's identity key, covers:

```
pqsec-dds.protocol = "pqsec-dds.auth:1.1"
pqsec-dds.role     = "reply"
hash_c2, challenge2, pqsec-dds.kem_ciphertext,
challenge1, pqsec-dds.kem_public, hash_c1
```

The Final signature, made with the initiator's identity key, covers:

```
pqsec-dds.protocol = "pqsec-dds.auth:1.1"
pqsec-dds.role     = "final"
hash_c1, challenge1, pqsec-dds.kem_public,
challenge2, pqsec-dds.kem_ciphertext, hash_c2
```

## Shared secret

Both sides derive the value returned in `SharedSecretHandle`:

```
th            = SHA-256(serialized Final transcript)
shared_secret = HKDF-SHA-256(IKM  = KEM shared secret,
                             salt = none,
                             info = "pqsec-dds.auth:1.1 shared-secret" || th,
                             L    = 32)
```

HKDF is RFC 5869 Extract followed by Expand; an absent salt is the same as 32
zero bytes.  The info string is ASCII without a terminating NUL.  The IKM is
the complete KEM output; for the hybrids that is both component secrets.  The
raw KEM secret is erased once the derivation is done.

The handle also returns `challenge1` and `challenge2`, and the built-in
Cryptographic plugin of each DDS implementation derives its keys from these
three values as it does for PKI-DH.

## Replier state

A Request whose `hash_c1`, `challenge1`, and `kem_public` equal those of the
replier's pending attempt is a retransmission, and the replier answers with
the same ciphertext.  Any other Request starts a new attempt with a fresh
encapsulation.  A completed handshake is never changed by a later Request.

## Security properties and limits

The two signatures bind both identities, both challenges, the selected
algorithms, and all KEM material, and the derived secret is bound to the same
transcript.  This gives mutual authentication and implicit key
authentication.  It does not give explicit key confirmation: neither message
proves that its sender holds the shared secret.  Possession is first shown
when the Cryptographic plugin exchanges its encrypted tokens.
Direction-specific MACs could be added in a later version.

Known limits of this version:

- There is no algorithm negotiation.
- Requests are unauthenticated, so a forged Request can make the replier
  restart a pending attempt.  The same holds for PKI-DH.
- Permissions and governance documents are still signed by the Access Control
  plugin with classical algorithms.
- Handshake messages carrying ML-DSA certificates and signatures are several
  kilobytes long and have not been tested under packet loss and fragmentation.

## Cross-implementation requirement

An OpenDDS and a CycloneDDS adapter interoperate only if both implement the
same class identifier, property names, serialization, transcript ordering,
algorithm identifiers, challenge rules, and derivation above.  The vectors in
`tests/vectors/pqsec-auth-1.1.txt` pin these down byte for byte, and both
adapters test against them.
