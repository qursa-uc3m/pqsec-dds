# PQSec DDS authentication protocol 1.0

## Status

This is an experimental custom Authentication SPI protocol built on the DDS
Security 1.2 authentication state machine and token types.  It is not the
built-in `DDS:Auth:PKI-DH:1.0` protocol.  Its token class identifier is:

```
pqsec-dds.auth:1.0
```

This project-based identifier is provisional.  Before a stable release it
should be replaced by a reverse-domain prefix owned by the project, as required
by DDS Security for custom token identifiers.

The `+AuthReq`, `+Req`, `+Reply`, and `+Final` suffixes identify the four token
formats.  Both peers must implement this document.  DDS Security does not
standardize plugin instantiation, so each DDS implementation needs its own
adapter even when the on-wire protocol is shared.

## Algorithms

- Identity certificates and handshake signatures use pure ML-DSA-44,
  ML-DSA-65, or ML-DSA-87.
- Key establishment uses `X25519MLKEM768` by default.  This is OpenSSL 3.6's
  native TLS-style X25519 plus ML-KEM-768 hybrid KEM.  Pure ML-KEM-512,
  ML-KEM-768, and ML-KEM-1024 are also defined.
- Credential hashes use SHA-256 over XCDR1 big-endian serialization.
- Challenges are independent 256-bit random nonces.

There is no algorithm negotiation in version 1.0.  The initiator identifies
the configured KEM and the replier fails closed unless its configuration is
identical.  There is no downgrade to PKI-DH.

## Credentials and names

The request and reply carry the DDS Security credential fields `c.id`,
`c.perm`, `c.pdata`, `c.dsign_algo`, and `c.kagree_algo` with their usual
meanings.  The KEM fields are project-specific and therefore use the
reverse-domain prefix required for custom DDS Security properties:

```
pqsec-dds.kem_public
pqsec-dds.kem_ciphertext
```

The credential hash includes a protocol and role domain separator followed by
the five credential fields above in that order.  Each received certificate is
validated against the configured identity CA.  Its subject name must derive
the adjusted participant GUID, and `c.pdata` must contain that same GUID.

## Messages

The initiator generates one ephemeral KEM key pair and sends:

```
Request = credentials_1, kem_public, challenge1
```

The replier validates the request credentials, encapsulates exactly once to
`kem_public`, and sends:

```
Reply = credentials_2, kem_ciphertext, challenge1, challenge2,
        ML-DSA-Sign_2(reply_transcript)
```

The signed reply transcript is the XCDR1 big-endian serialization of:

```
protocol, role="reply", hash(credentials_2), challenge2, kem_ciphertext,
challenge1, kem_public, hash(credentials_1)
```

After validating the reply and decapsulating, the initiator sends:

```
Final = ML-DSA-Sign_1(final_transcript)
```

The signed final transcript is the XCDR1 big-endian serialization of:

```
protocol, role="final", hash(credentials_1), challenge1, kem_public,
challenge2, kem_ciphertext, hash(credentials_2)
```

This preserves the three-message mutual-authentication shape of the built-in
PKI-DH protocol while adapting the asymmetric DH exchange to a one-way KEM
encapsulation.  The signatures bind both identities, both challenges, the
selected algorithms, and all KEM material.

## DDS Security output

The successful Authentication SPI returns the KEM provider's shared secret and
both challenges in `SharedSecretHandle`.  OpenDDS's built-in Cryptographic SPI
then performs its normal HKDF-based derivation for volatile participant keys.
For the hybrid algorithm, combination of the X25519 and ML-KEM-768 components
is performed by OpenSSL's provider before the secret reaches the plugin.

## Cross-implementation requirement

An OpenDDS and a CycloneDDS adapter can interoperate only if both implement the
same class identifier, property names, serialization, transcript ordering,
algorithm identifiers, and challenge rules above.  Sharing cryptographic code
is optional; sharing this protocol definition and byte-for-byte test vectors is
not.
