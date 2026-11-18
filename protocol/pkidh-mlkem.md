# ML-KEM and ML-DSA in DDS:Auth:PKI-DH

## Status

A proposed change to DDS Security 1.2 (formal/25-03-06), written for
DDSSEC13-91. Both adapters in this repository implement it. Nothing in it
changes the PKI-DH tokens, class ids, messages, signed transcripts, or the
Authentication SPI: the new algorithms are rows of Tables 25 and 26.

Section numbers below are those of DDS Security 1.2.

## 8.2 Digital signature algorithms

Add to Table 25:

| CryptoAlgorithmName | Id   | Bit          | Description                                       |
|---------------------|------|--------------|---------------------------------------------------|
| `ML-DSA-65`         | 0x90 | `0x00010000` | FIPS 204 ML-DSA-65, pure signing, empty context   |
| `ML-DSA-87`         | 0x91 | `0x00020000` | FIPS 204 ML-DSA-87, pure signing, empty context   |

The public key is carried in an X.509 certificate as in RFC 9881. The
signature in a `signature` property is the FIPS 204 signature encoding.

`pkidh-mlkem-sizes.md` explains why these two rows and no others: ML-DSA-44,
SLH-DSA, FN-DSA and the composite signatures were measured against them.

## 8.3 Key establishment algorithms

Add to Table 26:

| CryptoAlgorithmName | Id   | Bit          | Description                                       |
|---------------------|------|--------------|---------------------------------------------------|
| `ML-KEM-768`        | 0xA0 | `0x00010000` | FIPS 203 ML-KEM-768                               |
| `ML-KEM-1024`       | 0xA1 | `0x00020000` | FIPS 203 ML-KEM-1024                              |
| `X25519MLKEM768`    | 0xA2 | `0x00040000` | ML-KEM-768 combined with X25519, as the TLS group of the same name |

The ids and bits are in the vendor ranges of 7.3.7 and 7.3.8 and are
provisional. Vendor-range bits are interpreted per RTPS vendor ID, so they
cannot negotiate between two vendors. Interoperable use needs the RTF to
assign values in the specification ranges. The CycloneDDS and OpenDDS
adapters authenticate each other without the 1.2 negotiation; with it,
OpenDDS rightly refuses the CycloneDDS participant before the handshake
(`tests/interoperability`).

ML-KEM-768 and ML-DSA-65 sit at the level of the P-256 rows; ML-KEM-1024 and
ML-DSA-87 at the level of the P-384 rows that 1.2 added for CNSA.

For a KEM the two key establishment properties carry different things:

| Property | ML-KEM-768 / ML-KEM-1024           | X25519MLKEM768                                   |
|----------|------------------------------------|--------------------------------------------------|
| `dh1`    | encapsulation key (1184 / 1568)    | ML-KEM-768 encapsulation key ‖ X25519 public key (1216) |
| `dh2`    | ciphertext (1088 / 1568)           | ML-KEM-768 ciphertext ‖ X25519 public key (1120)  |
| secret   | ML-KEM shared key K (32)           | ML-KEM-768 K ‖ X25519 shared secret (64)          |

Sizes are in bytes. ML-KEM values use the FIPS 203 byte encodings and X25519
values the RFC 7748 encodings. For `X25519MLKEM768` the order is ML-KEM first,
as in the TLS group (draft-ietf-tls-ecdhe-mlkem).

The rule of 10.3.2.5.2 is unchanged: `SharedSecret` is SHA-256 of the secret
in the last row.

## 10.3 DDS:Auth:PKI-DH

`c.dsign_algo` and `c.kagree_algo` may hold the names above. The
`key_establishment_algorithm` property of 10.3.1.4 may name any row of
Table 26, including the new ones.

For a KEM, the following rules apply. They say for KEMs what 1.2 leaves
implicit for Diffie-Hellman.

1. **Roles.** The initiator generates a key pair and sends the encapsulation
   key as `dh1`. The replier checks `dh1` (the FIPS 203 encapsulation key
   check; for `X25519MLKEM768` also the length of the X25519 part), then
   encapsulates to it and sends the ciphertext as `dh2`. The initiator
   decapsulates `dh2` with its own key. For `X25519MLKEM768` an all-zero
   X25519 shared secret is an error.
2. **Local state.** Each side signs and verifies with its own copies of
   `dh1`, `dh2`, `hash_c1` and `hash_c2`: the ones it generated, or the ones it
   received in the message that defines them. An echoed copy in a later
   token, if present, must equal the local one and is never used as input.
   Since echoes carry no information, a Reply should not repeat `hash_c1`
   or `dh1`, and a Final should not repeat `hash_c1`, `hash_c2`, `dh1` or
   `dh2`. With `X25519MLKEM768` they would add 3.7 KB to a handshake.
3. **Ciphertext lifetime.** A ciphertext belongs to one Request. A Request
   with the same `hash_c1`, `challenge1` and `dh1` as the pending attempt is a
   retransmission and gets the same Reply. Any other Request gets a new
   encapsulation.
4. **Decapsulation is silent.** ML-KEM decapsulation of a wrong ciphertext
   returns a different key, not an error. Success of decapsulation proves
   nothing; only the two signatures authenticate the exchange.
5. **Erasure.** The decapsulation key is erased once it has been used, and the
   KEM secret once `SharedSecret` has been computed.

The certificate in `c.id` and the Identity CA certificate may use ML-DSA. The
initiator chooses `c.kagree_algo`; a Reply naming another algorithm is
rejected.

One more rule applies to every key establishment algorithm, not only the
new ones. With `AUTO` (10.3.1.4) the plugin chooses, and the only thing it
knows about the peer's support is the algorithm info from discovery, which
nothing authenticates. A plugin that chooses by it ("ML-KEM if the peer has
it, otherwise ECDH") can be steered by an attacker who rewrites discovery:
two participants that both support ML-KEM settle on an algorithm both still
accept, such as `ECDH+prime256v1-CEUM`. The peer's real algorithm info is
also inside its `c.pdata`, which is hashed and signed. So: once the
handshake has been verified, the algorithm info in the peer's `c.pdata`
must equal what discovery delivered for that peer, or the peer is not
authenticated. The formal model finds the downgrade without this check and
none with it (`formal/README.md`). Plugins that always use one configured
algorithm, as the adapters here and the OpenDDS built-in plugin do, are not
exposed, but they cannot adapt to the peer either.

## 10.4 Governance

`DigitalSignatureKind` and `KeyEstablishmentKind` in the governance XSD
(10.4.1.2.5.9) need the new names as enumeration values, so that
`<allowed_crypto_algorithms>` can allow or forbid them:

```xml
<xs:enumeration value="ML-DSA-65" />
<xs:enumeration value="ML-DSA-87" />

<xs:enumeration value="ML-KEM-768" />
<xs:enumeration value="ML-KEM-1024" />
<xs:enumeration value="X25519MLKEM768" />
```

10.4.1.2 and 10.4.1.5 have the Permissions CA sign the governance and
permissions documents as S/MIME 3.2 SignedData, which is CMS. With an ML-DSA
Permissions CA the signature follows RFC 9882. (OpenSSL's PKCS#7 functions
cannot produce or check it; its CMS functions can.)

Both sections also require the signer certificate inside the signature.
Every participant has the Permissions CA configured and does not need it,
and with ML-DSA-65 it adds 7.5 KB to each Request and Reply. The sentence
"Additionally, the signer certificate shall be included within the
signature" becomes "The signer certificate should not be included within the
signature". The CycloneDDS and OpenDDS plugins already accept documents
without it.

## Questions

Q1 and Q2 were answered with the Tamarin model in `formal/`.

- **Q1.** Is `SharedSecret = SHA-256(secret)` enough, or must the derivation
  also cover the transcript? For `X25519MLKEM768` this matters most: the TLS
  draft warns that the plain concatenation is analysed only with the TLS 1.3
  transcript. *Answer:* the plain rule is enough in the model, for a KEM
  without binding properties and for the hybrid with either component
  broken, because `dh1` and `dh2` are inside both signatures and each side
  uses its own copies (rule 2). The proposal adds no derivation and no
  combiner. This is a symbolic result; it does not exclude computational
  weaknesses of the plain concatenation.
- **Q2.** Is the algorithm choice protected against downgrade? *Answer:*
  not when the initiator's choice depends on discovery. The model finds the
  downgrade through rewritten discovery data; the comparison rule at the end
  of 10.3 above removes it.
- **Q3.** Should the profile add a composite signature, ML-DSA-65 with
  ECDSA-P256 as `MLDSA65-ECDSA-P256-SHA512` of RFC 10073? European
  guidance asks for ML-DSA to be combined with a classical signature, and
  the composite costs 2% more than ML-DSA-65 alone. No OpenSSL release
  implements it yet, so neither adapter could test it today.

## Vectors

`tests/vectors/pkidh-mlkem.txt` fixes the credential hashes, the two signed
transcripts, and `SharedSecret` byte for byte. Both adapters test against
it.
