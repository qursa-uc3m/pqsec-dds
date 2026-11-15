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
assign values in the specification ranges.

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

## Open questions

These are checked by the formal model in `formal/`, not settled here.

- **Q1.** Is `SharedSecret = SHA-256(secret)` enough, or must the derivation
  also cover the transcript? For `X25519MLKEM768` this matters most: the TLS
  draft warns that the plain concatenation is analysed only with the TLS 1.3
  transcript and may not be secure elsewhere. In PKI-DH, `dh1` and `dh2` are
  inside both signatures, but they are not inputs to the derivation. If the
  model confirms the plain rule, the proposal adds no derivation. If it does
  not, the hybrid row changes to a combiner that hashes the X25519 shares
  into the secret, as X-Wing (draft-connolly-cfrg-xwing-kem) does.
- **Q2.** Is the algorithm choice protected against downgrade? The algorithm
  info travels in discovery unauthenticated and again inside `c.pdata`,
  which is hashed and signed. 1.2 does not require comparing the two.

## Vectors

`tests/vectors/pkidh-mlkem.txt` fixes the credential hashes, the two signed
transcripts, and `SharedSecret` byte for byte. Both adapters test against
it.
