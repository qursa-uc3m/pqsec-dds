# Protocol vectors

`pkidh-mlkem.txt` holds fixed inputs and the expected credential hashes,
serialized Reply and Final signature transcripts, and `SharedSecret` of
[ML-KEM in DDS:Auth:PKI-DH](../../protocol/pkidh-mlkem.md), for each key
establishment algorithm of the profile: `ML-KEM-768`, `ML-KEM-1024` and
`X25519MLKEM768`. Values that depend on the algorithm carry its name as a
prefix.

The file is produced by `generate.py`, a small independent implementation
written only against the protocol document. Its inputs are synthetic, since
PKI-DH hashes and signs them as opaque bytes. Regenerate it with:

```sh
./generate.py > pkidh-mlkem.txt
```

The hashes and transcripts were also checked against the serializer of
OpenDDS's built-in PKI-DH plugin (`SSL::hash_serialized`).

Signatures and KEM operations are randomized and are not part of the vectors.
