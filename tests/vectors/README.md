# Protocol vectors

`pqsec-auth-1.1.txt` holds fixed inputs and the expected credential hashes,
serialized Reply and Final transcripts, transcript hash, and shared secret of
[protocol 1.1](../../protocol/pqsec-auth-v1.md).  Both adapters check their
own implementation against it in their test suites.

The file is produced by `generate.py`, a small independent implementation
written only against the protocol document.  Its inputs are synthetic, since
the protocol hashes and signs them as opaque bytes.  Regenerate it with:

```sh
./generate.py > pqsec-auth-1.1.txt
```

Signatures and KEM operations are randomized and are not part of the vectors.
