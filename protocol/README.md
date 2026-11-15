# Protocol documents

- [ML-KEM and ML-DSA in DDS:Auth:PKI-DH](pkidh-mlkem.md) is the proposed
  change to DDS Security 1.2. The adapters are moving to it.
- [PQSec DDS authentication protocol 1.1](pqsec-auth-v1.md) is the custom
  protocol the adapters implement today. It is removed once both adapters
  speak the PKI-DH profile.

Both adapters test against the vectors in [tests/vectors](../tests/vectors).
