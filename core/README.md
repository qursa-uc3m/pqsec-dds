# DDS-neutral core

This directory is reserved for the OpenSSL-based, DDS-neutral implementation
of KEM operations, signatures, transcript construction, and secret handling.

No code has been extracted here yet.  Both adapters implement protocol 1.1
with their own code and are kept in agreement by the shared vectors in
`tests/vectors`.  The future
core should expose a small C ABI so both the CycloneDDS C adapter and the
OpenDDS C++ adapter can use it.
