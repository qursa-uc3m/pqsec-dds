# DDS-neutral core

This directory is reserved for the OpenSSL-based, DDS-neutral implementation
of KEM operations, signatures, transcript construction, and secret handling.

No code has been extracted here yet.  The existing CycloneDDS implementation
is intentionally unchanged, and the OpenDDS implementation remains inside its
adapter until the shared wire protocol and test vectors are stable.  The future
core should expose a small C ABI so both the CycloneDDS C adapter and the
OpenDDS C++ adapter can use it.
