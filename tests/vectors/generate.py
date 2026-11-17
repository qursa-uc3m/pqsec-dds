#!/usr/bin/env python3
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
"""Regenerate pkidh-mlkem.txt from protocol/pkidh-mlkem.md.

An independent implementation of the credential hashes, signed transcripts
and SharedSecret of DDS:Auth:PKI-DH (DDS Security 1.2, 10.3.2.5), for each
key establishment algorithm of the profile. The inputs are synthetic: PKI-DH
hashes and signs them as opaque bytes, so they need not be real
certificates or KEM output.

Usage: generate.py > pkidh-mlkem.txt
"""

import hashlib
import struct

# Key establishment algorithm, signature algorithm paired with it, and the
# sizes in bytes of dh1, dh2 and the KEM secret.
PROFILE = (
    (b"ML-KEM-768", b"ML-DSA-65", 1184, 1088, 32),
    (b"ML-KEM-1024", b"ML-DSA-87", 1568, 1568, 32),
    (b"X25519MLKEM768", b"ML-DSA-65", 1216, 1120, 64),
)


def serialize(properties):
    """CDR big-endian serialization of a BinaryPropertySeq."""
    out = bytearray()

    def put_length(length):
        out.extend(b"\0" * (-len(out) % 4))
        out.extend(struct.pack(">I", length))

    put_length(len(properties))
    for name, value in properties:
        put_length(len(name) + 1)
        out.extend(name + b"\0")
        put_length(len(value))
        out.extend(value)
    return bytes(out)


def sha256(data):
    return hashlib.sha256(data).digest()


def filler(label, size):
    out = b""
    counter = 0
    while len(out) < size:
        out += sha256(label + counter.to_bytes(4, "big"))
        counter += 1
    return out[:size]


def credential_hash(c, dsign_algo, kagree_algo):
    return sha256(serialize([
        (b"c.id", c["id"]), (b"c.perm", c["perm"]), (b"c.pdata", c["pdata"]),
        (b"c.dsign_algo", dsign_algo + b"\0"),
        (b"c.kagree_algo", kagree_algo + b"\0")]))


def main():
    c1 = {"id": filler(b"certificate initiator", 700),
          "perm": b"<permissions>initiator</permissions>\0",
          "pdata": filler(b"participant data initiator", 61)}
    c2 = {"id": filler(b"certificate replier", 700),
          "perm": b"<permissions>replier</permissions>\0",
          "pdata": filler(b"participant data replier", 61)}
    challenge1 = filler(b"challenge1", 32)
    challenge2 = filler(b"challenge2", 32)

    print("# DDS:Auth:PKI-DH vectors for protocol/pkidh-mlkem.md, from generate.py.")
    print("# Each line is: name = hex. String values include their NUL.")
    print("# Values that depend on the key establishment algorithm are")
    print("# prefixed with its name.")
    for prefix, c in (("c1", c1), ("c2", c2)):
        for key in ("id", "perm", "pdata"):
            print(f"{prefix}.{key} = {c[key].hex()}")
    print(f"challenge1 = {challenge1.hex()}")
    print(f"challenge2 = {challenge2.hex()}")

    for kagree_algo, dsign_algo, dh1_size, dh2_size, secret_size in PROFILE:
        dh1 = filler(b"dh1 " + kagree_algo, dh1_size)
        dh2 = filler(b"dh2 " + kagree_algo, dh2_size)
        secret = filler(b"secret " + kagree_algo, secret_size)
        hash_c1 = credential_hash(c1, dsign_algo, kagree_algo)
        hash_c2 = credential_hash(c2, dsign_algo, kagree_algo)
        reply = serialize([
            (b"hash_c2", hash_c2), (b"challenge2", challenge2), (b"dh2", dh2),
            (b"challenge1", challenge1), (b"dh1", dh1), (b"hash_c1", hash_c1)])
        final = serialize([
            (b"hash_c1", hash_c1), (b"challenge1", challenge1), (b"dh1", dh1),
            (b"challenge2", challenge2), (b"dh2", dh2), (b"hash_c2", hash_c2)])

        name = kagree_algo.decode()
        for key, value in (("dsign_algo", dsign_algo + b"\0"),
                           ("kagree_algo", kagree_algo + b"\0"),
                           ("dh1", dh1), ("dh2", dh2), ("secret", secret),
                           ("hash_c1", hash_c1), ("hash_c2", hash_c2),
                           ("reply_transcript", reply),
                           ("final_transcript", final),
                           ("shared_secret", sha256(secret))):
            print(f"{name}.{key} = {value.hex()}")


if __name__ == "__main__":
    main()
