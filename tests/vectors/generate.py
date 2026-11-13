#!/usr/bin/env python3
# Copyright (C) 2023-2026 Javier Blanco-Romero @fj-blanco (UC3M)
"""Regenerate pqsec-auth-1.1.txt from the protocol document.

This is a third, independent implementation of the hashes, transcripts and
key derivation of protocol 1.1, written only against the document.  The
inputs are synthetic: the protocol hashes and signs them as opaque bytes, so
they do not need to be real certificates or KEM output.

Usage: generate.py > pqsec-auth-1.1.txt
"""

import hashlib
import hmac
import struct

PROTOCOL = b"pqsec-dds.auth:1.1"


def serialize(properties):
    """XCDR1 big-endian serialization of a BinaryPropertySeq."""
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


def string_value(text):
    return text + b"\0"


def domain(role):
    return [(b"pqsec-dds.protocol", string_value(PROTOCOL)),
            (b"pqsec-dds.role", string_value(role))]


def credential_hash(c):
    properties = domain(b"credential-hash") + [
        (b"c.id", c["id"]), (b"c.perm", c["perm"]), (b"c.pdata", c["pdata"]),
        (b"c.dsign_algo", c["dsign_algo"]), (b"c.kagree_algo", c["kagree_algo"])]
    return hashlib.sha256(serialize(properties)).digest()


def hkdf_sha256(ikm, info, length):
    prk = hmac.new(b"\0" * 32, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def filler(label, size):
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:size]


def credentials(name):
    return {
        "id": filler(b"certificate " + name, 700),
        "perm": string_value(b"<permissions>" + name + b"</permissions>"),
        "pdata": filler(b"participant data " + name, 61),
        "dsign_algo": string_value(b"ML-DSA-65"),
        "kagree_algo": string_value(b"X25519MLKEM768"),
    }


def main():
    c1, c2 = credentials(b"initiator"), credentials(b"replier")
    challenge1 = filler(b"challenge1", 32)
    challenge2 = filler(b"challenge2", 32)
    kem_public = filler(b"kem public key", 1216)
    kem_ciphertext = filler(b"kem ciphertext", 1120)
    kem_secret = filler(b"kem secret", 64)

    hash_c1, hash_c2 = credential_hash(c1), credential_hash(c2)
    reply = serialize(domain(b"reply") + [
        (b"hash_c2", hash_c2), (b"challenge2", challenge2),
        (b"pqsec-dds.kem_ciphertext", kem_ciphertext), (b"challenge1", challenge1),
        (b"pqsec-dds.kem_public", kem_public), (b"hash_c1", hash_c1)])
    final = serialize(domain(b"final") + [
        (b"hash_c1", hash_c1), (b"challenge1", challenge1),
        (b"pqsec-dds.kem_public", kem_public), (b"challenge2", challenge2),
        (b"pqsec-dds.kem_ciphertext", kem_ciphertext), (b"hash_c2", hash_c2)])
    th = hashlib.sha256(final).digest()
    shared_secret = hkdf_sha256(kem_secret, PROTOCOL + b" shared-secret" + th, 32)

    print("# PQSec DDS authentication protocol 1.1 vectors, from generate.py.")
    print("# Each line is: name = hex.  String values include their NUL.")
    for prefix, c in (("c1", c1), ("c2", c2)):
        for key in ("id", "perm", "pdata", "dsign_algo", "kagree_algo"):
            print(f"{prefix}.{key} = {c[key].hex()}")
    for name, value in (("challenge1", challenge1), ("challenge2", challenge2),
                        ("kem_public", kem_public), ("kem_ciphertext", kem_ciphertext),
                        ("kem_secret", kem_secret), ("hash_c1", hash_c1),
                        ("hash_c2", hash_c2), ("reply_transcript", reply),
                        ("final_transcript", final), ("transcript_hash", th),
                        ("shared_secret", shared_secret)):
        print(f"{name} = {value.hex()}")


if __name__ == "__main__":
    main()
