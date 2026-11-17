#!/usr/bin/env python3
"""Print the PKI-DH handshake sizes behind pkidh-mlkem-sizes.md.

    sizes.py <openssl 3.5 or later> <permissions.xml>

Certificates and signed permissions are made with the given OpenSSL. FN-DSA
and the RFC 10073 composites are not in OpenSSL; their certificates are
modelled from the measured ML-DSA-65 certificate. Token sizes follow the XCDR1
layout of ParticipantStatelessMessage with the properties the adapters in this
repository send (no echoed dh1, dh2 or hashes).
"""
import os
import subprocess
import sys
import tempfile

OPENSSL, PERMISSIONS = sys.argv[1:3]

# name, OpenSSL key type (None: modelled), public key and signature bytes
SIGNATURES = [
    ("ECDSA-P256", "EC", 65, 72),
    ("ML-DSA-44", "ML-DSA-44", 1312, 2420),
    ("ML-DSA-65", "ML-DSA-65", 1952, 3309),
    ("ML-DSA-87", "ML-DSA-87", 2592, 4627),
    ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", 32, 7856),
    ("SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f", 32, 17088),
    ("FN-DSA-512", None, 897, 666),
    ("MLDSA65-ECDSA-P256", None, 1952 + 65, 3309 + 72),
]
KEM, DH1, DH2 = "X25519MLKEM768", 1216, 1120
PDATA = 356        # c.pdata of a CycloneDDS participant, measured
FRAGMENT = 1344    # CycloneDDS default FragmentSize
LOSS = 0.01        # fragment loss rate for the last column


def openssl(*args):
    subprocess.run([OPENSSL, *args], check=True, capture_output=True)


def keygen(kind, path):
    curve = ["-pkeyopt", "ec_paramgen_curve:P-256"] if kind == "EC" else []
    openssl("genpkey", "-algorithm", kind, *curve, "-out", path)


def measure(kind, d):
    keygen(kind, f"{d}/ca.key")
    openssl("req", "-new", "-x509", "-key", f"{d}/ca.key", "-subj", "/C=ES/O=PQSec/CN=PQSec CA",
            "-out", f"{d}/ca.pem")
    keygen(kind, f"{d}/id.key")
    openssl("req", "-new", "-key", f"{d}/id.key", "-subj", "/C=ES/O=PQSec/CN=alice", "-out", f"{d}/id.csr")
    openssl("x509", "-req", "-in", f"{d}/id.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key",
            "-CAcreateserial", "-out", f"{d}/id.pem")
    openssl("x509", "-in", f"{d}/id.pem", "-outform", "DER", "-out", f"{d}/id.der")
    # openssl smime (PKCS#7) cannot sign with ML-DSA or SLH-DSA; openssl cms can
    md = "sha256" if kind == "EC" else "sha512"
    for name, nocerts in (("perm", []), ("perm-nocerts", ["-nocerts"])):
        openssl("cms", "-sign", "-md", md, "-text", "-in", PERMISSIONS, "-signer", f"{d}/ca.pem",
                "-inkey", f"{d}/ca.key", "-out", f"{d}/{name}.p7s", *nocerts)
    return [os.path.getsize(f"{d}/{f}") for f in ("id.pem", "id.der", "perm.p7s", "perm-nocerts.p7s")]


def base64(n):
    return 4 * ((n + 2) // 3)


def pem(der):
    return base64(der) + base64(der) // 64 + 1 + 54


def model(reference, pk, sig):
    """Scale the ML-DSA-65 certificate and signed permissions to other sizes."""
    pem65, der65, perm65, nocerts65 = reference
    der = der65 - 1952 - 3309 + pk + sig
    nocerts = nocerts65 - base64(3309) + base64(sig)
    return [pem(der), der, nocerts + perm65 - nocerts65 - pem65 + pem(der), nocerts]


def align(n):
    return (n + 3) & ~3


def string(text):
    return align(4 + len(text) + 1)


def message(class_id, properties):
    n = 4 + 2 * 24 + 3 * 16 + string("dds.sec.auth") + 4 + string(class_id) + 4 + 4
    return n + sum(string(name) + align(4 + length) for name, length in properties)


def handshake(name, sig, cert, perm):
    common = [("c.id", cert), ("c.perm", perm), ("c.pdata", PDATA), ("c.dsign_algo", len(name)),
              ("c.kagree_algo", len(KEM))]
    return (message("DDS:Auth:PKI-DH:1.0+Req", common + [("hash_c1", 32), ("dh1", DH1), ("challenge1", 32)]),
            message("DDS:Auth:PKI-DH:1.0+Reply", common + [("hash_c2", 32), ("dh2", DH2), ("challenge1", 32),
                                                         ("challenge2", 32), ("signature", sig)]),
            message("DDS:Auth:PKI-DH:1.0+Final", [("challenge1", 32), ("challenge2", 32), ("signature", sig)]))


def main():
    rows = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name, kind, pk, sig in SIGNATURES:
            if kind:
                os.mkdir(f"{tmp}/{name}")
                rows[name] = measure(kind, f"{tmp}/{name}")
    for name, kind, pk, sig in SIGNATURES:
        if not kind:
            rows[name] = model(rows["ML-DSA-65"], pk, sig)

    print(f"Key establishment {KEM}; fragments of {FRAGMENT} bytes; * modelled\n")
    print("| Signature | c.id | c.perm | Request | Reply | Final | Total | Fragments | No resend at 1% loss |")
    print("|---|---|---|---|---|---|---|---|---|")
    for name, kind, pk, sig in SIGNATURES:
        cert_pem, cert_der, perm, nocerts = rows[name]
        for label, cert, permissions in (("", cert_pem, perm), (", no CA cert in c.perm", cert_pem, nocerts)):
            sizes = handshake(name, sig, cert, permissions)
            frags = [-(-s // FRAGMENT) for s in sizes]
            print(f"| {name}{'*' if not kind else ''}{label} | {cert} | {permissions} | "
                  + " | ".join(str(s) for s in sizes) + f" | {sum(sizes)} | "
                  + "+".join(str(f) for f in frags) + f" | {(1 - LOSS) ** sum(frags):.2f} |")


main()
