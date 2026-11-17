# Handshake sizes and the choice of signature

Why the profile in `pkidh-mlkem.md` adds ML-DSA-65 and ML-DSA-87 and no
other signature, and what makes a PKI-DH handshake large. The numbers come
from `sizes.py`, run with OpenSSL 3.6.5.

## What a handshake carries

Request and Reply each carry the participant's certificate (`c.id`, PEM)
and its signed permissions document (`c.perm`, S/MIME). Reply and Final
each carry one signature. `dh1` and `dh2` carry the KEM encapsulation key
and ciphertext. There is no certificate chain on the wire: the Identity CA
and the Permissions CA are configured at every participant.

Three properties of DDS make size matter more than in TLS:

- Handshakes go over `ParticipantStatelessMessage`, which is best effort. A
  fragmented message is lost when any of its fragments is lost, and the
  plugin then resends the whole message after its timeout.
- Every pair of participants runs its own handshake, so a system of N
  participants runs N(N-1)/2 of them when it starts.
- RTPS fragments anything above the writer's fragment size (1344 bytes by
  default in CycloneDDS), so a large handshake also depends on fragment
  reassembly working across vendors. It did not, see
  `tests/interoperability`.

## Sizes

Key establishment X25519MLKEM768 in every row. Identity CA, identity and
Permissions CA use the same algorithm. Sizes in bytes; fragments of 1344
bytes; the last column is the chance that the three messages get through
without a resend when 1% of fragments are lost. Rows marked * are modelled,
because OpenSSL has neither FN-DSA nor the composites.

| Signature | c.id | c.perm | Request | Reply | Final | Total | Fragments | No resend at 1% loss |
|---|---|---|---|---|---|---|---|---|
| ECDSA-P256 | 627 | 2956 | 5552 | 5604 | 360 | 11516 | 5+5+1 | 0.90 |
| ECDSA-P256, no CA cert in c.perm | 627 | 2350 | 4948 | 5000 | 360 | 10308 | 4+4+1 | 0.91 |
| ML-DSA-44 | 5494 | 11052 | 18516 | 20916 | 2708 | 42140 | 14+16+3 | 0.72 |
| ML-DSA-44, no CA cert in c.perm | 5494 | 5580 | 13044 | 15444 | 2708 | 31196 | 10+12+3 | 0.78 |
| ML-DSA-65 | 7566 | 14326 | 23864 | 27156 | 3600 | 54620 | 18+21+3 | 0.66 |
| ML-DSA-65, no CA cert in c.perm | 7566 | 6786 | 16324 | 19616 | 3600 | 39540 | 13+15+3 | 0.73 |
| ML-DSA-87 | 10219 | 18763 | 30952 | 35560 | 4916 | 71428 | 24+27+4 | 0.58 |
| ML-DSA-87, no CA cert in c.perm | 10219 | 8570 | 20760 | 25368 | 4916 | 51044 | 16+19+4 | 0.68 |
| SLH-DSA-SHA2-128s | 11117 | 24036 | 37132 | 44968 | 8144 | 90244 | 28+34+7 | 0.50 |
| SLH-DSA-SHA2-128s, no CA cert in c.perm | 11117 | 12941 | 26040 | 33876 | 8144 | 68060 | 20+26+7 | 0.59 |
| SLH-DSA-SHA2-128f | 23621 | 49041 | 74644 | 91712 | 17376 | 183732 | 56+69+13 | 0.25 |
| SLH-DSA-SHA2-128f, no CA cert in c.perm | 23621 | 25446 | 51048 | 68116 | 17376 | 136540 | 38+51+13 | 0.36 |
| FN-DSA-512* | 2557 | 5793 | 10324 | 10972 | 956 | 22252 | 8+9+1 | 0.83 |
| FN-DSA-512*, no CA cert in c.perm | 2557 | 3262 | 7792 | 8440 | 956 | 17188 | 6+7+1 | 0.87 |
| MLDSA65-ECDSA-P256* | 7753 | 14609 | 24344 | 27708 | 3672 | 55724 | 19+21+3 | 0.65 |
| MLDSA65-ECDSA-P256*, no CA cert in c.perm | 7753 | 6882 | 16616 | 19980 | 3672 | 40268 | 13+15+3 | 0.73 |

Signing and verifying cost little next to this. Each side signs once and
verifies three times (the peer's certificate, its permissions, its
handshake signature). On the machine used here (x86_64, 2 cores):

| Signature | Sign | Verify | Per side and handshake |
|---|---|---|---|
| ECDSA-P256 | 0.02 ms | 0.07 ms | 0.2 ms |
| ML-DSA-44 | 0.49 ms | 0.09 ms | 0.8 ms |
| ML-DSA-65 | 0.77 ms | 0.15 ms | 1.2 ms |
| ML-DSA-87 | 0.96 ms | 0.24 ms | 1.7 ms |
| SLH-DSA-SHA2-128s | 272 ms | 0.26 ms | 273 ms |
| SLH-DSA-SHA2-128f | 13 ms | 0.84 ms | 16 ms |

## Reading the table

**The largest item is not the algorithm.** DDS Security 1.2 (10.4.1.5)
requires the signer's certificate inside the S/MIME signature of the
permissions document. The receiver has the Permissions CA configured and
never needs it, but every Request and Reply carries it. With an ML-DSA-65
Permissions CA that is 7.5 KB per message, 28% of the handshake. Signing
with `openssl cms -nocerts` removes it. The CycloneDDS and OpenDDS access
control plugins both accept such documents, in both directions of the
interoperability runs, so the proposal relaxes the requirement.

**Smaller standard signatures save little.** ML-DSA-44 makes the handshake
21% smaller than ML-DSA-65 and still needs 25 fragments. European guidance
(BSI TR-02102-1, the ECCG agreed mechanisms) asks for ML-DSA-65 or
ML-DSA-87, and CNSA 2.0 for ML-DSA-87 only. A row that the main regulated
users cannot select would split deployments without making the handshake
small, so the profile leaves it out.

**SLH-DSA does not fit.** Its public keys are tiny, but the CA signature
inside the certificate and the handshake signature are not, and signing
costs 13 to 272 ms per handshake.

**FN-DSA-512 is the only real reduction**: 17 KB against 40 KB, and 14
fragments against 31. FIPS 206 is still a draft, OpenSSL does not implement
it, its signing is hard to make constant time, and CNSA 2.0 will not add
it. It is the candidate for a later row once FIPS 206 is final and OpenSSL
ships it. Adding it then is a name and a bit, as for the rows here.

**A composite signature costs 2%.** MLDSA65-ECDSA-P256-SHA512 (RFC 10073)
adds 65 bytes of key and 72 of signature per certificate and per signature.
ANSSI, BSI and the ECCG recommend combining ML-DSA with a classical
signature. OpenSSL 3.6 and 4.0 do not implement the composites. See Q3 in
`pkidh-mlkem.md`.

**The KEM is urgent, the signature is not.** Traffic recorded today can be
decrypted once a quantum computer exists, so key establishment needs ML-KEM
now. A signature only has to resist forgery while it is being checked:
breaking ECDSA later does not reveal recorded traffic. PKI-DH negotiates
`c.dsign_algo` and `c.kagree_algo` independently, so ECDSA-P256 identities
with X25519MLKEM768 are already a valid combination: 10.3 KB and 9
fragments, against 40 KB and 31 for ML-DSA-65. That is a sensible first
step for deployments whose PKI is not ready for ML-DSA. (The adapters here
accept ML-DSA identities only.)

**DER instead of PEM in `c.id`** would save 4 KB per ML-DSA-65 handshake
(10%), but changes an existing wire format. Not proposed.

**Echoes are expensive with a KEM.** DDS Security 1.2 lets Reply repeat
`hash_c1` and `dh1`, and Final repeat `hash_c1`, `hash_c2`, `dh1` and
`dh2`. With X25519MLKEM768 that adds 3.7 KB, and Final grows from 3 to 5
fragments. Rule 2 of `pkidh-mlkem.md` already forbids using an echo as
input, so the proposal asks implementations to omit them. The adapters here
do; the OpenDDS built-in plugin sends them.

**Permissions signed with ML-DSA need CMS.** OpenSSL's PKCS#7 functions
cannot sign or verify ML-DSA or SLH-DSA S/MIME documents; its CMS functions
can (RFC 9882 for ML-DSA). The CycloneDDS and OpenDDS access control
plugins verify with `PKCS7_verify`, so today the Permissions CA has to stay
classical, as it was in the interoperability runs. A post-quantum
Permissions CA needs both plugins moved to the CMS API.
