# Formal model

`pkidh.spthy` is a Tamarin model of the DDS:Auth:PKI-DH handshake of DDS
Security 1.2 with the key establishment of `protocol/pkidh-mlkem.md`. It
answers the open questions Q1 and Q2 of that document and checks that the
five KEM rules are enough.

A formal analysis of the classical handshake was published by Lauser,
Müller, Baumgart and Krauß ("Data Distribution and Redistribution", ACM SAC
2025). This model was written from scratch.

## What it contains

Three messages, as in 10.3.2.5 of the specification. The Request carries
`c1` (identity, key, participant data, algorithm), `dh1` and `challenge1`.
The Reply carries `c2`, `dh2`, both challenges and the replier's signature
over `hash_c2, challenge2, dh2, challenge1, dh1, hash_c1`. The Final carries
the challenges and the initiator's signature over `hash_c1, challenge1, dh1,
challenge2, dh2, hash_c2`. Each side uses its own copies of `dh1`, `dh2`
and the hashes (rule 2). `SharedSecret` is the hash of the key
establishment secret.

The KEM has no binding properties: the attacker can turn any ciphertext into
another that decapsulates to the same key, and decapsulating a ciphertext
that was not made for the key gives a value only the key holder can compute
(ML-KEM's implicit rejection). The attacker controls the network, can
register its own identities, and can reveal any long-term signing key at any
time.

Flags, passed to Tamarin as `-D=FLAG`:

| Flag | Meaning |
|---|---|
| (none) | `dh1 = g^x`, `dh2 = g^y` |
| `KEM` | `dh1` is an encapsulation key, `dh2` a ciphertext |
| `HYBRID` | both, as a pair, as in X25519MLKEM768 |
| `BREAKKEM` | the KEM is broken: honest decapsulation keys leak |
| `BREAKDH` | Diffie-Hellman is broken: honest exponents leak |
| `TRANSCRIPT` | `SharedSecret` also hashes both hashes, both challenges, `dh1` and `dh2` |
| `ECHO` | each side verifies the peer's signature over the `dh1` echoed in the message, not its own copy |
| `NEGOTIATE` | two KEMs, `strong` and `weak` (broken). The initiator picks by the peer's algorithm info from discovery, which the attacker can rewrite |
| `CHECK` | with `NEGOTIATE`: the initiator compares the authenticated algorithm info in `c.pdata` with what discovery said |

Lemmas:

1. `executable`: two honest participants complete a handshake.
2. `secrecy`: `SharedSecret` stays secret unless a long-term key of either
   side is revealed.
3. `forward_secrecy`: the same, where only reveals before the handshake
   completed count.
4. `agreement_initiator`, `agreement_replier`: injective agreement on both
   identities, `hash_c1`, `hash_c2`, both challenges, `dh1`, `dh2`, the
   algorithm and `SharedSecret`.
5. With `ECHO` lemma 4 must fail: this is the bug of the old CycloneDDS
   adapter, and the model has to be able to see it.
6. `no_downgrade`: a handshake between honest participants, who both
   support the strong KEM, never ends with the weak one.

## Running

```sh
./run.sh
```

runs every combination below. It fails when `tamarin-prover` is not on the
PATH, or when a combination does not report all six lemmas. A single one:

```sh
tamarin-prover -D=HYBRID -D=BREAKKEM --prove pkidh.spthy
```

Tamarin 1.12.0 with Maude 3.5.1; Tamarin needs a UTF-8 locale. All
combinations together take about ten minutes on two cores.

## Results

`v` verified, `F` falsified (Tamarin found an attack).

| Flags | exec | secrecy | fwd secrecy | agree I | agree R | no downgrade |
|---|---|---|---|---|---|---|
| (DH) | v | v | v | v | v | v |
| KEM | v | v | v | v | v | v |
| KEM TRANSCRIPT | v | v | v | v | v | v |
| HYBRID | v | v | v | v | v | v |
| HYBRID BREAKKEM | v | v | v | v | v | v |
| HYBRID BREAKDH | v | v | v | v | v | v |
| HYBRID TRANSCRIPT BREAKKEM | v | v | v | v | v | v |
| HYBRID TRANSCRIPT BREAKDH | v | v | v | v | v | v |
| KEM BREAKKEM | v | F | F | v | v | v |
| HYBRID BREAKKEM BREAKDH | v | F | F | v | v | v |
| KEM ECHO | v | F | F | F | F | v |
| HYBRID ECHO | v | F | F | F | F | v |
| KEM NEGOTIATE | v | F | F | v | v | F |
| KEM NEGOTIATE CHECK | v | v | v | v | v | v |

The rows with everything broken are controls: they show that secrecy
depends on the key establishment and that the lemmas can fail. The
`no_downgrade` lemma is only meaningful with `NEGOTIATE`; without it there
is no weak algorithm.

**Echo attack.** The attacker replaces `dh1` in the Request with its own
encapsulation key. The replier encapsulates to it and signs what it
received; the initiator signs its real `dh1`. Each side checks the other's
signature against the copy echoed in the message, so both accept, and the
attacker knows the replier's secret. Rule 2 (use your own copy) prevents
it.

**Downgrade attack.** The attacker rewrites the discovery data so that the
replier seems to support only the weak KEM. The initiator chooses it, the
replier accepts it because it supports it, and the handshake completes.
Both sides sign `c.pdata`, which carries the replier's real algorithm info,
but 1.2 never compares it with what discovery said. With that comparison
(`CHECK`) the attack is gone.

## Answers

**Q1. Is `SharedSecret = SHA-256(secret)` enough?** Yes, in this model.
For a KEM without any binding property and for the hybrid with either
component broken, secrecy, forward secrecy and agreement hold with the plain
hash, and hashing the transcript into `SharedSecret` adds nothing. The
reason is that both `dh1` and `dh2` are inside both signatures, and each
side uses its own copies: a changed share is noticed before the secret is
used. The proposal keeps the rule of 1.2 and adds no combiner.

This is a symbolic result. It cannot rule out computational weaknesses of
the plain concatenation in the hybrid, the concern behind X-Wing and the
TLS draft's warning. In PKI-DH an attacker cannot get a modified share
accepted without breaking a signature, which removes the setting those
warnings are about, but a computational proof is outside what Tamarin
shows.

**Q2. Is the algorithm choice protected against downgrade?** Not in 1.2,
when the initiator chooses by what discovery says about the peer. 1.2
leaves the choice to the plugin when the configured algorithm is `AUTO`,
and discovery is the only source of the peer's algorithm info. An attacker
who rewrites it can make two participants that both support a post-quantum
KEM agree on a weaker one that both still accept, for example a classical
Diffie-Hellman. The fix is one check: after the handshake, the algorithm
info in the authenticated `c.pdata` must equal what discovery delivered.

The adapters in this repository and the OpenDDS built-in plugin always use
their configured algorithm, so they are not exposed today.

## Limits

- Symbolic model: cryptography is perfect except where a flag breaks it.
- One signature algorithm, and the permissions document and its CA are left
  out.
- No leaks of session state; rule 5 (erasure) is assumed.
- Rule 3 (one ciphertext per Request, retransmissions get an equivalent
  Reply) is not modelled: every Request gets one Reply.
- The downgrade model has the initiator choose; the replier accepts any
  algorithm it supports, as in 1.2.
- The two algorithms of `NEGOTIATE` are labelled `strong` and `weak`, and
  the weak one gives its secret to the attacker. It stands for any algorithm
  both sides still accept and the attacker can break, such as ECDH against
  an attacker with a quantum computer; the attack does not depend on how it
  works. The 1.2 algorithm masks are abstracted as one announced value.
