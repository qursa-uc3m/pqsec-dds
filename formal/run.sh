#!/bin/sh
# Prove every lemma of pkidh.spthy under each flag combination and print one
# line per combination. Needs tamarin-prover and maude on the PATH.

set -u
cd "$(dirname "$0")"
export LANG=C.UTF-8 LC_ALL=C.UTF-8

if ! command -v tamarin-prover >/dev/null; then
  echo "tamarin-prover not found" >&2
  exit 1
fi
lemmas=$(grep -c '^lemma ' pkidh.spthy)
status=0

for flags in \
  "" \
  "KEM" \
  "KEM TRANSCRIPT" \
  "HYBRID" \
  "HYBRID BREAKKEM" \
  "HYBRID BREAKDH" \
  "HYBRID TRANSCRIPT BREAKKEM" \
  "HYBRID TRANSCRIPT BREAKDH" \
  "KEM BREAKKEM" \
  "HYBRID BREAKKEM BREAKDH" \
  "KEM ECHO" \
  "HYBRID ECHO" \
  "KEM NEGOTIATE" \
  "KEM NEGOTIATE CHECK"
do
  defines=$(for f in $flags; do printf ' -D=%s' "$f"; done)
  # shellcheck disable=SC2086
  results=$(timeout 1800 tamarin-prover $defines --prove pkidh.spthy 2>&1 |
    sed -n 's/^  \([a-z_]*\) ([a-z-]*): \([a-z]*\).*/\1=\2/p' | tr '\n' ' ')
  printf '%-28s %s\n' "${flags:-DH}" "$results"
  if [ "$(echo "$results" | wc -w)" -ne "$lemmas" ]; then
    echo "  expected $lemmas lemma results; run tamarin-prover by hand to see why" >&2
    status=1
  fi
done
exit $status
