# Threat model

attestlog is a defensive, educational tool. Every demo and test runs against
local fixtures and a log on `127.0.0.1`. It contains no offensive
functionality, and the attacks in `make demo` are simulations against the
tool's own components.

## Assets

- **Artifact integrity.** The bytes a consumer runs are the bytes the trusted
  builder produced.
- **Provenance truthfulness**, as far as signatures can establish it. The
  claimed builder, source repository, ref and commit are what a trusted key
  signed.
- **Log append-only property.** Every client sees one history that only
  grows.
- **Discoverability.** Every attestation for an artifact that was logged can
  be found, including malicious ones.

## Trust assumptions

| Assumption | Where it is configured |
|---|---|
| The verifier knows the trusted builder public keys, distributed out of band | `verify --pubkey` |
| The verifier pins the log's checkpoint key | `--log-key` (`origin+hash+key`) |
| Policy files are authored by the verifier, not by the producer | `verify --policy` |
| SHA-256, Ed25519 and ECDSA P-256 are secure | `pkg/keys`, `pkg/merkle` |
| The first checkpoint a monitor sees is honest (TOFU), until gossip says otherwise | `log prove --state` |

The log server, the network, the artifact store and the uploader are **not**
trusted.

## Adversaries and outcomes

| # | Adversary / attack | Defence | Detected or prevented? | Test |
|---|---|---|---|---|
| A1 | Artifact swapped after build (mirror or CDN compromise) | subject digest match (sha256 + sha512) | prevented: `subject-digest` fails | `TestTamperedArtifactAndReceipt`, demo step 6 |
| A2 | Attacker signs provenance with their own key | only `--pubkey` keys count; unauthenticated payload never parsed | prevented | `TestUntrustedSignerNeverEvaluated` |
| A3 | Rogue or compromised build platform with a *trusted* key claims a different builder ID or repo | builder/repo/ref allowlists, deny-by-default | prevented, if the policy is specific | `TestEvaluateFailures`, demo step 7 |
| A4 | Look-alike builder ID (`builder-evil@v1` vs `builder@*`) | exact match or `@*` suffix only, no prefix globbing | prevented | `builder prefix lookalike` case |
| A5 | Payload-type confusion (re-label envelope) | PAE binds payloadType | prevented | `TestTamperingDetected` |
| A6 | Threshold bypass by duplicating one signature | distinct-key counting | prevented | `TestThresholdCountsDistinctKeys` |
| A7 | Server lies in a receipt, audit path, entry or proof labels | client recomputes the leaf and verifies every proof | detected (`ErrMisbehaviour`, exit 3) | `TestLyingServerDetected` |
| A8 | Log operator equivocates (two heads, same size) | signed checkpoints, state comparison and gossip | detected with **conclusive, portable** evidence | `TestEquivocationDetectedViaGossip`, demo steps 9–11 |
| A9 | Operator rewrites history and grows past a client | consistency proof from the trusted head | detected (inconsistent) | `TestForkDetectedOnUpdate` |
| A10 | Operator signs a smaller tree later (rollback or truncation) | timestamps in checkpoints | detected with conclusive evidence | `TestRollbackAndStaleViews` |
| A11 | Tampered bundle receipt (proof, size or index) | offline inclusion verification | prevented | `TestBundleParsing`, `TestTamperedArtifactAndReceipt` |
| A12 | Crash or torn write in the log store | CRC-32C framing, fsync before signing | torn tail truncated; corruption is fatal | `TestFileStoreReplayAndTornTail` |
| A13 | Resource-exhaustion submissions | 2 MiB request cap, 1 MiB entry cap, server timeouts, 4 MiB client read cap | mitigated (no rate limiting) | `TestRawHTTPValidation` |

## What attestlog does *not* defend against

Each of these is a limitation, not a hidden feature.

- **Builder key compromise.** Anyone with a trusted signing key can produce
  attestations that pass. The log makes them *discoverable*, but it cannot
  prevent them, and attestlog has no key revocation or rotation.
- **A malicious but consistent builder.** Provenance records what the
  builder *claims*. attestlog does not reproduce builds or inspect build
  isolation, so it cannot reach SLSA Build L3 on its own.
- **Censorship or omission.** A log can refuse to include an entry or delay
  it. Submitters get an inclusion proof immediately, so silence is visible to
  the submitter, but a third party cannot prove that an entry exists without
  its receipt.
- **Split views with no gossip.** If two victims never compare checkpoints
  and never touch each other's view, equivocation stays undetected. The
  defence is `log compare` or a shared monitor state. There is no witness
  network.
- **TOFU.** A monitor whose first contact is a forked view trusts that view
  until another checkpoint contradicts it.
- **Inconsistency evidence is weaker than equivocation evidence.** "The log's
  proof did not verify" shows the log *failed to justify* two heads. A third
  party should re-request the proof. Equivocation and rollback evidence need
  no cooperation.
- **Timestamps are claims by the log**, not trusted time. They order the
  log's own signatures, which is enough for rollback evidence, but they do
  not prove when something was built.
- **Confidentiality.** Logged entries are public by design. Do not log
  provenance that reveals private repository names.
- **Availability.** A single node with no replication, rate limiting or
  authentication on submission.

## Security-relevant implementation notes

- Unauthenticated payloads are never decoded into policy input
  (`pkg/verify`).
- Policy loading rejects unknown fields, so a typo cannot silently disable a
  rule.
- Key files are written `0600`, public keys `0644`, and existing files are
  never overwritten without `--force`.
- No secrets live in the repository. Keys for tests and the demo are
  generated at run time.
