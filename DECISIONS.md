# Decisions

Design decisions, each recorded as
`Ruling: <what> — <why> — <cost if wrong>`.

## Scope and dependencies

- Ruling: Use only the Go standard library, with zero third-party modules. — Every primitive the spec needs (Ed25519, ECDSA, SHA-256, PEM/PKIX, HTTP, slog) is in the stdlib, which keeps the supply-chain surface of a supply-chain tool at zero and makes `make check` work offline. — If wrong, interop helpers that exist upstream (sigstore-go bundles, in-toto-golang) have to be re-implemented to read their formats.
- Ruling: Implement the in-toto, SLSA and DSSE types here instead of importing in-toto-golang. — The types are small. Owning them lets parsing be strict (`_type`, digest formats, unknown policy fields) and keeps the dependency graph empty. — If wrong, there may be subtle divergence from the reference parser on edge cases such as non-hex digest algorithms.
- Ruling: Go directive `go 1.24`, built and tested with Go 1.27.1. — The code uses `b.Loop`, `slog.DiscardHandler` and method-pattern `ServeMux`, all of which exist in 1.24. CI installs the version from `go.mod`. — If wrong, CI runs an older toolchain than local; the race and coverage gates still apply.

## Cryptography and formats

- Ruling: DSSE ECDSA signatures are ASN.1 DER over SHA-256(PAE). Ed25519 is pure Ed25519 over the PAE bytes. — These match the encodings used by sigstore and in-toto tooling. — If wrong, envelopes signed with P-256 by other tools would not verify. The risk is mitigated by following the common convention.
- Ruling: A DSSE key ID is the hex SHA-256 of the PKIX DER, and verification never trusts it. — The key ID is a stable, collision-resistant hint. The DSSE spec says `keyid` is unauthenticated, so it only reorders candidate keys. — If wrong, an ecosystem that expects a different key-ID scheme would see a mismatch, but verification is unaffected.
- Ruling: The threshold counts distinct keys, so one key signing twice counts once. — Otherwise a 2-of-N policy could be met by duplicating one signature. — No meaningful cost.
- Ruling: Checkpoints use the C2SP signed-note and tlog-checkpoint formats, with Ed25519 only. — This is the format Go's sumdb, Rekor checkpoints and the transparency-dev ecosystem use, so the bytes are recognisable and byte-compatible with `golang.org/x/mod/sumdb/note` (tested with its vector). — If wrong, an ECDSA log key would need the C2SP "0x02"-style extension, which is not implemented.
- Ruling: The checkpoint has a `timestamp <unix ms>` extension line. — RFC 6962 STHs carry a timestamp. The timestamp also makes rollback evidence possible (a smaller tree signed later). — If wrong, the extension line is non-standard; other parsers keep it as an opaque extension, as C2SP allows.
- Ruling: A consistency proof from size 0 is an error, at both generation and verification. — RFC 9162 defines proofs only for `0 < m`, and the upstream reference vectors expect an error. Callers treat a trusted size of 0 as trivially consistent if the root equals the empty-tree hash. — No meaningful cost.

## Log design

- Ruling: The log stores every complete-subtree hash in memory, under 2n hashes, about 64 MB per million entries. — This gives amortised O(1) append and O(log² n) worst-case proofs, with no database. — If wrong, logs with tens of millions of entries need a tiled or on-disk node store (see Roadmap).
- Ruling: Entry bodies stay in memory after replay. — It keeps the small-scale design simple, and bodies are capped at 1 MiB (the demo's are about 3 KB). — If wrong, memory grows linearly with log size. The fix is to keep file offsets instead of bodies.
- Ruling: Entries must be canonical JSON (re-marshalling must reproduce the bytes), and keys are normalised (sorted by key ID, de-duplicated). — This gives exactly one leaf hash per logical entry, so deduplication and offline bundle reconstruction both work. — If wrong, clients that hand-craft bodies with other whitespace get rejected. The server canonicalises submissions itself, so normal clients are unaffected.
- Ruling: Every public key listed in an entry must have signed the envelope. — Otherwise an uploader could attach unrelated keys and make key-based discovery misleading. — If wrong, a submitter with a partially signed multi-sig envelope must list only the keys that signed.
- Ruling: The log signs a new checkpoint after every append, with no batching. — Every submission gets an immediate inclusion proof, and the code stays simple. — If wrong, durable throughput is bounded by fsync. On macOS, which uses F_FULLFSYNC, two runs measured 4 to 6 ms per append, about 160 to 250 entries/s (see README). Group commit is on the roadmap.
- Ruling: The file store fsyncs before signing, truncates a torn tail, and fails hard on a complete record with a bad CRC. — A torn tail was never acknowledged, so it is safe to drop. A complete record may have been signed already, so dropping it silently would fork the log. — If wrong, an operator must repair a corrupted store by hand. That is the intended behaviour.
- Ruling: A failed append (write error, short write or fsync error) truncates the file back to the offset where the record started and fsyncs the truncation before returning the error. If that rollback fails too, the store latches and refuses every later append with `ErrStoreFailed` until restart. — The process keeps running after an I/O error, unlike a crash, so leftover bytes would otherwise sit under the next acknowledged and signed record: a torn leftover makes replay fail its CRC, and a complete leftover replays as an extra leaf that forks history away from already-signed checkpoints. Rolling back keeps the store usable after a transient error such as ENOSPC. The record was never acknowledged, so dropping it is safe. — If wrong (for example, the filesystem reports a successful truncate+fsync but keeps the bytes), replay still detects a torn tail or a CRC mismatch. A latched store needs a restart, and replay then truncates the torn tail. A complete leftover replays as one unacknowledged leaf after every signed head, which is an append-only extension, not a fork, because nothing was appended after it.
- Ruling: The server is untrusted. Clients verify checkpoint signatures, recompute leaf hashes and verify every proof, including the receipt at submission time. — This is the central property of a transparency log. — No meaningful cost.

## Detection semantics

- Ruling: Evidence comes in three kinds: equivocation (same size, different roots), rollback (smaller tree signed strictly later) and inconsistent (the log's own consistency proof fails). — The first two are self-contained and conclusive. The third is weaker, and the threat model says so. — If wrong, inconsistency evidence may be over-trusted. The docs say a third party should re-request the proof.
- Ruling: An older head that the source cannot prove consistent is reported as "stale" and is not treated as a fork. — A cache or lagging mirror cannot prove consistency up to a tree it does not have. Calling that a fork would be a false accusation. — If wrong, a fork is missed only if the malicious head is also older by timestamp, and then the trusted state does not move, so nothing is accepted.
- Ruling: Monitoring uses trust on first use (TOFU) for the first checkpoint. — No witness network exists in an offline tool. — If wrong, a client whose first contact is with a forked view trusts that view until gossip reveals the fork. The threat model documents this.

## Policy

- Ruling: Policy is deny-by-default. Empty builder or repo allowlists are rejected, and unknown JSON fields are rejected. — An empty list that meant "allow all", or a typo that silently disabled a rule, is a classic supply-chain policy failure. — If wrong, users must write explicit allowlists.
- Ruling: Builder IDs match exactly or with a trailing `@*` (any ref of that builder). Repos match exactly. — Prefix and glob matching invite look-alike bypasses such as `builder-evil`, which is tested. — If wrong, users with many builders must list each one.
- Ruling: The policy runs every rule and reports all failures, after authentication succeeds. — Operators see every reason at once. Unauthenticated payloads are never parsed, so an attacker cannot shape the report. — No meaningful cost.
- Ruling: The source revision comes from `externalParameters.source` (object or string), falling back to the first `git+` resolved dependency. — SLSA v1 leaves `externalParameters` to each buildType. This is the convention for attestlog's generic buildType, with a fallback that covers common real-world shapes. — If wrong, provenance from other builders with different parameter layouts reports "no source" and fails closed.

## Process

- Ruling: Core coverage is measured over `./pkg/...` across the whole test suite (`-coverpkg`), and the CLI is reported separately. — `pkg/server` is exercised through the client integration tests, which is where its behaviour matters. — If wrong, per-package numbers differ from the aggregate. Both commands are shown in the report.
- Ruling: The demo uses `127.0.0.1` with port 0 and bundled fixtures, and the forked log is a second server holding the same key. — This simulates a malicious operator without touching anything external. — No meaningful cost.
