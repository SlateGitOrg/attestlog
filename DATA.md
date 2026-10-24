# Data and test vectors

attestlog ships no datasets. It does use a few public test vectors and some
small fixtures written for this repository.

| Data | Location | Source | License | Use |
|---|---|---|---|---|
| RFC 6962 Merkle leaf, node and root hashes for an 8-leaf tree | `pkg/merkle/merkle_test.go` (`vectorLeaves`, `vectorLeafHashes`, `vectorRoots`, `vectorNodes`) | [transparency-dev/merkle](https://github.com/transparency-dev/merkle) `testonly/constants.go` @ `c39fbf350a405f68571bf4c42a6a518eb0a46a4b` | Apache-2.0 | Golden test for leaf and node hashing and tree roots |
| 98 inclusion-proof probes + 98 consistency-proof probes (valid and deliberately broken proofs) | `pkg/merkle/testdata/{inclusion,consistency}/` (196 JSON files, 800 KB on disk) | same repository and commit, `testdata/inclusion` and `testdata/consistency`, copied unmodified | Apache-2.0 (license copied to `pkg/merkle/testdata/LICENSE.transparency-dev-merkle`) | Proof verification must accept the valid probes and reject every broken one |
| Signed-note vector ("PeterNeumann" key, private key, signed text) | `pkg/note/note_test.go` | [golang/mod](https://github.com/golang/mod) `sumdb/note/note_test.go` @ `b5136e5ba156da612a1efc6e49b55988a134a5e0` | BSD-3-Clause | Byte-for-byte check against Go's `sumdb/note` signing format |
| DSSE PAE example (`DSSEv1 29 http://example.com/HelloWorld 11 hello world`) | `pkg/dsse/dsse_test.go` | [DSSE protocol spec](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) | Apache-2.0 | Golden test for the pre-authentication encoding |
| Demo artifact and policy | `examples/demo/` | written for this repository | MIT (this repo) | `make demo` |

## Provenance checks

The probe files were taken from the GitHub tarball of the pinned commit:

```
curl -sSfL -o merkle.tgz https://codeload.github.com/transparency-dev/merkle/tar.gz/c39fbf350a405f68571bf4c42a6a518eb0a46a4b
shasum -a 256 merkle.tgz
# ed0c1017ea66fc7e88e67998f7d6b9cc1eef66d30b97b58a1dbfc1aa3a1edd09  (tarball as downloaded on 2026-10-24)
```

Checksum of the committed probe files (run in `pkg/merkle/testdata`):

```
find inclusion consistency -type f -name '*.json' | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256
# b9ebca6061a41485e515d2909c5ce5eec2f0858429f2f01822ab8dd35beed803  -
```

One deliberate difference in semantics. Upstream treats a consistency proof
from an empty tree (`size1 == 0`) as an error. RFC 9162 §2.1.4 only defines
proofs for `0 < size1`, and attestlog follows the same rule, so all 98
consistency probes pass unmodified. Some equal-size probes use 12-byte
placeholder roots. The test maps those through SHA-256 to keep byte-equality
semantics under the typed 32-byte `Hash` API; see `probeRoot` in
`pkg/merkle/merkle_test.go`.

All keys used by tests and the demo are generated fresh at run time. The
repository contains no private keys.
