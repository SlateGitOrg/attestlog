package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RFC 6962 reference vectors from github.com/transparency-dev/merkle
// (testonly/constants.go, Apache-2.0). See DATA.md.
var (
	vectorLeaves = []string{
		"", "00", "10", "2021", "3031", "40414243",
		"5051525354555657", "606162636465666768696a6b6c6d6e6f",
	}
	vectorLeafHashes = []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
		"0298d122906dcfc10892cb53a73992fc5b9f493ea4c9badb27b791b4127a7fe7",
		"07506a85fd9dd2f120eb694f86011e5bb4662e5c415a62917033d4a9624487e7",
		"bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
		"4271a26be0d8a84f0bd54c8c302e7cb3a3b5d1fa6780a40bcce2873477dab658",
		"b08693ec2e721597130641e8211e7eedccb4c26413963eee6c1e2ed16ffb1a5f",
		"46f6ffadd3d06a09ff3c5860d2755c8b9819db7df44251788c7d8e3180de8eb1",
	}
	vectorRoots = []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	// Interior nodes of the 8-leaf tree (levels 1..3).
	vectorNodes = [][]string{
		{
			"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
			"5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
			"0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
			"ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
		},
		{
			"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
			"6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
		},
		{"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"},
	}
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRFC6962Vectors(t *testing.T) {
	if got := EmptyRoot().String(); got != vectorRoots[0] {
		t.Fatalf("empty root = %s", got)
	}
	tree := NewTree()
	for i, in := range vectorLeaves {
		lh := LeafHash(mustHex(t, in))
		if lh.String() != vectorLeafHashes[i] {
			t.Fatalf("leaf %d hash = %s, want %s", i, lh, vectorLeafHashes[i])
		}
		tree.AppendLeaf(mustHex(t, in))
		if got := tree.Root().String(); got != vectorRoots[i+1] {
			t.Fatalf("root at size %d = %s, want %s", i+1, got, vectorRoots[i+1])
		}
	}
	for size := uint64(0); size <= 8; size++ {
		r, err := tree.RootAt(size)
		if err != nil || r.String() != vectorRoots[size] {
			t.Fatalf("RootAt(%d) = %s, %v", size, r, err)
		}
	}
	for lvl, nodes := range vectorNodes {
		for i, want := range nodes {
			if got := tree.levels[lvl+1][i].String(); got != want {
				t.Errorf("node level %d index %d = %s, want %s", lvl+1, i, got, want)
			}
		}
	}
}

// probe files: github.com/transparency-dev/merkle testdata (Apache-2.0).
type inclusionProbe struct {
	LeafIdx   uint64   `json:"leafIdx"`
	TreeSize  uint64   `json:"treeSize"`
	Root      []byte   `json:"root"`
	LeafHash  []byte   `json:"leafHash"`
	Proof     [][]byte `json:"proof"`
	Desc      string   `json:"desc"`
	WantError bool     `json:"wantErr"`
}

type consistencyProbe struct {
	Size1     uint64   `json:"size1"`
	Size2     uint64   `json:"size2"`
	Root1     []byte   `json:"root1"`
	Root2     []byte   `json:"root2"`
	Proof     [][]byte `json:"proof"`
	Desc      string   `json:"desc"`
	WantError bool     `json:"wantErr"`
}

func loadProbes[T any](t *testing.T, dir string) []T {
	t.Helper()
	var out []T
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var p T
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatalf("no probes in %s", dir)
	}
	return out
}

// toHashes converts a probe proof; ok is false if any element has the wrong
// length (such a proof must be rejected).
func toHashes(raw [][]byte) ([]Hash, bool) {
	out := make([]Hash, len(raw))
	for i, b := range raw {
		h, err := HashFromBytes(b)
		if err != nil {
			return nil, false
		}
		out[i] = h
	}
	return out, true
}

func TestInclusionProbes(t *testing.T) {
	probes := loadProbes[inclusionProbe](t, "testdata/inclusion")
	for _, p := range probes {
		proof, ok1 := toHashes(p.Proof)
		root, err1 := HashFromBytes(p.Root)
		leaf, err2 := HashFromBytes(p.LeafHash)
		err := errors.New("malformed input")
		if ok1 && err1 == nil && err2 == nil {
			err = VerifyInclusion(p.LeafIdx, p.TreeSize, leaf, proof, root)
		}
		if p.WantError && err == nil {
			t.Errorf("%s: expected error", p.Desc)
		}
		if !p.WantError && err != nil {
			t.Errorf("%s: unexpected error %v", p.Desc, err)
		}
	}
	t.Logf("checked %d inclusion probes", len(probes))
}

func TestConsistencyProbes(t *testing.T) {
	probes := loadProbes[consistencyProbe](t, "testdata/consistency")
	for _, p := range probes {
		proof, ok1 := toHashes(p.Proof)
		// Some probes use placeholder roots of the wrong length when the
		// sizes are equal and only byte-equality matters; map those through
		// SHA-256 so equality is preserved under the typed Hash API.
		r1, r2 := probeRoot(p.Root1), probeRoot(p.Root2)
		err := errors.New("malformed input")
		if ok1 {
			err = VerifyConsistency(p.Size1, p.Size2, proof, r1, r2)
		}
		if p.WantError && err == nil {
			t.Errorf("%s: expected error", p.Desc)
		}
		if !p.WantError && err != nil {
			t.Errorf("%s: unexpected error %v", p.Desc, err)
		}
	}
	t.Logf("checked %d consistency probes", len(probes))
}

func probeRoot(b []byte) Hash {
	if h, err := HashFromBytes(b); err == nil {
		return h
	}
	return sha256.Sum256(b)
}

// referenceRoot is the literal recursive definition of MTH from RFC 9162,
// used as an oracle for the stored-level implementation.
func referenceRoot(leaves [][]byte) Hash {
	switch len(leaves) {
	case 0:
		return EmptyRoot()
	case 1:
		return LeafHash(leaves[0])
	}
	k := largestPow2Below(uint64(len(leaves)))
	return NodeHash(referenceRoot(leaves[:k]), referenceRoot(leaves[k:]))
}

func TestPropertyProofsRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	tree := NewTree()
	var leaves [][]byte
	for n := 1; n <= 70; n++ {
		leaf := []byte{byte(n), byte(rng.IntN(256))}
		leaves = append(leaves, leaf)
		tree.AppendLeaf(leaf)
		if tree.Root() != referenceRoot(leaves) {
			t.Fatalf("root mismatch at size %d", n)
		}
	}
	size := tree.Size()
	for s2 := uint64(1); s2 <= size; s2++ {
		r2, _ := tree.RootAt(s2)
		for i := range s2 {
			proof, err := tree.InclusionProof(i, s2)
			if err != nil {
				t.Fatal(err)
			}
			lh, _ := tree.LeafHashAt(i)
			if err := VerifyInclusion(i, s2, lh, proof, r2); err != nil {
				t.Fatalf("inclusion %d/%d: %v", i, s2, err)
			}
			if i+1 < s2 {
				if VerifyInclusion(i+1, s2, lh, proof, r2) == nil {
					t.Fatalf("inclusion accepted wrong index %d/%d", i+1, s2)
				}
			}
		}
		for s1 := uint64(1); s1 <= s2; s1++ {
			r1, _ := tree.RootAt(s1)
			proof, err := tree.ConsistencyProof(s1, s2)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(s1, s2, proof, r1, r2); err != nil {
				t.Fatalf("consistency %d->%d: %v", s1, s2, err)
			}
			if s1 > 0 && s1 < s2 {
				bad := r1
				bad[0] ^= 1
				if VerifyConsistency(s1, s2, proof, bad, r2) == nil {
					t.Fatalf("consistency accepted tampered root %d->%d", s1, s2)
				}
			}
		}
	}
}

func TestProofBounds(t *testing.T) {
	tree := NewTree()
	for i := range 5 {
		tree.AppendLeaf([]byte{byte(i)})
	}
	if _, err := tree.InclusionProof(5, 5); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("want ErrIndexOutOfRange, got %v", err)
	}
	if _, err := tree.InclusionProof(0, 6); !errors.Is(err, ErrSizeOutOfRange) {
		t.Errorf("want ErrSizeOutOfRange, got %v", err)
	}
	if _, err := tree.ConsistencyProof(4, 3); !errors.Is(err, ErrInconsistentSize) {
		t.Errorf("want ErrInconsistentSize, got %v", err)
	}
	if _, err := tree.ConsistencyProof(1, 9); !errors.Is(err, ErrSizeOutOfRange) {
		t.Errorf("want ErrSizeOutOfRange, got %v", err)
	}
	if _, err := tree.RootAt(6); !errors.Is(err, ErrSizeOutOfRange) {
		t.Errorf("want ErrSizeOutOfRange, got %v", err)
	}
	if _, err := tree.LeafHashAt(5); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("want ErrIndexOutOfRange, got %v", err)
	}
	if _, err := tree.ConsistencyProof(0, 3); !errors.Is(err, ErrEmptyConsistency) {
		t.Errorf("want ErrEmptyConsistency, got %v", err)
	}
	if err := VerifyConsistency(3, 2, nil, Hash{}, Hash{}); !errors.Is(err, ErrInconsistentSize) {
		t.Errorf("want ErrInconsistentSize, got %v", err)
	}
	if _, err := RootFromInclusionProof(3, 3, Hash{}, nil); !errors.Is(err, ErrIndexOutOfRange) {
		t.Errorf("want ErrIndexOutOfRange, got %v", err)
	}
}

func TestHashParsing(t *testing.T) {
	h := LeafHash([]byte("x"))
	got, err := ParseHash(h.String())
	if err != nil || got != h {
		t.Fatalf("ParseHash round trip: %v", err)
	}
	if _, err := ParseHash("zz"); err == nil {
		t.Error("want hex error")
	}
	if _, err := ParseHash("abcd"); err == nil {
		t.Error("want length error")
	}
}

// FuzzVerifyInclusion asserts verification never panics and never accepts
// a proof that has been modified from a valid one.
func FuzzVerifyInclusion(f *testing.F) {
	tree := NewTree()
	for i := range 13 {
		tree.AppendLeaf([]byte{byte(i)})
	}
	f.Add(uint64(3), uint64(13), []byte{0}, uint8(0))
	f.Add(uint64(12), uint64(13), []byte{1, 2}, uint8(5))
	f.Fuzz(func(t *testing.T, idx, size uint64, flip []byte, pos uint8) {
		size = size%tree.Size() + 1
		idx %= size
		proof, err := tree.InclusionProof(idx, size)
		if err != nil {
			t.Fatal(err)
		}
		root, _ := tree.RootAt(size)
		leaf, _ := tree.LeafHashAt(idx)
		if err := VerifyInclusion(idx, size, leaf, proof, root); err != nil {
			t.Fatalf("valid proof rejected: %v", err)
		}
		if len(proof) == 0 || len(flip) == 0 || bytes.Count(flip, []byte{0}) == len(flip) {
			return
		}
		p := int(pos) % len(proof)
		mut := append([]Hash(nil), proof...)
		for i, b := range flip {
			mut[p][i%HashSize] ^= b
		}
		if mut[p] == proof[p] {
			return
		}
		if VerifyInclusion(idx, size, leaf, mut, root) == nil {
			t.Fatalf("mutated proof accepted")
		}
	})
}

func BenchmarkAppend(b *testing.B) {
	tree := NewTree()
	leaf := LeafHash([]byte("bench"))
	for b.Loop() {
		tree.AppendHash(leaf)
	}
}

func benchTree(n int) *Tree {
	tree := NewTree()
	for i := range n {
		tree.AppendLeaf([]byte{byte(i), byte(i >> 8), byte(i >> 16)})
	}
	return tree
}

func BenchmarkInclusionProof1M(b *testing.B) {
	tree := benchTree(1 << 20)
	size := tree.Size() - 7 // ragged right edge: worst case for subtree recomputation
	i := uint64(0)
	for b.Loop() {
		if _, err := tree.InclusionProof(i%size, size); err != nil {
			b.Fatal(err)
		}
		i += 7919
	}
}

func BenchmarkVerifyInclusion1M(b *testing.B) {
	tree := benchTree(1 << 20)
	size := tree.Size() - 7
	proof, _ := tree.InclusionProof(12345, size)
	root, _ := tree.RootAt(size)
	leaf, _ := tree.LeafHashAt(12345)
	for b.Loop() {
		if err := VerifyInclusion(12345, size, leaf, proof, root); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConsistencyProof1M(b *testing.B) {
	tree := benchTree(1 << 20)
	size := tree.Size() - 7
	for b.Loop() {
		if _, err := tree.ConsistencyProof(size/3+1, size); err != nil {
			b.Fatal(err)
		}
	}
}
