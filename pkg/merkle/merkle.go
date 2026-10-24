// Package merkle implements the RFC 6962 / RFC 9162 Merkle tree: hashing,
// an append-only in-memory tree with O(log n) root computation, and the
// generation and verification of inclusion and consistency proofs.
//
// Hashing (RFC 9162 §2.1.1):
//
//	MTH({})        = SHA-256()
//	leaf hash      = SHA-256(0x00 || entry)
//	interior node  = SHA-256(0x01 || left || right)
//
// The 0x00/0x01 domain separation prevents second-preimage attacks where an
// interior node is passed off as a leaf.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// HashSize is the size of every node hash in bytes.
const HashSize = sha256.Size

// Hash is a SHA-256 node hash.
type Hash [HashSize]byte

// String returns the lowercase hex form.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// HashFromBytes converts a byte slice to a Hash, checking its length.
func HashFromBytes(b []byte) (Hash, error) {
	var h Hash
	if len(b) != HashSize {
		return h, fmt.Errorf("merkle: hash has %d bytes, want %d", len(b), HashSize)
	}
	copy(h[:], b)
	return h, nil
}

// ParseHash decodes a hex hash.
func ParseHash(s string) (Hash, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, fmt.Errorf("merkle: invalid hex hash: %w", err)
	}
	return HashFromBytes(b)
}

// EmptyRoot is the root of the empty tree: SHA-256 of the empty string.
func EmptyRoot() Hash { return sha256.Sum256(nil) }

// LeafHash returns SHA-256(0x00 || data).
func LeafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

// NodeHash returns SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return sha256.Sum256(buf[:])
}

// Errors returned by tree operations and proof verification.
var (
	ErrIndexOutOfRange  = errors.New("merkle: index out of range")
	ErrSizeOutOfRange   = errors.New("merkle: tree size out of range")
	ErrProofMismatch    = errors.New("merkle: computed root does not match")
	ErrMalformedProof   = errors.New("merkle: malformed proof")
	ErrInconsistentSize = errors.New("merkle: second tree is smaller than first")
	// ErrEmptyConsistency: RFC 9162 §2.1.4 defines consistency proofs only
	// for 0 < size1. Every tree trivially extends the empty tree, so callers
	// must treat a trusted size of zero specially instead of asking for a
	// proof (a "proof" there would prove nothing).
	ErrEmptyConsistency = errors.New("merkle: consistency from an empty tree is undefined")
)

// largestPow2Below returns the largest power of two strictly less than n
// (n must be >= 2). This is the split point k of RFC 9162 §2.1.1.
func largestPow2Below(n uint64) uint64 {
	return 1 << (bits.Len64(n-1) - 1)
}

// Tree is an append-only Merkle tree that stores the hash of every complete
// subtree. levels[h][i] is the hash of the perfect subtree of height h that
// covers leaves [i·2^h, (i+1)·2^h). Storage is < 2n hashes; append is
// amortised O(1) hashes (worst case O(log n)), root and proofs are
// O(log² n) worst case because ragged right edges are recomputed.
//
// Tree is not safe for concurrent mutation; callers (see package tlog)
// serialise writers and readers.
type Tree struct {
	levels [][]Hash
}

// NewTree returns an empty tree.
func NewTree() *Tree { return &Tree{} }

// Size returns the number of leaves.
func (t *Tree) Size() uint64 {
	if len(t.levels) == 0 {
		return 0
	}
	return uint64(len(t.levels[0]))
}

// AppendLeaf hashes data as a leaf and appends it, returning its index.
func (t *Tree) AppendLeaf(data []byte) uint64 { return t.AppendHash(LeafHash(data)) }

// AppendHash appends an already-computed leaf hash and returns its index.
func (t *Tree) AppendHash(leaf Hash) uint64 {
	idx := t.Size()
	h := leaf
	for level := 0; ; level++ {
		if level == len(t.levels) {
			t.levels = append(t.levels, nil)
		}
		t.levels[level] = append(t.levels[level], h)
		n := len(t.levels[level])
		if n%2 == 1 {
			return idx
		}
		h = NodeHash(t.levels[level][n-2], t.levels[level][n-1])
	}
}

// LeafHashAt returns the stored hash of leaf i.
func (t *Tree) LeafHashAt(i uint64) (Hash, error) {
	if i >= t.Size() {
		return Hash{}, ErrIndexOutOfRange
	}
	return t.levels[0][i], nil
}

// Root returns the root of the current tree.
func (t *Tree) Root() Hash {
	r, _ := t.RootAt(t.Size())
	return r
}

// RootAt returns the root the tree had when it contained size leaves.
func (t *Tree) RootAt(size uint64) (Hash, error) {
	if size > t.Size() {
		return Hash{}, ErrSizeOutOfRange
	}
	if size == 0 {
		return EmptyRoot(), nil
	}
	return t.subtree(0, size), nil
}

// subtree returns MTH(D[lo:hi]). lo is always a multiple of the largest
// power of two not exceeding hi-lo, which is what the RFC recursion
// produces, so the left part is always a stored perfect subtree.
func (t *Tree) subtree(lo, hi uint64) Hash {
	n := hi - lo
	if n&(n-1) == 0 && lo%n == 0 {
		level := bits.TrailingZeros64(n)
		return t.levels[level][lo>>level]
	}
	k := largestPow2Below(n)
	return NodeHash(t.subtree(lo, lo+k), t.subtree(lo+k, hi))
}

// InclusionProof returns the audit path for leaf index in the tree of the
// given size (RFC 9162 §2.1.3.1 PATH), ordered from leaf to root.
func (t *Tree) InclusionProof(index, size uint64) ([]Hash, error) {
	if size > t.Size() || size == 0 {
		return nil, ErrSizeOutOfRange
	}
	if index >= size {
		return nil, ErrIndexOutOfRange
	}
	return t.path(index, 0, size), nil
}

// path implements PATH(m, D[lo:hi]) with m relative to lo.
func (t *Tree) path(m, lo, hi uint64) []Hash {
	n := hi - lo
	if n <= 1 {
		return nil
	}
	k := largestPow2Below(n)
	if m < k {
		return append(t.path(m, lo, lo+k), t.subtree(lo+k, hi))
	}
	return append(t.path(m-k, lo+k, hi), t.subtree(lo, lo+k))
}

// ConsistencyProof returns the proof that the tree of size1 is a prefix of
// the tree of size2 (RFC 9162 §2.1.4.1 PROOF).
func (t *Tree) ConsistencyProof(size1, size2 uint64) ([]Hash, error) {
	if size2 > t.Size() {
		return nil, ErrSizeOutOfRange
	}
	if size1 == 0 {
		return nil, ErrEmptyConsistency
	}
	if size1 > size2 {
		return nil, ErrInconsistentSize
	}
	if size1 == size2 {
		return nil, nil
	}
	return t.subproof(size1, 0, size2, true), nil
}

// subproof implements SUBPROOF(m, D[lo:hi], b).
func (t *Tree) subproof(m, lo, hi uint64, b bool) []Hash {
	n := hi - lo
	if m == n {
		if b {
			return nil
		}
		return []Hash{t.subtree(lo, hi)}
	}
	k := largestPow2Below(n)
	if m <= k {
		return append(t.subproof(m, lo, lo+k, b), t.subtree(lo+k, hi))
	}
	return append(t.subproof(m-k, lo+k, hi, false), t.subtree(lo, lo+k))
}

// RootFromInclusionProof computes the root implied by an inclusion proof
// using the RFC 9162 §2.1.3.2 algorithm.
func RootFromInclusionProof(index, size uint64, leaf Hash, proof []Hash) (Hash, error) {
	if index >= size {
		return Hash{}, ErrIndexOutOfRange
	}
	fn, sn := index, size-1
	r := leaf
	for _, p := range proof {
		if sn == 0 {
			return Hash{}, fmt.Errorf("%w: proof too long", ErrMalformedProof)
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return Hash{}, fmt.Errorf("%w: proof too short", ErrMalformedProof)
	}
	return r, nil
}

// VerifyInclusion checks that leaf is at index in the tree with the given
// size and root.
func VerifyInclusion(index, size uint64, leaf Hash, proof []Hash, root Hash) error {
	got, err := RootFromInclusionProof(index, size, leaf, proof)
	if err != nil {
		return err
	}
	if got != root {
		return ErrProofMismatch
	}
	return nil
}

// VerifyConsistency checks that the tree (size1, root1) is a prefix of the
// tree (size2, root2) using the RFC 9162 §2.1.4.2 algorithm.
func VerifyConsistency(size1, size2 uint64, proof []Hash, root1, root2 Hash) error {
	switch {
	case size1 == 0:
		return ErrEmptyConsistency
	case size2 < size1:
		return ErrInconsistentSize
	case size1 == size2:
		if len(proof) != 0 {
			return fmt.Errorf("%w: sizes equal but proof not empty", ErrMalformedProof)
		}
		if root1 != root2 {
			return ErrProofMismatch
		}
		return nil
	case len(proof) == 0:
		return fmt.Errorf("%w: empty proof", ErrMalformedProof)
	}

	path := proof
	if size1&(size1-1) == 0 {
		path = append([]Hash{root1}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if sn == 0 {
			return fmt.Errorf("%w: proof too long", ErrMalformedProof)
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fmt.Errorf("%w: proof too short", ErrMalformedProof)
	}
	if fr != root1 || sr != root2 {
		return ErrProofMismatch
	}
	return nil
}
