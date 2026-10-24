// Package tlog is the append-only transparency log: it validates DSSE
// attestation entries, appends them to an RFC 6962 Merkle tree backed by a
// durable store, and signs a checkpoint after every append.
package tlog

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/archit2501/attestlog/pkg/checkpoint"
	"github.com/archit2501/attestlog/pkg/intoto"
	"github.com/archit2501/attestlog/pkg/merkle"
	"github.com/archit2501/attestlog/pkg/note"
)

// ErrNotFound is returned for unknown indices or leaf hashes.
var ErrNotFound = errors.New("tlog: not found")

// Options configures a Log.
type Options struct {
	// Now supplies checkpoint timestamps; defaults to time.Now.
	Now func() time.Time
	// Logger receives structured operational logs; defaults to discard.
	Logger *slog.Logger
}

// Log is a transparency log instance. It is safe for concurrent use.
type Log struct {
	mu        sync.RWMutex
	tree      *merkle.Tree
	bodies    [][]byte
	byLeaf    map[merkle.Hash]uint64
	bySubject map[string][]uint64
	head      *checkpoint.Signed

	store  Store
	signer *note.Signer
	now    func() time.Time
	logger *slog.Logger
}

// New opens a log over store, replaying and re-indexing existing entries.
// The checkpoint origin is the signer's key name.
func New(store Store, signer *note.Signer, opts Options) (*Log, error) {
	if store == nil || signer == nil {
		return nil, errors.New("tlog: store and signer are required")
	}
	l := &Log{
		tree:      merkle.NewTree(),
		byLeaf:    map[merkle.Hash]uint64{},
		bySubject: map[string][]uint64{},
		store:     store,
		signer:    signer,
		now:       opts.Now,
		logger:    opts.Logger,
	}
	if l.now == nil {
		l.now = time.Now
	}
	if l.logger == nil {
		l.logger = slog.New(slog.DiscardHandler)
	}
	err := store.Load(func(body []byte) error {
		e, err := ParseEntry(body)
		if err != nil {
			return fmt.Errorf("tlog: replay entry %d: %w", l.tree.Size(), err)
		}
		// Signatures were verified on admission; replay re-parses the
		// payload only to rebuild the subject index.
		var subjects []intoto.DigestSet
		if payload, err := e.Spec.Envelope.DecodePayload(); err == nil {
			if st, err := intoto.ParseStatement(payload); err == nil {
				for _, s := range st.Subject {
					subjects = append(subjects, s.Digest)
				}
			}
		}
		l.appendLocked(body, merkle.LeafHash(body), subjects)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := l.signHeadLocked(); err != nil {
		return nil, err
	}
	l.logger.Info("log opened", "origin", signer.Name(), "size", l.tree.Size(), "root", l.head.Root.String())
	return l, nil
}

// Origin returns the log identity (the checkpoint origin line).
func (l *Log) Origin() string { return l.signer.Name() }

// Verifier returns the key that verifies this log's checkpoints.
func (l *Log) Verifier() *note.Verifier { return l.signer.Verifier() }

func (l *Log) appendLocked(body []byte, leaf merkle.Hash, subjects []intoto.DigestSet) uint64 {
	idx := l.tree.AppendHash(leaf)
	l.bodies = append(l.bodies, body)
	l.byLeaf[leaf] = idx
	for _, d := range subjects {
		for alg, v := range d {
			k := alg + ":" + v
			l.bySubject[k] = append(l.bySubject[k], idx)
		}
	}
	return idx
}

func (l *Log) signHeadLocked() error {
	cp := &checkpoint.Checkpoint{
		Origin:    l.signer.Name(),
		Size:      l.tree.Size(),
		Root:      l.tree.Root(),
		Timestamp: l.now().UTC(),
	}
	signed, err := checkpoint.Sign(cp, l.signer)
	if err != nil {
		return fmt.Errorf("tlog: sign checkpoint: %w", err)
	}
	l.head = signed
	return nil
}

// AddResult describes an accepted entry.
type AddResult struct {
	Index     uint64
	LeafHash  merkle.Hash
	Duplicate bool
	// Checkpoint is the signed head that includes the entry.
	Checkpoint *checkpoint.Signed
	// Proof is the inclusion proof of the entry against Checkpoint.
	Proof []merkle.Hash
}

// Add validates body (canonical form, signatures, in-toto payload), appends
// it durably and signs a new checkpoint. Re-submitting an existing entry
// returns the original index with Duplicate set.
func (l *Log) Add(body []byte) (*AddResult, error) {
	e, err := ParseEntry(body)
	if err != nil {
		return nil, err
	}
	ve, err := e.Verify()
	if err != nil {
		return nil, err
	}
	leaf := merkle.LeafHash(body)

	l.mu.Lock()
	defer l.mu.Unlock()
	if idx, ok := l.byLeaf[leaf]; ok {
		return l.resultLocked(idx, leaf, true)
	}
	if err := l.store.Append(body); err != nil {
		return nil, err
	}
	subjects := make([]intoto.DigestSet, len(ve.Statement.Subject))
	for i, s := range ve.Statement.Subject {
		subjects[i] = s.Digest
	}
	idx := l.appendLocked(append([]byte(nil), body...), leaf, subjects)
	if err := l.signHeadLocked(); err != nil {
		return nil, err
	}
	l.logger.Info("entry appended", "index", idx, "leaf", leaf.String(), "signers", len(ve.KeyIDs), "size", l.tree.Size())
	return l.resultLocked(idx, leaf, false)
}

func (l *Log) resultLocked(idx uint64, leaf merkle.Hash, dup bool) (*AddResult, error) {
	proof, err := l.tree.InclusionProof(idx, l.head.Size)
	if err != nil {
		return nil, err
	}
	return &AddResult{Index: idx, LeafHash: leaf, Duplicate: dup, Checkpoint: l.head, Proof: proof}, nil
}

// Head returns the latest signed checkpoint.
func (l *Log) Head() *checkpoint.Signed {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.head
}

// Size returns the number of entries.
func (l *Log) Size() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.Size()
}

// Entry returns the canonical body and leaf hash of entry index.
func (l *Log) Entry(index uint64) ([]byte, merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if index >= l.tree.Size() {
		return nil, merkle.Hash{}, ErrNotFound
	}
	leaf, _ := l.tree.LeafHashAt(index)
	return l.bodies[index], leaf, nil
}

// InclusionProof returns the audit path of index in the tree of size.
func (l *Log) InclusionProof(index, size uint64) ([]merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.InclusionProof(index, size)
}

// InclusionProofByHash looks a leaf up by hash and returns its index and
// audit path in the tree of size.
func (l *Log) InclusionProofByHash(leaf merkle.Hash, size uint64) (uint64, []merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	idx, ok := l.byLeaf[leaf]
	if !ok || idx >= size {
		return 0, nil, ErrNotFound
	}
	proof, err := l.tree.InclusionProof(idx, size)
	return idx, proof, err
}

// ConsistencyProof proves the tree of size1 is a prefix of the tree of size2.
func (l *Log) ConsistencyProof(size1, size2 uint64) ([]merkle.Hash, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.tree.ConsistencyProof(size1, size2)
}

// Search returns the indices of entries with a subject matching any
// algorithm/value pair in d, in ascending order without duplicates.
func (l *Log) Search(d intoto.DigestSet) []uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	seen := map[uint64]bool{}
	var out []uint64
	for alg, v := range d {
		for _, idx := range l.bySubject[alg+":"+v] {
			if !seen[idx] {
				seen[idx] = true
				out = append(out, idx)
			}
		}
	}
	slices.Sort(out)
	return out
}

// Close closes the underlying store.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.store.Close()
}
