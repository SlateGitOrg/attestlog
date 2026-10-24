// Package monitor detects log misbehaviour: equivocation (two signed
// checkpoints of the same size with different roots), forks (a newer
// checkpoint that is not an append-only extension of an older one) and
// rollbacks (a log presenting an older state than a client has already
// seen).
//
// Because every checkpoint carries the log's signing timestamp, a log that
// signs a smaller tree after a larger one has also proven a rollback.
//
// Detection is client-side. A client persists the last checkpoint it
// trusted (TOFU on first use) and demands a consistency proof before moving
// to any newer one. Checkpoints gathered by different parties can be
// cross-checked ("gossiped") with Compare to catch split views, where a log
// shows each victim a different, internally consistent history.
package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/archit2501/attestlog/pkg/api"
	"github.com/archit2501/attestlog/pkg/checkpoint"
	"github.com/archit2501/attestlog/pkg/merkle"
	"github.com/archit2501/attestlog/pkg/note"
)

// Evidence kinds.
const (
	KindEquivocation = "equivocation"
	KindInconsistent = "inconsistent"
	KindRollback     = "rollback"
)

// Evidence documents detected misbehaviour. Both checkpoints are the exact
// signed bytes, so anyone holding the log key can re-check the claim.
type Evidence struct {
	Kind        string   `json:"kind"`
	Origin      string   `json:"origin"`
	CheckpointA string   `json:"checkpointA"`
	CheckpointB string   `json:"checkpointB"`
	Proof       []string `json:"proof,omitempty"`
	Detail      string   `json:"detail"`
}

// ForkError is returned when misbehaviour is detected.
type ForkError struct{ Evidence *Evidence }

func (e *ForkError) Error() string {
	return fmt.Sprintf("monitor: log %s misbehaved (%s): %s", e.Evidence.Origin, e.Evidence.Kind, e.Evidence.Detail)
}

// ErrDifferentLogs is returned when comparing checkpoints from two origins.
var ErrDifferentLogs = errors.New("monitor: checkpoints are from different logs")

// Prover supplies consistency proofs, typically a *client.Client.
type Prover interface {
	ConsistencyProof(ctx context.Context, from, to uint64) ([]merkle.Hash, error)
}

// Compare checks that two verified checkpoints of the same log describe one
// append-only history. For equal sizes no proof is needed; otherwise a
// consistency proof is requested from p (which may be nil only for equal
// sizes). A *ForkError means misbehaviour was proven or the log could not
// justify its own heads; any other error means the check could not run.
func Compare(ctx context.Context, a, b *checkpoint.Signed, p Prover) error {
	if a.Origin != b.Origin {
		return fmt.Errorf("%w: %q vs %q", ErrDifferentLogs, a.Origin, b.Origin)
	}
	small, large := a, b
	if small.Size > large.Size {
		small, large = large, small
	}
	if small.Size == large.Size {
		if small.Root == large.Root {
			return nil
		}
		return &ForkError{Evidence: &Evidence{
			Kind: KindEquivocation, Origin: a.Origin,
			CheckpointA: string(small.Raw), CheckpointB: string(large.Raw),
			Detail: fmt.Sprintf("two signed checkpoints for tree size %d with roots %s and %s",
				small.Size, short(small.Root), short(large.Root)),
		}}
	}
	if isRollback(small, large) {
		return &ForkError{Evidence: &Evidence{
			Kind: KindRollback, Origin: a.Origin,
			CheckpointA: string(large.Raw), CheckpointB: string(small.Raw),
			Detail: fmt.Sprintf("log signed tree size %d at %s, after signing size %d at %s",
				small.Size, small.Timestamp.Format(time.RFC3339Nano), large.Size, large.Timestamp.Format(time.RFC3339Nano)),
		}}
	}
	if small.Size == 0 {
		if small.Root != merkle.EmptyRoot() {
			return &ForkError{Evidence: &Evidence{
				Kind: KindInconsistent, Origin: a.Origin,
				CheckpointA: string(small.Raw), CheckpointB: string(large.Raw),
				Detail: "signed checkpoint of size 0 does not carry the empty-tree root",
			}}
		}
		return nil // every tree extends the empty tree
	}
	if p == nil {
		return errors.New("monitor: a prover is required for checkpoints of different sizes")
	}
	proof, err := p.ConsistencyProof(ctx, small.Size, large.Size)
	if err != nil {
		return fmt.Errorf("monitor: fetch consistency proof %d->%d: %w", small.Size, large.Size, err)
	}
	if err := merkle.VerifyConsistency(small.Size, large.Size, proof, small.Root, large.Root); err != nil {
		return &ForkError{Evidence: &Evidence{
			Kind: KindInconsistent, Origin: a.Origin,
			CheckpointA: string(small.Raw), CheckpointB: string(large.Raw),
			Proof:  api.EncodeHashes(proof),
			Detail: fmt.Sprintf("tree %d is not a prefix of tree %d: %v", small.Size, large.Size, err),
		}}
	}
	return nil
}

// isRollback reports whether the log signed the smaller tree strictly after
// the larger one. An append-only log never shrinks, so two such signed heads
// are conclusive evidence on their own.
func isRollback(small, large *checkpoint.Signed) bool {
	return small.Size < large.Size && !small.Timestamp.IsZero() && !large.Timestamp.IsZero() &&
		small.Timestamp.After(large.Timestamp)
}

// VerifyEvidence re-checks evidence offline. Equivocation evidence is
// conclusive: two valid signatures over conflicting heads. Inconsistency
// evidence shows the log's own proof does not verify; it is conclusive only
// if the log cannot later produce a valid proof for the same pair (see
// docs/THREAT_MODEL.md).
func VerifyEvidence(e *Evidence, logKey *note.Verifier) error {
	a, err := checkpoint.Open([]byte(e.CheckpointA), logKey)
	if err != nil {
		return fmt.Errorf("monitor: evidence checkpoint A: %w", err)
	}
	b, err := checkpoint.Open([]byte(e.CheckpointB), logKey)
	if err != nil {
		return fmt.Errorf("monitor: evidence checkpoint B: %w", err)
	}
	switch e.Kind {
	case KindEquivocation:
		if a.Size != b.Size || a.Root == b.Root {
			return errors.New("monitor: equivocation evidence needs equal sizes and different roots")
		}
		return nil
	case KindRollback:
		if a.Size < b.Size {
			a, b = b, a
		}
		if !isRollback(b, a) {
			return errors.New("monitor: rollback evidence needs a smaller tree signed strictly later")
		}
		return nil
	case KindInconsistent:
		if a.Size > b.Size {
			a, b = b, a
		}
		if a.Size == 0 {
			if a.Root != merkle.EmptyRoot() {
				return nil
			}
			return errors.New("monitor: empty-tree checkpoint is consistent with everything")
		}
		proof, err := api.DecodeHashes(e.Proof)
		if err != nil {
			return fmt.Errorf("monitor: evidence proof: %w", err)
		}
		if merkle.VerifyConsistency(a.Size, b.Size, proof, a.Root, b.Root) == nil {
			return errors.New("monitor: the recorded proof verifies; no inconsistency shown")
		}
		return nil
	default:
		return fmt.Errorf("monitor: unknown evidence kind %q", e.Kind)
	}
}

// State is a persisted trusted checkpoint.
type State struct {
	path string
}

// NewState returns a state backed by path (created on first Save).
func NewState(path string) *State { return &State{path: path} }

// Load returns the trusted checkpoint, or nil if none has been saved yet.
func (s *State) Load(logKey *note.Verifier) (*checkpoint.Signed, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("monitor: read state: %w", err)
	}
	cp, err := checkpoint.Open(data, logKey)
	if err != nil {
		return nil, fmt.Errorf("monitor: state file holds an invalid checkpoint: %w", err)
	}
	return cp, nil
}

// Save atomically replaces the trusted checkpoint.
func (s *State) Save(cp *checkpoint.Signed) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("monitor: create state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("monitor: write state: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(cp.Raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("monitor: write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("monitor: sync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("monitor: close state: %w", err)
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return fmt.Errorf("monitor: replace state: %w", err)
	}
	return nil
}

// Source is what Update needs from a log: its latest checkpoint and proofs.
type Source interface {
	Prover
	Checkpoint(ctx context.Context) (*checkpoint.Signed, error)
	LogKey() *note.Verifier
}

// UpdateResult describes one monitoring step.
type UpdateResult struct {
	Previous *checkpoint.Signed // nil on first use
	Current  *checkpoint.Signed
	// Stale is true when the source served a head that is older (smaller
	// and signed earlier) than the trusted one, e.g. a cached or lagging
	// copy. The trusted state is kept. StaleVerified tells whether the
	// source could also prove the old head consistent with the trusted one.
	Stale         bool
	StaleVerified bool
	// FirstUse is true when no trusted state existed (trust on first use).
	FirstUse bool
}

// Update fetches the log's latest checkpoint, proves it consistent with the
// trusted state and advances the state. On a *ForkError the state is left
// untouched, so the evidence remains reproducible.
func Update(ctx context.Context, st *State, src Source) (*UpdateResult, error) {
	prev, err := st.Load(src.LogKey())
	if err != nil {
		return nil, err
	}
	cur, err := src.Checkpoint(ctx)
	if err != nil {
		return nil, err
	}
	res := &UpdateResult{Previous: prev, Current: cur}
	if prev == nil {
		res.FirstUse = true
		return res, st.Save(cur)
	}
	err = Compare(ctx, prev, cur, src)
	var fe *ForkError
	if errors.As(err, &fe) {
		return res, err
	}
	if cur.Size < prev.Size {
		// A source serving an older head usually cannot prove consistency
		// up to a tree it does not have; that is not evidence of a fork.
		res.Stale, res.StaleVerified = true, err == nil
		return res, nil
	}
	if err != nil {
		return res, err
	}
	return res, st.Save(cur)
}

// LoadEvidence reads evidence written by SaveEvidence.
func LoadEvidence(path string) (*Evidence, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("monitor: read evidence: %w", err)
	}
	var e Evidence
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("monitor: decode evidence: %w", err)
	}
	return &e, nil
}

// SaveEvidence writes evidence as indented JSON.
func SaveEvidence(path string, e *Evidence) error {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("monitor: encode evidence: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("monitor: write evidence: %w", err)
	}
	return nil
}

func short(h merkle.Hash) string { return h.String()[:16] + "…" }
