package monitor_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SlateGitOrg/attestlog/internal/testutil"
	"github.com/SlateGitOrg/attestlog/pkg/checkpoint"
	"github.com/SlateGitOrg/attestlog/pkg/client"
	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/merkle"
	"github.com/SlateGitOrg/attestlog/pkg/monitor"
	"github.com/SlateGitOrg/attestlog/pkg/note"
	"github.com/SlateGitOrg/attestlog/pkg/server"
	"github.com/SlateGitOrg/attestlog/pkg/tlog"
)

// operator simulates one log operator key serving one or more views. A
// malicious operator serves different histories to different clients, each
// signed with the same key — exactly the attack consistency proofs and
// gossip exist to catch.
type operator struct {
	key    *note.Signer
	signer keys.Signer
	tick   int64
}

func newOperator(t *testing.T) *operator {
	return &operator{key: testutil.LogSigner(t), signer: testutil.Signer(t, keys.Ed25519)}
}

// now is a strictly increasing clock shared by all of the operator's views.
func (o *operator) now() time.Time {
	o.tick++
	return time.Unix(1_700_000_000, 0).Add(time.Duration(o.tick) * time.Second)
}

// view starts a log + HTTP server for one history.
func (o *operator) view(t *testing.T, contents ...string) (*tlog.Log, *client.Client) {
	t.Helper()
	l, err := tlog.New(tlog.NewMemoryStore(), o.key, tlog.Options{Now: o.now})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range contents {
		if _, err := l.Add(testutil.EntryBody(t, c, o.signer)); err != nil {
			t.Fatal(err)
		}
	}
	srv := httptest.NewServer(server.New(l, nil))
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, o.key.Verifier(), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func (o *operator) add(t *testing.T, l *tlog.Log, contents ...string) {
	t.Helper()
	for _, c := range contents {
		if _, err := l.Add(testutil.EntryBody(t, c, o.signer)); err != nil {
			t.Fatal(err)
		}
	}
}

func asFork(t *testing.T, err error) *monitor.Evidence {
	t.Helper()
	var fe *monitor.ForkError
	if !errors.As(err, &fe) {
		t.Fatalf("expected ForkError, got %v", err)
	}
	if fe.Error() == "" {
		t.Fatal("empty error text")
	}
	return fe.Evidence
}

func TestHonestGrowthAdvancesState(t *testing.T) {
	ctx := context.Background()
	op := newOperator(t)
	l, c := op.view(t, "a", "b")
	st := monitor.NewState(filepath.Join(t.TempDir(), "state", "trusted.checkpoint"))

	res, err := monitor.Update(ctx, st, c)
	if err != nil || !res.FirstUse || res.Current.Size != 2 {
		t.Fatalf("first use: %+v %v", res, err)
	}
	op.add(t, l, "c", "d", "e")
	res, err = monitor.Update(ctx, st, c)
	if err != nil || res.FirstUse || res.Previous.Size != 2 || res.Current.Size != 5 {
		t.Fatalf("growth: %+v %v", res, err)
	}
	// No growth is fine too.
	if _, err := monitor.Update(ctx, st, c); err != nil {
		t.Fatal(err)
	}
	saved, err := st.Load(c.LogKey())
	if err != nil || saved.Size != 5 {
		t.Fatalf("saved state: %v", err)
	}
}

func TestEquivocationDetectedViaGossip(t *testing.T) {
	ctx := context.Background()
	op := newOperator(t)
	// Same size, different last entry: a split view.
	_, alice := op.view(t, "a", "b", "c")
	_, bob := op.view(t, "a", "b", "evil")
	ca, _ := alice.Checkpoint(ctx)
	cb, _ := bob.Checkpoint(ctx)

	ev := asFork(t, monitor.Compare(ctx, ca, cb, nil))
	if ev.Kind != monitor.KindEquivocation {
		t.Fatalf("kind = %s", ev.Kind)
	}
	// The evidence is self-contained and transferable.
	if err := monitor.VerifyEvidence(ev, op.key.Verifier()); err != nil {
		t.Fatalf("evidence does not verify: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence.json")
	if err := monitor.SaveEvidence(path, ev); err != nil {
		t.Fatal(err)
	}
	loaded, err := monitor.LoadEvidence(path)
	if err != nil || monitor.VerifyEvidence(loaded, op.key.Verifier()) != nil {
		t.Fatalf("reloaded evidence: %v", err)
	}
	// A stranger's key cannot validate it.
	other := testutil.LogSigner(t)
	if monitor.VerifyEvidence(loaded, other.Verifier()) == nil {
		t.Fatal("evidence verified under the wrong key")
	}
}

func TestForkDetectedOnUpdate(t *testing.T) {
	ctx := context.Background()
	op := newOperator(t)
	honest, honestClient := op.view(t, "a", "b", "c")
	st := monitor.NewState(filepath.Join(t.TempDir(), "trusted"))
	if _, err := monitor.Update(ctx, st, honestClient); err != nil {
		t.Fatal(err)
	}
	// The operator rewrites history (drops "c") and grows past the client.
	_, forked := op.view(t, "a", "b", "x", "y", "z")
	_, err := monitor.Update(ctx, st, forked)
	ev := asFork(t, err)
	if ev.Kind != monitor.KindInconsistent || len(ev.Proof) == 0 {
		t.Fatalf("evidence = %+v", ev)
	}
	if err := monitor.VerifyEvidence(ev, op.key.Verifier()); err != nil {
		t.Fatalf("inconsistency evidence: %v", err)
	}
	// State is untouched by a detected fork.
	saved, _ := st.Load(op.key.Verifier())
	if saved.Size != 3 || saved.Root != honest.Head().Root {
		t.Fatal("trusted state advanced past a fork")
	}
}

// staleSource serves a fixed old checkpoint but real proofs.
type staleSource struct {
	*client.Client
	head *checkpoint.Signed
}

func (s staleSource) Checkpoint(context.Context) (*checkpoint.Signed, error) { return s.head, nil }

func TestRollbackAndStaleViews(t *testing.T) {
	ctx := context.Background()
	op := newOperator(t)
	l, c := op.view(t, "a", "b")
	st := monitor.NewState(filepath.Join(t.TempDir(), "trusted"))
	_, _ = monitor.Update(ctx, st, c)
	old, _ := c.Checkpoint(ctx)
	op.add(t, l, "c", "d")
	if _, err := monitor.Update(ctx, st, c); err != nil {
		t.Fatal(err)
	}

	// A cache replaying the genuine older head: stale, provably consistent.
	res, err := monitor.Update(ctx, st, staleSource{Client: c, head: old})
	if err != nil || !res.Stale || !res.StaleVerified {
		t.Fatalf("stale cache: %+v %v", res, err)
	}
	// Same old head from a source that cannot prove anything: still only stale.
	_, replica := op.view(t)
	res, err = monitor.Update(ctx, st, staleSource{Client: replica, head: old})
	if err != nil || !res.Stale || res.StaleVerified {
		t.Fatalf("unprovable stale head: %+v %v", res, err)
	}

	// The operator signs a smaller, different tree *later*: rollback.
	_, rolled := op.view(t, "a", "q")
	_, err = monitor.Update(ctx, st, rolled)
	ev := asFork(t, err)
	if ev.Kind != monitor.KindRollback {
		t.Fatalf("kind = %s", ev.Kind)
	}
	if err := monitor.VerifyEvidence(ev, op.key.Verifier()); err != nil {
		t.Fatalf("rollback evidence: %v", err)
	}
	// Even an honest-looking prefix re-signed later is a rollback.
	_, prefix := op.view(t, "a", "b")
	_, err = monitor.Update(ctx, st, prefix)
	if ev := asFork(t, err); ev.Kind != monitor.KindRollback {
		t.Fatalf("kind = %s", ev.Kind)
	}
	saved, _ := st.Load(op.key.Verifier())
	if saved.Size != 4 {
		t.Fatal("state moved after rollback")
	}
}

func TestCompareEdgeCases(t *testing.T) {
	ctx := context.Background()
	op := newOperator(t)
	l, c := op.view(t)
	empty := l.Head()
	op.add(t, l, "a")
	one := l.Head()
	if err := monitor.Compare(ctx, empty, one, nil); err != nil {
		t.Fatalf("empty -> one: %v", err)
	}
	if err := monitor.Compare(ctx, one, one, nil); err != nil {
		t.Fatal(err)
	}
	op.add(t, l, "b")
	two := l.Head()
	if err := monitor.Compare(ctx, one, two, nil); err == nil {
		t.Fatal("different sizes compared without prover")
	}
	if err := monitor.Compare(ctx, two, one, c); err != nil {
		t.Fatalf("argument order should not matter: %v", err)
	}

	// A signed empty checkpoint with a non-empty root is misbehaviour.
	bad, _ := checkpoint.Sign(&checkpoint.Checkpoint{Origin: testutil.Origin, Size: 0, Root: merkle.LeafHash([]byte("x"))}, op.key)
	ev := asFork(t, monitor.Compare(ctx, bad, two, c))
	if monitor.VerifyEvidence(ev, op.key.Verifier()) != nil {
		t.Fatal("bad-empty evidence should verify")
	}

	otherKey := testutil.LogSigner(t)
	otherOrigin, _ := checkpoint.Sign(&checkpoint.Checkpoint{Origin: otherKey.Name() + ".other", Size: 1}, mustSigner(t, otherKey.Name()+".other"))
	if err := monitor.Compare(ctx, one, otherOrigin, c); !errors.Is(err, monitor.ErrDifferentLogs) {
		t.Fatalf("different logs: %v", err)
	}
}

func mustSigner(t *testing.T, name string) *note.Signer {
	t.Helper()
	skey, _, err := note.GenerateKey(nil, name)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := note.NewSigner(skey)
	return s
}

func TestVerifyEvidenceRejectsBogusClaims(t *testing.T) {
	op := newOperator(t)
	l, _ := op.view(t, "a", "b", "c")
	h3 := string(l.Head().Raw)
	op.add(t, l, "d")
	h4 := string(l.Head().Raw)
	proof, _ := l.ConsistencyProof(3, 4)
	v := op.key.Verifier()

	cases := map[string]*monitor.Evidence{
		"equivocation, same head":   {Kind: monitor.KindEquivocation, CheckpointA: h3, CheckpointB: h3},
		"equivocation, diff sizes":  {Kind: monitor.KindEquivocation, CheckpointA: h3, CheckpointB: h4},
		"inconsistent, valid proof": {Kind: monitor.KindInconsistent, CheckpointA: h4, CheckpointB: h3, Proof: hexes(proof)},
		"unknown kind":              {Kind: "other", CheckpointA: h3, CheckpointB: h4},
		"rollback, normal growth":   {Kind: monitor.KindRollback, CheckpointA: h3, CheckpointB: h4},
		"unsigned A":                {Kind: monitor.KindEquivocation, CheckpointA: "junk", CheckpointB: h4},
		"unsigned B":                {Kind: monitor.KindEquivocation, CheckpointA: h3, CheckpointB: "junk"},
		"bad proof hex":             {Kind: monitor.KindInconsistent, CheckpointA: h3, CheckpointB: h4, Proof: []string{"zz"}},
	}
	for name, ev := range cases {
		if monitor.VerifyEvidence(ev, v) == nil {
			t.Errorf("%s: bogus evidence verified", name)
		}
	}
	emptyHead, _ := checkpoint.Sign(&checkpoint.Checkpoint{Origin: testutil.Origin, Root: merkle.EmptyRoot()}, op.key)
	ev := &monitor.Evidence{Kind: monitor.KindInconsistent, CheckpointA: string(emptyHead.Raw), CheckpointB: h4}
	if monitor.VerifyEvidence(ev, v) == nil {
		t.Error("empty tree cannot be inconsistent")
	}
}

func hexes(hs []merkle.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.String()
	}
	return out
}

func TestStateErrors(t *testing.T) {
	dir := t.TempDir()
	v := testutil.LogSigner(t).Verifier()
	bad := filepath.Join(dir, "bad")
	_ = os.WriteFile(bad, []byte("not a checkpoint"), 0o600)
	if _, err := monitor.NewState(bad).Load(v); err == nil {
		t.Error("garbage state loaded")
	}
	if _, err := monitor.NewState(dir).Load(v); err == nil {
		t.Error("directory loaded as state")
	}
	blocker := filepath.Join(dir, "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	cp := &checkpoint.Signed{Raw: []byte("x")}
	if err := monitor.NewState(filepath.Join(blocker, "sub", "state")).Save(cp); err == nil {
		t.Error("state saved under a file")
	}
	if _, err := monitor.LoadEvidence(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing evidence loaded")
	}
	if _, err := monitor.LoadEvidence(bad); err == nil {
		t.Error("garbage evidence loaded")
	}
	if err := monitor.SaveEvidence(filepath.Join(blocker, "x"), &monitor.Evidence{}); err == nil {
		t.Error("evidence saved under a file")
	}
}
