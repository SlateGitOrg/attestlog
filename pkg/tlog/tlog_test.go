package tlog_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SlateGitOrg/attestlog/internal/testutil"
	"github.com/SlateGitOrg/attestlog/pkg/dsse"
	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/merkle"
	"github.com/SlateGitOrg/attestlog/pkg/tlog"
)

func newLog(t *testing.T, store tlog.Store) *tlog.Log {
	t.Helper()
	l, err := tlog.New(store, testutil.LogSigner(t), tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestEntryCanonicalAndKeysNormalised(t *testing.T) {
	a, b := testutil.Signer(t, keys.Ed25519), testutil.Signer(t, keys.ECDSAP256)
	env := testutil.Envelope(t, "x", testutil.Builder, a, b)
	e1, err := tlog.NewEntry(env, a.Public(), b.Public(), a.Public())
	if err != nil {
		t.Fatal(err)
	}
	e2, _ := tlog.NewEntry(env, b.Public(), a.Public())
	h1, _ := e1.LeafHash()
	h2, _ := e2.LeafHash()
	if h1 != h2 || len(e1.Spec.PublicKeys) != 2 {
		t.Fatal("key order or duplicates changed the leaf hash")
	}
	body, _ := e1.Canonical()
	if _, err := tlog.ParseEntry(body); err != nil {
		t.Fatal(err)
	}
	// Re-indented JSON is semantically equal but not canonical.
	var v any
	_ = json.Unmarshal(body, &v)
	pretty, _ := json.MarshalIndent(v, "", " ")
	if _, err := tlog.ParseEntry(pretty); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Fatalf("non-canonical body accepted: %v", err)
	}
	ve, err := e1.Verify()
	if err != nil || len(ve.KeyIDs) != 2 {
		t.Fatalf("verify: %v", err)
	}
}

func TestEntryRejections(t *testing.T) {
	a, b := testutil.Signer(t, keys.Ed25519), testutil.Signer(t, keys.Ed25519)
	env := testutil.Envelope(t, "x", testutil.Builder, a)

	// A key that did not sign may not ride along.
	e, _ := tlog.NewEntry(env, a.Public(), b.Public())
	if _, err := e.Verify(); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Errorf("unrelated key accepted: %v", err)
	}
	// Wrong payload type.
	other, _ := dsse.Sign("application/json", []byte("{}"), a)
	e, _ = tlog.NewEntry(other, a.Public())
	if _, err := e.Verify(); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Errorf("non in-toto payload accepted: %v", err)
	}
	// Signed, right type, but not a statement.
	notStmt, _ := dsse.Sign("application/vnd.in-toto+json", []byte(`{"_type":"x"}`), a)
	e, _ = tlog.NewEntry(notStmt, a.Public())
	if _, err := e.Verify(); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Errorf("invalid statement accepted: %v", err)
	}
	if _, err := tlog.NewEntry(nil, a.Public()); err == nil {
		t.Error("nil envelope accepted")
	}
	if _, err := tlog.NewEntry(env); err == nil {
		t.Error("no keys accepted")
	}
	bad := &tlog.Entry{APIVersion: tlog.EntryAPIVersion, Kind: tlog.KindDSSE,
		Spec: tlog.DSSESpec{Envelope: *env, PublicKeys: []string{"junk"}}}
	if _, err := bad.Verify(); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Errorf("junk key accepted: %v", err)
	}
	bad.Spec.PublicKeys = nil
	if _, err := bad.Verify(); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Errorf("no keys accepted: %v", err)
	}
	for name, body := range map[string]string{
		"not json":     "{",
		"unknown kind": `{"apiVersion":"attestlog/v1","kind":"rekord","spec":{"envelope":{"payloadType":"","payload":"","signatures":null},"publicKeys":null}}`,
		"extra field":  `{"apiVersion":"attestlog/v1","kind":"dsse","extra":1}`,
		"too big":      strings.Repeat(" ", tlog.MaxEntrySize+1),
	} {
		if _, err := tlog.ParseEntry([]byte(body)); !errors.Is(err, tlog.ErrInvalidEntry) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAddProveSearch(t *testing.T) {
	l := newLog(t, tlog.NewMemoryStore())
	s := testutil.Signer(t, keys.Ed25519)
	if l.Size() != 0 || l.Head().Root != merkle.EmptyRoot() {
		t.Fatal("new log not empty")
	}
	var heads []merkle.Hash
	for i := range 9 {
		res, err := l.Add(testutil.EntryBody(t, fmt.Sprintf("artifact-%d", i), s))
		if err != nil {
			t.Fatal(err)
		}
		if res.Index != uint64(i) || res.Duplicate || res.Checkpoint.Size != uint64(i+1) {
			t.Fatalf("unexpected result %+v", res)
		}
		if err := merkle.VerifyInclusion(res.Index, res.Checkpoint.Size, res.LeafHash, res.Proof, res.Checkpoint.Root); err != nil {
			t.Fatalf("receipt proof: %v", err)
		}
		heads = append(heads, res.Checkpoint.Root)
	}
	// Duplicate submission returns the original index.
	res, err := l.Add(testutil.EntryBody(t, "artifact-3", s))
	if err != nil || !res.Duplicate || res.Index != 3 || l.Size() != 9 {
		// ECDSA would differ per signature; Ed25519 is deterministic.
		t.Fatalf("duplicate handling: %+v %v", res, err)
	}
	for size := uint64(1); size < 9; size++ {
		proof, err := l.ConsistencyProof(size, 9)
		if err != nil {
			t.Fatal(err)
		}
		if err := merkle.VerifyConsistency(size, 9, proof, heads[size-1], l.Head().Root); err != nil {
			t.Fatalf("consistency %d: %v", size, err)
		}
	}
	body, leaf, err := l.Entry(4)
	if err != nil || merkle.LeafHash(body) != leaf {
		t.Fatal("entry/leaf mismatch")
	}
	idx, proof, err := l.InclusionProofByHash(leaf, 9)
	if err != nil || idx != 4 || merkle.VerifyInclusion(4, 9, leaf, proof, l.Head().Root) != nil {
		t.Fatalf("by-hash proof: %v", err)
	}
	if _, _, err := l.InclusionProofByHash(leaf, 3); !errors.Is(err, tlog.ErrNotFound) {
		t.Errorf("leaf beyond size found: %v", err)
	}
	if _, _, err := l.Entry(99); !errors.Is(err, tlog.ErrNotFound) {
		t.Error("missing entry found")
	}
	if got := l.Search(testutil.Digest("artifact-7")); len(got) != 1 || got[0] != 7 {
		t.Fatalf("search = %v", got)
	}
	if got := l.Search(testutil.Digest("nope")); len(got) != 0 {
		t.Fatalf("search miss = %v", got)
	}
	if _, err := l.InclusionProof(0, 10); err == nil {
		t.Error("proof beyond size")
	}
	if _, err := l.Add([]byte("{}")); !errors.Is(err, tlog.ErrInvalidEntry) {
		t.Errorf("garbage added: %v", err)
	}
	if l.Origin() != testutil.Origin || l.Verifier().Name() != testutil.Origin {
		t.Error("origin mismatch")
	}
}

func TestFileStoreReplayAndTornTail(t *testing.T) {
	dir := t.TempDir()
	signer := testutil.LogSigner(t)
	s := testutil.Signer(t, keys.Ed25519)
	open := func() *tlog.Log {
		st, err := tlog.OpenFileStore(dir, nil)
		if err != nil {
			t.Fatal(err)
		}
		l, err := tlog.New(st, signer, tlog.Options{Now: func() time.Time { return time.Unix(1, 0) }})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	l := open()
	testutil.Populate(t, l, s, "persist", 5)
	root := l.Head().Root
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	l = open()
	if l.Size() != 5 || l.Head().Root != root {
		t.Fatalf("replay: size %d root %s", l.Size(), l.Head().Root)
	}
	if got := l.Search(testutil.Digest("persist-2")); len(got) != 1 || got[0] != 2 {
		t.Fatalf("index not rebuilt: %v", got)
	}
	_ = l.Close()

	// Simulate a crash mid-append: a partial record at the tail.
	path := filepath.Join(dir, "entries.log")
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.Write([]byte{0, 0, 1, 0, 'x', 'y'})
	_ = f.Close()
	l = open()
	if l.Size() != 5 || l.Head().Root != root {
		t.Fatal("torn tail not recovered")
	}
	testutil.Populate(t, l, s, "after-crash", 1)
	_ = l.Close()
	l = open()
	if l.Size() != 6 {
		t.Fatalf("size after recovery = %d", l.Size())
	}
	_ = l.Close()

	// Flip a byte inside a complete record: hard failure, never silent loss.
	data, _ := os.ReadFile(path)
	data[20] ^= 0xff
	_ = os.WriteFile(path, data, 0o600)
	st, _ := tlog.OpenFileStore(dir, nil)
	if _, err := tlog.New(st, signer, tlog.Options{}); !errors.Is(err, tlog.ErrCorruptStore) {
		t.Fatalf("corruption not detected: %v", err)
	}
	_ = st.Close()
}

func TestFileStoreErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := tlog.OpenFileStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(nil); err == nil {
		t.Error("empty record appended")
	}
	_ = st.Close()
	if err := os.WriteFile(filepath.Join(dir, "entries.log"), []byte{0, 0, 0, 0, 1, 2, 3, 4, 5}, 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ = tlog.OpenFileStore(dir, nil)
	if err := st.Load(func([]byte) error { return nil }); !errors.Is(err, tlog.ErrCorruptStore) {
		t.Errorf("zero-length record: %v", err)
	}
	_ = st.Close()
	blocker := filepath.Join(dir, "file")
	_ = os.WriteFile(blocker, nil, 0o600)
	if _, err := tlog.OpenFileStore(filepath.Join(blocker, "sub"), nil); err == nil {
		t.Error("store under a file opened")
	}
	if _, err := tlog.New(nil, nil, tlog.Options{}); err == nil {
		t.Error("nil store accepted")
	}
}

func TestReplayRejectsForeignBody(t *testing.T) {
	st := tlog.NewMemoryStore()
	_ = st.Append([]byte(`{"not":"an entry"}`))
	if _, err := tlog.New(st, testutil.LogSigner(t), tlog.Options{}); err == nil {
		t.Fatal("foreign body replayed")
	}
}

func TestConcurrentAddsAndProofs(t *testing.T) {
	l := newLog(t, tlog.NewMemoryStore())
	s := testutil.Signer(t, keys.Ed25519)
	bodies := make([][]byte, 32)
	for i := range bodies {
		bodies[i] = testutil.EntryBody(t, fmt.Sprintf("c-%d", i), s)
	}
	var wg sync.WaitGroup
	for i := range bodies {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := l.Add(bodies[i]); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			head := l.Head()
			if head.Size > 0 {
				leaf, _, _ := l.Entry(head.Size - 1)
				if _, err := l.InclusionProof(head.Size-1, head.Size); err != nil || leaf == nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if l.Size() != 32 {
		t.Fatalf("size = %d", l.Size())
	}
}

// BenchmarkAdd measures admission cost per entry: canonical parse, DSSE
// signature verification, statement parsing, append and checkpoint signing.
func BenchmarkAdd(b *testing.B) {
	for _, store := range []string{"memory", "file+fsync"} {
		b.Run(store, func(b *testing.B) {
			s := testutil.Signer(b, keys.Ed25519)
			var st tlog.Store = tlog.NewMemoryStore()
			if store != "memory" {
				fs, err := tlog.OpenFileStore(b.TempDir(), nil)
				if err != nil {
					b.Fatal(err)
				}
				st = fs
			}
			l, err := tlog.New(st, testutil.LogSigner(b), tlog.Options{})
			if err != nil {
				b.Fatal(err)
			}
			defer func() { _ = l.Close() }()
			bodies := make([][]byte, 0, 4096)
			for i := range cap(bodies) {
				bodies = append(bodies, testutil.EntryBody(b, fmt.Sprintf("bench-%d", i), s))
			}
			i := 0
			for b.Loop() {
				if i == len(bodies) {
					b.StopTimer()
					bodies = append(bodies, testutil.EntryBody(b, fmt.Sprintf("bench-%d", i), s))
					b.StartTimer()
				}
				if _, err := l.Add(bodies[i]); err != nil {
					b.Fatal(err)
				}
				i++
			}
		})
	}
}

// A failed append must not leave bytes that later appends follow: the
// review reproduced a torn write followed by an accepted Add that made the
// store unopenable, and an fsync failure that replayed an extra leaf.
func TestFileStoreFailedAppendRollsBack(t *testing.T) {
	signer := testutil.LogSigner(t)
	s := testutil.Signer(t, keys.Ed25519)
	cases := []struct {
		name   string
		inject func(*tlog.FileFaults)
	}{
		{"torn write (ENOSPC after 6 bytes)", func(f *tlog.FileFaults) { f.WriteFail, f.WritePartial = true, 6 }},
		{"full write then failed write call", func(f *tlog.FileFaults) { f.WriteFail, f.WritePartial = true, 1<<30 }},
		{"complete write, fsync fails", func(f *tlog.FileFaults) { f.SyncFailures = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "entries.log")
			ff := &tlog.FileFaults{}
			st, err := tlog.OpenFaultyFileStore(dir, nil, ff)
			if err != nil {
				t.Fatal(err)
			}
			l, err := tlog.New(st, signer, tlog.Options{})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Populate(t, l, s, "before", 1)
			info, _ := os.Stat(path)
			durable := info.Size()

			ff.Set(tc.inject)
			if _, err := l.Add(testutil.EntryBody(t, "failed", s)); err == nil {
				t.Fatal("append with injected fault succeeded")
			} else if errors.Is(err, tlog.ErrStoreFailed) {
				t.Fatalf("successful rollback reported as store failure: %v", err)
			}
			if info, _ := os.Stat(path); info.Size() != durable {
				t.Fatalf("leftover bytes after rollback: size %d, want %d", info.Size(), durable)
			}
			ff.Reset()

			// The store keeps working, and the next entry lands right after
			// the last durable record.
			res, err := l.Add(testutil.EntryBody(t, "after", s))
			if err != nil {
				t.Fatal(err)
			}
			if res.Index != 1 || l.Size() != 2 {
				t.Fatalf("index %d size %d after recovery", res.Index, l.Size())
			}
			signed := l.Head()
			_ = l.Close()

			st2, err := tlog.OpenFileStore(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			l2, err := tlog.New(st2, signer, tlog.Options{})
			if err != nil {
				t.Fatalf("reopen after rolled-back append: %v", err)
			}
			defer func() { _ = l2.Close() }()
			if l2.Size() != signed.Size || l2.Head().Root != signed.Root {
				t.Fatalf("replay forked: size %d root %s, signed size %d root %s",
					l2.Size(), l2.Head().Root, signed.Size, signed.Root)
			}
			if got := l2.Search(testutil.Digest("failed")); len(got) != 0 {
				t.Fatalf("failed entry replayed at %v", got)
			}
		})
	}
}

// If the rollback itself fails, the store must refuse every later append
// instead of writing after the leftover bytes.
func TestFileStoreLatchesWhenRollbackFails(t *testing.T) {
	signer := testutil.LogSigner(t)
	s := testutil.Signer(t, keys.Ed25519)
	cases := []struct {
		name   string
		inject func(*tlog.FileFaults)
	}{
		{"truncate fails", func(f *tlog.FileFaults) { f.WriteFail, f.WritePartial, f.TruncateFail = true, 6, true }},
		{"fsync after truncate fails", func(f *tlog.FileFaults) { f.WriteFail, f.WritePartial, f.SyncFailures = true, 6, 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			ff := &tlog.FileFaults{}
			st, err := tlog.OpenFaultyFileStore(dir, nil, ff)
			if err != nil {
				t.Fatal(err)
			}
			l, err := tlog.New(st, signer, tlog.Options{})
			if err != nil {
				t.Fatal(err)
			}
			testutil.Populate(t, l, s, "before", 1)
			root := l.Head().Root

			ff.Set(tc.inject)
			if _, err := l.Add(testutil.EntryBody(t, "failed", s)); !errors.Is(err, tlog.ErrStoreFailed) {
				t.Fatalf("want ErrStoreFailed, got %v", err)
			}
			ff.Reset()
			if _, err := l.Add(testutil.EntryBody(t, "after", s)); !errors.Is(err, tlog.ErrStoreFailed) {
				t.Fatalf("append after unrecoverable failure: %v", err)
			}
			if l.Size() != 1 || l.Head().Root != root {
				t.Fatalf("in-memory log moved: size %d", l.Size())
			}
			_ = l.Close()

			// Restart: replay truncates the torn tail and the log matches
			// what was signed.
			st2, err := tlog.OpenFileStore(dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			l2, err := tlog.New(st2, signer, tlog.Options{})
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer func() { _ = l2.Close() }()
			if l2.Size() != 1 || l2.Head().Root != root {
				t.Fatalf("replay after restart: size %d", l2.Size())
			}
		})
	}
}
