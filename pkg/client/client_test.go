package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/archit2501/attestlog/internal/testutil"
	"github.com/archit2501/attestlog/pkg/api"
	"github.com/archit2501/attestlog/pkg/client"
	"github.com/archit2501/attestlog/pkg/keys"
	"github.com/archit2501/attestlog/pkg/merkle"
	"github.com/archit2501/attestlog/pkg/note"
	"github.com/archit2501/attestlog/pkg/server"
	"github.com/archit2501/attestlog/pkg/tlog"
)

type fixture struct {
	log    *tlog.Log
	srv    *httptest.Server
	client *client.Client
	signer keys.Signer
}

func newFixture(t *testing.T, wrap func(http.Handler) http.Handler) *fixture {
	t.Helper()
	l, err := tlog.New(tlog.NewMemoryStore(), testutil.LogSigner(t), tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler = server.New(l, nil)
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := client.New(srv.URL, l.Verifier(), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{log: l, srv: srv, client: c, signer: testutil.Signer(t, keys.ECDSAP256)}
}

func TestSubmitEntryProveRoundTrip(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	var lastLeaf merkle.Hash
	for i := range 5 {
		env := testutil.Envelope(t, fmt.Sprintf("a-%d", i), testutil.Builder, f.signer)
		b, dup, err := f.client.Submit(ctx, env, f.signer.Public())
		if err != nil {
			t.Fatal(err)
		}
		if dup || b.Log.LogIndex != uint64(i) {
			t.Fatalf("receipt %+v dup=%v", b.Log, dup)
		}
		body, _ := b.Entry().Canonical()
		lastLeaf = merkle.LeafHash(body)

		// Resubmitting the same envelope is idempotent.
		_, dup, err = f.client.Submit(ctx, env, f.signer.Public())
		if err != nil || !dup {
			t.Fatalf("resubmit: dup=%v err=%v", dup, err)
		}
	}
	cp, err := f.client.Checkpoint(ctx)
	if err != nil || cp.Size != 5 {
		t.Fatalf("checkpoint: %v", err)
	}
	e, leaf, err := f.client.Entry(ctx, 4)
	if err != nil || leaf != lastLeaf || e.Kind != tlog.KindDSSE {
		t.Fatalf("entry: %v", err)
	}
	if _, err := f.client.VerifyInclusion(ctx, 4, leaf, cp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.VerifyInclusion(ctx, 3, leaf, cp); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("wrong index accepted: %v", err)
	}
	proof, err := f.client.ConsistencyProof(ctx, 2, 5)
	if err != nil || len(proof) == 0 {
		t.Fatal(err)
	}
	idx, err := f.client.Search(ctx, testutil.Digest("a-2"))
	if err != nil || len(idx) != 1 || idx[0] != 2 {
		t.Fatalf("search: %v %v", idx, err)
	}
}

func TestServerErrorsSurface(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	if _, _, err := f.client.Entry(ctx, 0); !errors.Is(err, client.ErrServer) {
		t.Errorf("missing entry: %v", err)
	}
	if _, err := f.client.InclusionProof(ctx, 0, 1); !errors.Is(err, client.ErrServer) {
		t.Errorf("proof beyond size: %v", err)
	}
	if _, err := f.client.ConsistencyProof(ctx, 0, 0); !errors.Is(err, client.ErrServer) {
		t.Errorf("empty consistency: %v", err)
	}
	// Unsigned key in submit -> 400.
	other := testutil.Signer(t, keys.Ed25519)
	env := testutil.Envelope(t, "x", testutil.Builder, f.signer)
	if _, _, err := f.client.Submit(ctx, env, other.Public()); !errors.Is(err, client.ErrServer) {
		t.Errorf("unsigned key submit: %v", err)
	}
}

func TestRawHTTPValidation(t *testing.T) {
	f := newFixture(t, nil)
	get := func(path string) int {
		resp, err := f.srv.Client().Get(f.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	cases := map[string]int{
		api.PathHealth:                     200,
		api.PathPublicKey:                  200,
		api.PathCheckpoint:                 200,
		api.PathEntries + "/abc":           400,
		api.PathEntries + "?subject=bogus": 400,
		api.PathEntries + "?subject=sha256:" + strings.Repeat("a", 64): 200,
		api.PathInclusion:                                                     400,
		api.PathInclusion + "?treeSize=1":                                     400,
		api.PathInclusion + "?treeSize=1&leafHash=zz":                         400,
		api.PathInclusion + "?treeSize=0&leafHash=" + strings.Repeat("a", 64): 404,
		api.PathInclusion + "?treeSize=x&index=0":                             400,
		api.PathConsistency + "?from=1":                                       400,
		api.PathConsistency + "?to=1":                                         400,
		api.PathConsistency + "?from=2&to=1":                                  400,
		"/nope":                                                               404,
	}
	for path, want := range cases {
		if got := get(path); got != want {
			t.Errorf("GET %s = %d, want %d", path, got, want)
		}
	}
	post := func(body string) int {
		resp, err := f.srv.Client().Post(f.srv.URL+api.PathEntries, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := post("{"); got != 400 {
		t.Errorf("bad JSON = %d", got)
	}
	if got := post(`{"publicKeys":["junk"]}`); got != 400 {
		t.Errorf("bad key = %d", got)
	}
	if got := post(`{"publicKeys":[]}`); got != 400 {
		t.Errorf("no keys = %d", got)
	}
	if got := post(strings.Repeat("a", api.MaxRequestBodyKB<<10+10)); got != 413 {
		t.Errorf("oversized = %d", got)
	}
	resp, _ := f.srv.Client().Get(f.srv.URL + api.PathPublicKey)
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if _, err := note.NewVerifier(string(data)); err != nil {
		t.Errorf("published key does not parse: %v", err)
	}
}

// tamper rewrites JSON responses on one path to simulate a lying server.
func tamper(path string, fn func(map[string]any)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			var m map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes())
				return
			}
			fn(m)
			out, _ := json.Marshal(m)
			w.WriteHeader(rec.Code)
			_, _ = w.Write(out)
		})
	}
}

func flipFirstHash(m map[string]any, field string) {
	switch v := m[field].(type) {
	case []any:
		if len(v) > 0 {
			s := v[0].(string)
			v[0] = strings.Repeat("0", 2) + s[2:]
		}
	case map[string]any:
		flipFirstHash(v, "hashes")
	}
}

func TestLyingServerDetected(t *testing.T) {
	ctx := context.Background()

	// Bad receipt proof at submission time.
	f := newFixture(t, tamper(api.PathEntries, func(m map[string]any) { flipFirstHash(m, "inclusionProof") }))
	env1 := testutil.Envelope(t, "one", testutil.Builder, f.signer)
	env2 := testutil.Envelope(t, "two", testutil.Builder, f.signer)
	if _, _, err := f.client.Submit(ctx, env1, f.signer.Public()); err != nil {
		t.Fatalf("size-1 tree has empty proof, nothing to tamper: %v", err)
	}
	if _, _, err := f.client.Submit(ctx, env2, f.signer.Public()); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("tampered receipt accepted: %v", err)
	}

	// Bad inclusion proof on audit.
	f = newFixture(t, tamper(api.PathInclusion, func(m map[string]any) { flipFirstHash(m, "hashes") }))
	testutil.Populate(t, f.log, f.signer, "x", 4)
	cp, _ := f.client.Checkpoint(ctx)
	_, leaf, _ := f.client.Entry(ctx, 1)
	if _, err := f.client.VerifyInclusion(ctx, 1, leaf, cp); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("tampered audit path accepted: %v", err)
	}

	// Entry body that does not hash to the claimed leaf.
	f = newFixture(t, tamper(api.PathEntries+"/0", func(m map[string]any) { m["leafHash"] = strings.Repeat("0", 64) }))
	testutil.Populate(t, f.log, f.signer, "y", 1)
	if _, _, err := f.client.Entry(ctx, 0); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("leaf mismatch accepted: %v", err)
	}

	// Proof for the wrong sizes.
	f = newFixture(t, tamper(api.PathConsistency, func(m map[string]any) { m["to"] = 99 }))
	testutil.Populate(t, f.log, f.signer, "z", 3)
	if _, err := f.client.ConsistencyProof(ctx, 1, 3); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("mislabelled proof accepted: %v", err)
	}
	f = newFixture(t, tamper(api.PathInclusion, func(m map[string]any) { m["treeSize"] = 99 }))
	testutil.Populate(t, f.log, f.signer, "w", 3)
	if _, err := f.client.InclusionProof(ctx, 1, 3); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("mislabelled inclusion proof accepted: %v", err)
	}
}

func TestCheckpointFromWrongKeyRejected(t *testing.T) {
	f := newFixture(t, nil)
	_, vkey, _ := note.GenerateKey(nil, testutil.Origin)
	impostor, _ := note.NewVerifier(vkey)
	c, _ := client.New(f.srv.URL, impostor, nil)
	if _, err := c.Checkpoint(context.Background()); !errors.Is(err, client.ErrMisbehaviour) {
		t.Fatalf("checkpoint under wrong key accepted: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	v := testutil.LogSigner(t).Verifier()
	for _, u := range []string{"", "ftp://x", "http://", "::"} {
		if _, err := client.New(u, v, nil); err == nil {
			t.Errorf("URL %q accepted", u)
		}
	}
	if _, err := client.New("http://localhost", nil, nil); err == nil {
		t.Error("nil key accepted")
	}
}

func TestOversizedAndUnreachable(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.Copy(w, bytes.NewReader(make([]byte, 5<<20)))
	}))
	defer big.Close()
	v := testutil.LogSigner(t).Verifier()
	c, _ := client.New(big.URL, v, nil)
	if _, err := c.Checkpoint(context.Background()); err == nil {
		t.Error("oversized response accepted")
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer plain.Close()
	c, _ = client.New(plain.URL, v, nil)
	if _, err := c.Checkpoint(context.Background()); !errors.Is(err, client.ErrServer) {
		t.Errorf("non-JSON error: %v", err)
	}
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer notJSON.Close()
	c, _ = client.New(notJSON.URL, v, nil)
	if _, err := c.Search(context.Background(), testutil.Digest("x")); err == nil {
		t.Error("non-JSON body decoded")
	}
	big.Close()
	c, _ = client.New(big.URL, v, nil)
	if _, err := c.Checkpoint(context.Background()); err == nil {
		t.Error("closed server reachable")
	}
}
