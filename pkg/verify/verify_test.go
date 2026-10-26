package verify_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SlateGitOrg/attestlog/internal/testutil"
	"github.com/SlateGitOrg/attestlog/pkg/api"
	"github.com/SlateGitOrg/attestlog/pkg/bundle"
	"github.com/SlateGitOrg/attestlog/pkg/dsse"
	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/note"
	"github.com/SlateGitOrg/attestlog/pkg/policy"
	"github.com/SlateGitOrg/attestlog/pkg/tlog"
	"github.com/SlateGitOrg/attestlog/pkg/verify"
)

func pol() *policy.Policy {
	return &policy.Policy{
		Version:             1,
		Builders:            []string{"https://ci.example.test/builder@*"},
		SourceRepos:         []string{testutil.Repo},
		SourceRefs:          []string{testutil.Ref},
		RequireSourceDigest: true,
	}
}

// logged submits env to a fresh log and returns a bundle with a receipt.
func logged(t *testing.T, env *dsse.Envelope, s keys.Signer) (*bundle.Bundle, *note.Verifier) {
	t.Helper()
	logSigner := testutil.LogSigner(t)
	l, err := tlog.New(tlog.NewMemoryStore(), logSigner, tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	testutil.Populate(t, l, s, "noise", 6)
	b, err := bundle.New(env, s.Public())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := b.Entry().Canonical()
	res, err := l.Add(body)
	if err != nil {
		t.Fatal(err)
	}
	b.Log = &bundle.LogReceipt{
		LogIndex:   res.Index,
		Checkpoint: string(res.Checkpoint.Raw),
		InclusionProof: api.InclusionProof{
			LogIndex: res.Index, TreeSize: res.Checkpoint.Size, Hashes: api.EncodeHashes(res.Proof),
		},
	}
	return b, l.Verifier()
}

func checkNames(r *verify.Result, passed bool) []string {
	var out []string
	for _, c := range r.Report.Checks {
		if c.Passed == passed {
			out = append(out, c.Name)
		}
	}
	return out
}

func TestEndToEndWithLogReceipt(t *testing.T) {
	for _, alg := range []keys.Algorithm{keys.Ed25519, keys.ECDSAP256} {
		t.Run(string(alg), func(t *testing.T) {
			s := testutil.Signer(t, alg)
			env := testutil.Envelope(t, "release.tar.gz", testutil.Builder, s)
			b, logKey := logged(t, env, s)

			// Bundles survive a disk round trip.
			path := filepath.Join(t.TempDir(), "b.json")
			raw, _ := b.Marshal()
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			b, err := bundle.Load(path)
			if err != nil {
				t.Fatal(err)
			}

			p := pol()
			p.RequireTransparencyLog = true
			res, err := verify.Verify(verify.Request{
				Envelope: &b.Envelope, TrustedKeys: []*keys.PublicKey{s.Public()},
				ArtifactDigest: testutil.Digest("release.tar.gz"), Policy: p, Bundle: b, LogKey: logKey,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Passed() {
				t.Fatalf("failed: %v", checkNames(res, false))
			}
			if res.Checkpoint == nil || res.Checkpoint.Size != 7 || len(res.SignerKeyIDs) != 1 {
				t.Fatalf("result = %+v", res)
			}
		})
	}
}

func TestTamperedArtifactAndReceipt(t *testing.T) {
	s := testutil.Signer(t, keys.Ed25519)
	env := testutil.Envelope(t, "app", testutil.Builder, s)
	b, logKey := logged(t, env, s)
	base := verify.Request{
		Envelope: env, TrustedKeys: []*keys.PublicKey{s.Public()},
		ArtifactDigest: testutil.Digest("app"), Policy: pol(), Bundle: b, LogKey: logKey,
	}

	r := base
	r.ArtifactDigest = testutil.Digest("app-backdoored")
	res, _ := verify.Verify(r)
	if res.Passed() || strings.Join(checkNames(res, false), ",") != "subject-digest" {
		t.Fatalf("tampered artifact: %v", checkNames(res, false))
	}

	// Receipt proof edited.
	tampered := *b
	receipt := *b.Log
	receipt.InclusionProof.Hashes = append([]string{strings.Repeat("0", 64)}, receipt.InclusionProof.Hashes[1:]...)
	tampered.Log = &receipt
	r = base
	r.Bundle = &tampered
	res, _ = verify.Verify(r)
	if res.Passed() || strings.Join(checkNames(res, false), ",") != "transparency-log" {
		t.Fatalf("tampered receipt: %v", checkNames(res, false))
	}

	// Receipt verified under the wrong log key.
	r = base
	r.LogKey = testutil.LogSigner(t).Verifier()
	if res, _ := verify.Verify(r); res.Passed() {
		t.Fatal("receipt accepted under wrong log key")
	}
	r.LogKey = nil
	if res, _ := verify.Verify(r); res.Passed() {
		t.Fatal("receipt accepted without a log key")
	}

	// Bundle for a different envelope.
	other := testutil.Envelope(t, "other", testutil.Builder, s)
	r = base
	r.Envelope = other
	r.ArtifactDigest = testutil.Digest("other")
	if res, _ := verify.Verify(r); res.Passed() {
		t.Fatal("mismatched bundle accepted")
	}
}

func TestUntrustedSignerNeverEvaluated(t *testing.T) {
	attacker := testutil.Signer(t, keys.Ed25519)
	trusted := testutil.Signer(t, keys.Ed25519)
	env := testutil.Envelope(t, "app", testutil.Builder, attacker)
	res, err := verify.Verify(verify.Request{
		Envelope: env, TrustedKeys: []*keys.PublicKey{trusted.Public()},
		ArtifactDigest: testutil.Digest("app"), Policy: pol(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Passed() || res.Statement != nil || len(res.Report.Checks) != 1 || res.Report.Checks[0].Name != "signature" {
		t.Fatalf("unauthenticated payload was evaluated: %+v", res.Report)
	}
}

func TestPayloadTypeAndStatementChecks(t *testing.T) {
	s := testutil.Signer(t, keys.Ed25519)
	wrongType, _ := dsse.Sign("application/json", []byte("{}"), s)
	res, _ := verify.Verify(verify.Request{Envelope: wrongType, TrustedKeys: []*keys.PublicKey{s.Public()}, Policy: pol()})
	if res.Passed() || res.Report.Checks[0].Name != "payload-type" {
		t.Fatalf("payload type: %+v", res.Report)
	}
	badStmt, _ := dsse.Sign("application/vnd.in-toto+json", []byte(`{"_type":"nope"}`), s)
	res, _ = verify.Verify(verify.Request{Envelope: badStmt, TrustedKeys: []*keys.PublicKey{s.Public()}, Policy: pol()})
	if res.Passed() || res.Report.Checks[0].Name != "statement" {
		t.Fatalf("statement: %+v", res.Report)
	}
}

func TestDisallowedBuilderAndThreshold(t *testing.T) {
	a, b := testutil.Signer(t, keys.Ed25519), testutil.Signer(t, keys.ECDSAP256)
	env := testutil.Envelope(t, "app", "https://rogue.example.test/builder", a)
	res, _ := verify.Verify(verify.Request{
		Envelope: env, TrustedKeys: []*keys.PublicKey{a.Public()},
		ArtifactDigest: testutil.Digest("app"), Policy: pol(),
	})
	if strings.Join(checkNames(res, false), ",") != "builder-id" {
		t.Fatalf("rogue builder: %v", checkNames(res, false))
	}

	p := pol()
	p.SignatureThreshold = 2
	env = testutil.Envelope(t, "app", testutil.Builder, a, b)
	req := verify.Request{
		Envelope: env, TrustedKeys: []*keys.PublicKey{a.Public(), b.Public()},
		ArtifactDigest: testutil.Digest("app"), Policy: p,
	}
	if res, _ := verify.Verify(req); !res.Passed() {
		t.Fatalf("2-of-2: %v", checkNames(res, false))
	}
	req.TrustedKeys = []*keys.PublicKey{a.Public()}
	if res, _ := verify.Verify(req); res.Passed() {
		t.Fatal("threshold 2 met with one trusted key")
	}
}

func TestRequestValidation(t *testing.T) {
	s := testutil.Signer(t, keys.Ed25519)
	env := testutil.Envelope(t, "app", testutil.Builder, s)
	keysOK := []*keys.PublicKey{s.Public()}
	cases := map[string]verify.Request{
		"no envelope": {TrustedKeys: keysOK, Policy: pol()},
		"no policy":   {Envelope: env, TrustedKeys: keysOK},
		"bad policy":  {Envelope: env, TrustedKeys: keysOK, Policy: &policy.Policy{Version: 1}},
		"no keys":     {Envelope: env, Policy: pol()},
	}
	for name, req := range cases {
		if _, err := verify.Verify(req); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBundleParsing(t *testing.T) {
	s := testutil.Signer(t, keys.Ed25519)
	env := testutil.Envelope(t, "app", testutil.Builder, s)
	b, err := bundle.New(env, s.Public())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.VerifyInclusion(testutil.LogSigner(t).Verifier()); !errors.Is(err, bundle.ErrNoLogProof) {
		t.Fatalf("no receipt: %v", err)
	}
	ks, err := b.Keys()
	if err != nil || len(ks) != 1 {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"not json":     "{",
		"wrong media":  `{"mediaType":"x"}`,
		"bad envelope": `{"mediaType":"` + bundle.MediaType + `","envelope":{}}`,
	} {
		if _, err := bundle.Parse([]byte(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := bundle.Load(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file loaded")
	}
	if _, err := bundle.New(nil); err == nil {
		t.Error("nil envelope bundled")
	}

	lb, logKey := logged(t, env, s)
	mismatch := *lb
	r := *lb.Log
	r.InclusionProof.TreeSize++
	mismatch.Log = &r
	if _, err := mismatch.VerifyInclusion(logKey); err == nil {
		t.Error("size mismatch accepted")
	}
	r = *lb.Log
	r.InclusionProof.Hashes = []string{"zz"}
	mismatch.Log = &r
	if _, err := mismatch.VerifyInclusion(logKey); err == nil {
		t.Error("bad hex accepted")
	}
}
