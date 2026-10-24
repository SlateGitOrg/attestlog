package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/archit2501/attestlog/pkg/intoto"
	"github.com/archit2501/attestlog/pkg/slsa"
)

var (
	artifact = intoto.DigestSet{"sha256": strings.Repeat("a", 64)}
	commit   = strings.Repeat("c", 40)
)

func statement(t *testing.T, builder, repo, ref string) *intoto.Statement {
	t.Helper()
	p, err := slsa.New(slsa.Options{
		BuilderID: builder, SourceURI: repo, SourceRef: ref,
		SourceDigest: intoto.DigestSet{"gitCommit": commit},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := intoto.NewStatement([]intoto.ResourceDescriptor{{Name: "app.tar", Digest: artifact}}, slsa.PredicateType, p)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func basePolicy() *Policy {
	return &Policy{
		Version:             1,
		Builders:            []string{"https://ci.example.test/builder@*"},
		SourceRepos:         []string{"git+https://git.example.test/acme/app"},
		SourceRefs:          []string{"refs/heads/main"},
		BuildTypes:          []string{slsa.GenericBuildType},
		RequireSourceDigest: true,
	}
}

func failedNames(r *Report) []string {
	var out []string
	for _, c := range r.Failed() {
		out = append(out, c.Name)
	}
	return out
}

func TestEvaluatePasses(t *testing.T) {
	p := basePolicy()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	st := statement(t, "https://ci.example.test/builder@v2.1", "git+https://git.example.test/acme/app", "refs/heads/main")
	r := p.Evaluate(Input{Statement: st, ArtifactDigest: artifact, SignerKeyIDs: []string{"k1"}})
	if !r.Passed {
		t.Fatalf("expected pass, failures: %v", r.Failed())
	}
	if len(r.Checks) < 8 {
		t.Fatalf("expected every rule reported, got %d checks", len(r.Checks))
	}
}

func TestEvaluateFailures(t *testing.T) {
	good := func() Input {
		return Input{
			Statement:      statement(t, "https://ci.example.test/builder@v2", "git+https://git.example.test/acme/app", "refs/heads/main"),
			ArtifactDigest: artifact,
			SignerKeyIDs:   []string{"k1"},
		}
	}
	cases := []struct {
		name   string
		mutate func(*Input, *Policy)
		want   string
	}{
		{"wrong builder", func(in *Input, _ *Policy) {
			in.Statement = statement(t, "https://evil.example.test/builder", "git+https://git.example.test/acme/app", "refs/heads/main")
		}, "builder-id"},
		{"builder prefix lookalike", func(in *Input, _ *Policy) {
			in.Statement = statement(t, "https://ci.example.test/builder-evil@v1", "git+https://git.example.test/acme/app", "refs/heads/main")
		}, "builder-id"},
		{"wrong repo", func(in *Input, _ *Policy) {
			in.Statement = statement(t, "https://ci.example.test/builder@v2", "git+https://git.example.test/acme/app-fork", "refs/heads/main")
		}, "source-repo"},
		{"wrong ref", func(in *Input, _ *Policy) {
			in.Statement = statement(t, "https://ci.example.test/builder@v2", "git+https://git.example.test/acme/app", "refs/heads/dev")
		}, "source-ref"},
		{"digest mismatch", func(in *Input, _ *Policy) {
			in.ArtifactDigest = intoto.DigestSet{"sha256": strings.Repeat("b", 64)}
		}, "subject-digest"},
		{"no digest", func(in *Input, _ *Policy) { in.ArtifactDigest = nil }, "subject-digest"},
		{"too few signers", func(_ *Input, p *Policy) { p.SignatureThreshold = 2 }, "signature-threshold"},
		{"wrong build type", func(_ *Input, p *Policy) { p.BuildTypes = []string{"https://other"} }, "build-type"},
		{"log required", func(_ *Input, p *Policy) { p.RequireTransparencyLog = true }, "transparency-log"},
		{"log failed", func(in *Input, _ *Policy) {
			in.TransparencyLog = &LogEvidence{Verified: false, Err: "root mismatch"}
		}, "transparency-log"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in, p := good(), basePolicy()
			c.mutate(&in, p)
			r := p.Evaluate(in)
			if r.Passed {
				t.Fatal("expected failure")
			}
			if got := failedNames(r); len(got) != 1 || got[0] != c.want {
				t.Fatalf("failed checks = %v, want [%s]", got, c.want)
			}
		})
	}
}

func TestEvaluateNonProvenanceAndMissingSource(t *testing.T) {
	p := basePolicy()
	st, _ := intoto.NewStatement([]intoto.ResourceDescriptor{{Digest: artifact}}, "https://example.test/sbom", map[string]any{})
	r := p.Evaluate(Input{Statement: st, ArtifactDigest: artifact, SignerKeyIDs: []string{"k"}})
	if r.Passed || !strings.Contains(strings.Join(failedNames(r), ","), "predicate") {
		t.Fatalf("non-provenance accepted: %v", failedNames(r))
	}

	prov, _ := slsa.New(slsa.Options{BuilderID: "https://ci.example.test/builder"})
	st, _ = intoto.NewStatement([]intoto.ResourceDescriptor{{Digest: artifact}}, slsa.PredicateType, prov)
	r = p.Evaluate(Input{Statement: st, ArtifactDigest: artifact, SignerKeyIDs: []string{"k"}})
	if got := failedNames(r); len(got) != 1 || got[0] != "source-repo" {
		t.Fatalf("missing source: %v", got)
	}

	r = p.Evaluate(Input{})
	if r.Passed {
		t.Fatal("nil statement passed")
	}

	bad := &intoto.Statement{Type: "x"}
	r = p.Evaluate(Input{Statement: bad, SignerKeyIDs: []string{"k"}})
	if r.Passed {
		t.Fatal("invalid statement passed")
	}
}

func TestLogEvidencePasses(t *testing.T) {
	p := basePolicy()
	p.RequireTransparencyLog = true
	st := statement(t, "https://ci.example.test/builder", "git+https://git.example.test/acme/app", "refs/heads/main")
	r := p.Evaluate(Input{Statement: st, ArtifactDigest: artifact, SignerKeyIDs: []string{"k"},
		TransparencyLog: &LogEvidence{Verified: true, Index: 3, TreeSize: 9, Origin: "log.test"}})
	if !r.Passed {
		t.Fatalf("failures: %v", r.Failed())
	}
}

func TestValidateRejectsUnsafePolicies(t *testing.T) {
	cases := map[string]func(*Policy){
		"version":         func(p *Policy) { p.Version = 2 },
		"no builders":     func(p *Policy) { p.Builders = nil },
		"no repos":        func(p *Policy) { p.SourceRepos = nil },
		"star builder":    func(p *Policy) { p.Builders = []string{"*"} },
		"mid wildcard":    func(p *Policy) { p.Builders = []string{"https://ci.example.test/*"} },
		"double wildcard": func(p *Policy) { p.Builders = []string{"https://*/b@*"} },
		"empty builder":   func(p *Policy) { p.Builders = []string{""} },
		"wildcard repo":   func(p *Policy) { p.SourceRepos = []string{"git+https://git.example.test/*"} },
		"neg threshold":   func(p *Policy) { p.SignatureThreshold = -1 },
	}
	for name, mutate := range cases {
		p := basePolicy()
		mutate(p)
		if err := p.Validate(); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLoadAndParse(t *testing.T) {
	dir := t.TempDir()
	good := `{"version":1,"allowedBuilderIds":["https://b"],"allowedSourceRepos":["git+https://r"],"requireSourceDigest":true,"requireTransparencyLog":false}`
	path := filepath.Join(dir, "p.json")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Threshold() != 1 {
		t.Fatalf("threshold = %d", p.Threshold())
	}
	if _, err := Parse([]byte(`{"version":1,"allowedBuilderIds":["https://b"],"allowedSourceRepos":["r"],"allowedBuilderID":["typo"]}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file loaded")
	}
	if _, err := Parse([]byte(`{"version":1}`)); !errors.Is(err, ErrInvalidPolicy) {
		t.Error("empty allowlists accepted")
	}
}
