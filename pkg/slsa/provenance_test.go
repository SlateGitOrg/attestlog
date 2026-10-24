package slsa

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/attestlog/pkg/intoto"
)

var commit = strings.Repeat("c", 40)

func TestNewAndSourceRoundTrip(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p, err := New(Options{
		BuilderID:    "https://ci.example.test/builder@v1",
		SourceURI:    "git+https://git.example.test/acme/app",
		SourceRef:    "refs/heads/main",
		SourceDigest: intoto.DigestSet{"gitCommit": commit},
		Parameters:   map[string]string{"target": "release"},
		InvocationID: "run-42",
		StartedOn:    start,
		FinishedOn:   start.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.BuildDefinition.BuildType != GenericBuildType {
		t.Fatalf("buildType = %s", p.BuildDefinition.BuildType)
	}
	st, err := intoto.NewStatement([]intoto.ResourceDescriptor{{Digest: intoto.DigestSet{"sha256": strings.Repeat("a", 64)}}}, PredicateType, p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(st)
	st2, err := intoto.ParseStatement(raw)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := FromStatement(st2)
	if err != nil {
		t.Fatal(err)
	}
	src, ok := p2.SourceOf()
	if !ok || src.Repo() != "git+https://git.example.test/acme/app" || src.Ref != "refs/heads/main" ||
		src.Digest["gitCommit"] != commit {
		t.Fatalf("source = %+v", src)
	}
	if p2.RunDetails.Metadata.InvocationID != "run-42" {
		t.Fatal("metadata lost")
	}
}

func TestSourceOfFallbacks(t *testing.T) {
	// String source with embedded ref; digest from resolvedDependencies.
	p := &Provenance{BuildDefinition: BuildDefinition{
		ExternalParameters: map[string]any{"source": "git+https://h.test/o/r@refs/tags/v1"},
		ResolvedDependencies: []intoto.ResourceDescriptor{
			{URI: "git+https://h.test/o/r@refs/tags/v1", Digest: intoto.DigestSet{"gitCommit": commit}},
		},
	}}
	src, ok := p.SourceOf()
	if !ok || src.Repo() != "git+https://h.test/o/r" || src.Ref != "refs/tags/v1" || src.Digest["gitCommit"] != commit {
		t.Fatalf("string source: %+v", src)
	}

	// No parameters: first git+ dependency wins.
	p = &Provenance{BuildDefinition: BuildDefinition{
		ExternalParameters: map[string]any{},
		ResolvedDependencies: []intoto.ResourceDescriptor{
			{URI: "pkg:npm/left-pad@1.0.0"},
			{URI: "git+ssh://git@h.test/o/r@refs/heads/main", Digest: intoto.DigestSet{"gitCommit": commit}},
		},
	}}
	src, ok = p.SourceOf()
	if !ok || src.Repo() != "git+ssh://git@h.test/o/r" || src.Ref != "refs/heads/main" {
		t.Fatalf("dependency fallback: %+v (repo %s)", src, src.Repo())
	}

	p = &Provenance{BuildDefinition: BuildDefinition{ExternalParameters: map[string]any{}}}
	if _, ok := p.SourceOf(); ok {
		t.Fatal("source found where none exists")
	}
}

func TestRepoOf(t *testing.T) {
	for in, want := range map[string]string{
		"git+https://h/o/r@main":           "git+https://h/o/r",
		"git+https://h/o/r":                "git+https://h/o/r",
		"https://h":                        "https://h",
		"git+ssh://git@h/o/r":              "git+ssh://git@h/o/r",
		"git+ssh://git@h/o/r@refs/heads/x": "git+ssh://git@h/o/r",
		"o/r@v2":                           "o/r",
	} {
		if got := repoOf(in); got != want {
			t.Errorf("repoOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	now := time.Now()
	earlier := now.Add(-time.Hour)
	cases := map[string]*Provenance{
		"no build type": {BuildDefinition: BuildDefinition{ExternalParameters: map[string]any{}},
			RunDetails: RunDetails{Builder: Builder{ID: "https://b"}}},
		"relative build type": {BuildDefinition: BuildDefinition{BuildType: "generic", ExternalParameters: map[string]any{}},
			RunDetails: RunDetails{Builder: Builder{ID: "https://b"}}},
		"no ext params": {BuildDefinition: BuildDefinition{BuildType: "https://t"},
			RunDetails: RunDetails{Builder: Builder{ID: "https://b"}}},
		"no builder": {BuildDefinition: BuildDefinition{BuildType: "https://t", ExternalParameters: map[string]any{}}},
		"bad dep": {BuildDefinition: BuildDefinition{BuildType: "https://t", ExternalParameters: map[string]any{},
			ResolvedDependencies: []intoto.ResourceDescriptor{{}}},
			RunDetails: RunDetails{Builder: Builder{ID: "https://b"}}},
		"time travel": {BuildDefinition: BuildDefinition{BuildType: "https://t", ExternalParameters: map[string]any{}},
			RunDetails: RunDetails{Builder: Builder{ID: "https://b"},
				Metadata: &BuildMetadata{StartedOn: &now, FinishedOn: &earlier}}},
	}
	for name, p := range cases {
		if err := p.Validate(); !errors.Is(err, ErrInvalidProvenance) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := New(Options{BuilderID: "https://b", Parameters: map[string]string{"source": "x"}}); err == nil {
		t.Error("reserved parameter accepted")
	}
	if _, err := New(Options{BuilderID: "https://b", SourceURI: "git+https://x",
		SourceDigest: intoto.DigestSet{"gitCommit": "short"}}); err == nil {
		t.Error("bad source digest accepted")
	}
	if _, err := New(Options{}); err == nil {
		t.Error("missing builder accepted")
	}
}

func TestFromStatementErrors(t *testing.T) {
	d := []intoto.ResourceDescriptor{{Digest: intoto.DigestSet{"sha256": strings.Repeat("a", 64)}}}
	st, _ := intoto.NewStatement(d, "https://other/predicate", map[string]any{})
	if _, err := FromStatement(st); !errors.Is(err, ErrInvalidProvenance) {
		t.Error("wrong predicate type accepted")
	}
	st, _ = intoto.NewStatement(d, PredicateType, []int{1})
	if _, err := FromStatement(st); !errors.Is(err, ErrInvalidProvenance) {
		t.Error("non-object predicate accepted")
	}
	st, _ = intoto.NewStatement(d, PredicateType, map[string]any{})
	if _, err := FromStatement(st); !errors.Is(err, ErrInvalidProvenance) {
		t.Error("empty predicate accepted")
	}
}
