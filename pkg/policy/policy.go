// Package policy evaluates verified attestations against a deny-by-default
// supply-chain policy: who may build, from which source, and what the
// attestation must cover.
//
// Every check produces a named result, so a failed verification explains
// exactly which rule rejected the artifact instead of returning a bare
// "invalid".
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/SlateGitOrg/attestlog/pkg/intoto"
	"github.com/SlateGitOrg/attestlog/pkg/slsa"
)

// Policy is the on-disk JSON policy document.
type Policy struct {
	Version int `json:"version"`
	// Builders lists allowed builder IDs. An entry ending in "@*" matches
	// the same ID with any "@<ref>" suffix; all other entries match exactly.
	Builders []string `json:"allowedBuilderIds"`
	// BuildTypes optionally restricts buildType. Empty means any.
	BuildTypes []string `json:"allowedBuildTypes,omitempty"`
	// SourceRepos lists allowed source repositories (without "@ref").
	SourceRepos []string `json:"allowedSourceRepos"`
	// SourceRefs optionally restricts the source ref (e.g. refs/heads/main).
	SourceRefs []string `json:"allowedSourceRefs,omitempty"`
	// RequireSourceDigest demands that the source revision is pinned by
	// digest (e.g. gitCommit), not just named by a mutable ref.
	RequireSourceDigest bool `json:"requireSourceDigest"`
	// SignatureThreshold is the number of distinct trusted keys that must
	// sign the envelope. Defaults to 1.
	SignatureThreshold int `json:"signatureThreshold,omitempty"`
	// RequireTransparencyLog demands a verified inclusion proof.
	RequireTransparencyLog bool `json:"requireTransparencyLog"`
}

// ErrInvalidPolicy is returned for policies that would be unsafe or
// meaningless, e.g. an empty builder allowlist.
var ErrInvalidPolicy = errors.New("policy: invalid policy")

// Validate rejects policies that would silently allow everything.
func (p *Policy) Validate() error {
	if p.Version != 1 {
		return fmt.Errorf("%w: unsupported version %d (want 1)", ErrInvalidPolicy, p.Version)
	}
	if len(p.Builders) == 0 {
		return fmt.Errorf("%w: allowedBuilderIds must not be empty (deny-by-default)", ErrInvalidPolicy)
	}
	if len(p.SourceRepos) == 0 {
		return fmt.Errorf("%w: allowedSourceRepos must not be empty (deny-by-default)", ErrInvalidPolicy)
	}
	for _, b := range p.Builders {
		if b == "" || b == "*" || (strings.Contains(b, "*") && !strings.HasSuffix(b, "@*")) ||
			strings.Count(b, "*") > 1 {
			return fmt.Errorf("%w: builder pattern %q (only exact IDs or a trailing \"@*\" are allowed)", ErrInvalidPolicy, b)
		}
	}
	for _, r := range p.SourceRepos {
		if r == "" || strings.Contains(r, "*") {
			return fmt.Errorf("%w: source repo %q must be an exact repository URI", ErrInvalidPolicy, r)
		}
	}
	if p.SignatureThreshold < 0 {
		return fmt.Errorf("%w: negative signatureThreshold", ErrInvalidPolicy)
	}
	return nil
}

// Threshold returns the effective signature threshold.
func (p *Policy) Threshold() int {
	if p.SignatureThreshold == 0 {
		return 1
	}
	return p.SignatureThreshold
}

// Load reads and validates a policy file. Unknown fields are rejected so a
// misspelt rule cannot be silently ignored.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read: %w", err)
	}
	return Parse(data)
}

// Parse decodes and validates a policy document.
func Parse(data []byte) (*Policy, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPolicy, err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Input is everything the evaluator needs. Signature and log verification
// happen before evaluation; their outcomes are passed in.
type Input struct {
	Statement      *intoto.Statement
	ArtifactDigest intoto.DigestSet
	// SignerKeyIDs are the distinct trusted keys that produced valid
	// signatures over the envelope.
	SignerKeyIDs []string
	// TransparencyLog is nil when no log proof was supplied; otherwise it
	// carries the result of verifying it.
	TransparencyLog *LogEvidence
}

// LogEvidence summarises a verified transparency-log inclusion.
type LogEvidence struct {
	Verified bool
	Index    uint64
	TreeSize uint64
	Origin   string
	Err      string
}

// Check is the outcome of one policy rule.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

// Report is the overall evaluation result.
type Report struct {
	Passed bool    `json:"passed"`
	Checks []Check `json:"checks"`
}

// Failed returns the failed checks.
func (r *Report) Failed() []Check {
	var out []Check
	for _, c := range r.Checks {
		if !c.Passed {
			out = append(out, c)
		}
	}
	return out
}

func (r *Report) add(name string, ok bool, format string, args ...any) {
	r.Checks = append(r.Checks, Check{Name: name, Passed: ok, Detail: fmt.Sprintf(format, args...)})
}

// Evaluate runs every rule and never short-circuits, so the report lists all
// failures at once.
func (p *Policy) Evaluate(in Input) *Report {
	r := &Report{}

	n := len(in.SignerKeyIDs)
	r.add("signature-threshold", n >= p.Threshold(), "%d distinct trusted signer(s), need %d", n, p.Threshold())

	st := in.Statement
	if st == nil {
		r.add("statement", false, "no statement")
		r.Passed = false
		return r
	}
	if err := st.Validate(); err != nil {
		r.add("statement", false, "%v", err)
	} else {
		r.add("statement", true, "in-toto Statement v1 with %d subject(s)", len(st.Subject))
	}

	if len(in.ArtifactDigest) == 0 {
		r.add("subject-digest", false, "no artifact digest supplied")
	} else if subj, ok := st.MatchSubject(in.ArtifactDigest); ok {
		r.add("subject-digest", true, "artifact matches subject %q", subj.Name)
	} else {
		r.add("subject-digest", false, "artifact %s matches no subject", short(in.ArtifactDigest))
	}

	prov, err := slsa.FromStatement(st)
	if err != nil {
		r.add("predicate", false, "%v", err)
		p.evaluateLog(r, in.TransparencyLog)
		r.Passed = false
		return r
	}
	r.add("predicate", true, "SLSA Provenance v1")

	builder := prov.RunDetails.Builder.ID
	r.add("builder-id", matchBuilder(p.Builders, builder), "builder %q", builder)

	if len(p.BuildTypes) > 0 {
		bt := prov.BuildDefinition.BuildType
		r.add("build-type", slices.Contains(p.BuildTypes, bt), "buildType %q", bt)
	}

	src, ok := prov.SourceOf()
	switch {
	case !ok:
		r.add("source-repo", false, "provenance names no source repository")
	default:
		r.add("source-repo", slices.Contains(p.SourceRepos, src.Repo()), "source %q", src.Repo())
		if len(p.SourceRefs) > 0 {
			r.add("source-ref", src.Ref != "" && slices.Contains(p.SourceRefs, src.Ref), "ref %q", src.Ref)
		}
		if p.RequireSourceDigest {
			err := src.Digest.Validate()
			desc := src.Digest.String()
			if desc == "" {
				desc = "(none: source named only by a mutable ref)"
			}
			r.add("source-digest", len(src.Digest) > 0 && err == nil, "source digest %s", desc)
		}
	}

	p.evaluateLog(r, in.TransparencyLog)

	r.Passed = len(r.Failed()) == 0
	return r
}

func (p *Policy) evaluateLog(r *Report, ev *LogEvidence) {
	switch {
	case ev == nil && p.RequireTransparencyLog:
		r.add("transparency-log", false, "policy requires a log inclusion proof; none supplied")
	case ev == nil:
		// Not required and not supplied: no check recorded.
	case !ev.Verified:
		r.add("transparency-log", false, "inclusion proof rejected: %s", ev.Err)
	default:
		r.add("transparency-log", true, "entry %d included in %s at tree size %d", ev.Index, ev.Origin, ev.TreeSize)
	}
}

func matchBuilder(allowed []string, id string) bool {
	for _, a := range allowed {
		if prefix, ok := strings.CutSuffix(a, "@*"); ok {
			if id == prefix || strings.HasPrefix(id, prefix+"@") {
				return true
			}
			continue
		}
		if a == id {
			return true
		}
	}
	return false
}

func short(d intoto.DigestSet) string {
	if v, ok := d["sha256"]; ok && len(v) > 16 {
		return "sha256:" + v[:16] + "…"
	}
	return d.String()
}
