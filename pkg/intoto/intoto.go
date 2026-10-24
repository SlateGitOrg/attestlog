// Package intoto implements the in-toto Attestation Framework Statement v1
// and ResourceDescriptor types.
//
// Spec: https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
package intoto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Constants from the in-toto v1 specification.
const (
	StatementTypeV1 = "https://in-toto.io/Statement/v1"
	PayloadType     = "application/vnd.in-toto+json"
)

// ErrInvalidStatement wraps every Statement validation failure.
var ErrInvalidStatement = errors.New("intoto: invalid statement")

// DigestSet maps an algorithm name (e.g. "sha256") to a lowercase hex digest
// or, for non-hash identifiers such as "gitCommit", an opaque value.
type DigestSet map[string]string

// hexDigestLengths lists algorithms whose values must be lowercase hex of a
// fixed length. Other algorithm names are allowed but not length-checked.
var hexDigestLengths = map[string]int{
	"sha1":      40,
	"sha224":    56,
	"sha256":    64,
	"sha384":    96,
	"sha512":    128,
	"sha3_256":  64,
	"sha3_512":  128,
	"gitCommit": 0, // 40 (SHA-1) or 64 (SHA-256) hex
	"gitTree":   0,
}

// Validate checks that the set is non-empty and that well-known hash
// algorithms carry correctly sized lowercase hex.
func (d DigestSet) Validate() error {
	if len(d) == 0 {
		return errors.New("empty digest set")
	}
	for alg, val := range d {
		if alg == "" || val == "" {
			return fmt.Errorf("empty algorithm or value in digest %q", alg)
		}
		want, known := hexDigestLengths[alg]
		if !known {
			continue
		}
		if !isLowerHex(val) {
			return fmt.Errorf("digest %s is not lowercase hex", alg)
		}
		if want == 0 {
			if len(val) != 40 && len(val) != 64 {
				return fmt.Errorf("digest %s has length %d, want 40 or 64", alg, len(val))
			}
			continue
		}
		if len(val) != want {
			return fmt.Errorf("digest %s has length %d, want %d", alg, len(val), want)
		}
	}
	return nil
}

// Matches reports whether d and other describe the same content: they must
// share at least one algorithm and agree on every shared algorithm. A
// disagreement on any shared algorithm is a mismatch even if another agrees.
func (d DigestSet) Matches(other DigestSet) bool {
	shared := 0
	for alg, v := range d {
		ov, ok := other[alg]
		if !ok {
			continue
		}
		if !strings.EqualFold(v, ov) {
			return false
		}
		shared++
	}
	return shared > 0
}

// String renders the set deterministically as "alg:value" pairs.
func (d DigestSet) String() string {
	algs := make([]string, 0, len(d))
	for a := range d {
		algs = append(algs, a)
	}
	sort.Strings(algs)
	parts := make([]string, len(algs))
	for i, a := range algs {
		parts[i] = a + ":" + d[a]
	}
	return strings.Join(parts, ",")
}

// ParseDigest parses "alg:value" (e.g. "sha256:ab12...") into a DigestSet.
func ParseDigest(s string) (DigestSet, error) {
	alg, val, ok := strings.Cut(s, ":")
	if !ok || alg == "" || val == "" {
		return nil, fmt.Errorf("intoto: digest %q must look like alg:value", s)
	}
	d := DigestSet{alg: val}
	if err := d.Validate(); err != nil {
		return nil, fmt.Errorf("intoto: %w", err)
	}
	return d, nil
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DigestReader hashes r with SHA-256 and SHA-512 in a single pass.
func DigestReader(r io.Reader) (DigestSet, error) {
	h256 := sha256.New()
	h512 := sha512.New()
	if _, err := io.Copy(io.MultiWriter(h256, h512), r); err != nil {
		return nil, fmt.Errorf("intoto: hash artifact: %w", err)
	}
	return DigestSet{
		"sha256": hex.EncodeToString(h256.Sum(nil)),
		"sha512": hex.EncodeToString(h512.Sum(nil)),
	}, nil
}

// ResourceDescriptor describes a software artifact or resource.
type ResourceDescriptor struct {
	URI              string            `json:"uri,omitempty"`
	Digest           DigestSet         `json:"digest,omitempty"`
	Name             string            `json:"name,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	MediaType        string            `json:"mediaType,omitempty"`
	Content          []byte            `json:"content,omitempty"`
	Annotations      map[string]string `json:"annotations,omitempty"`
}

// Validate checks that the descriptor identifies something: the spec
// requires at least one of uri, digest or content.
func (r *ResourceDescriptor) Validate() error {
	if r.URI == "" && len(r.Digest) == 0 && len(r.Content) == 0 {
		return errors.New("resource descriptor needs uri, digest or content")
	}
	if len(r.Digest) > 0 {
		if err := r.Digest.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Statement is an in-toto v1 Statement.
type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     json.RawMessage      `json:"predicate,omitempty"`
}

// NewStatement builds a v1 statement with a JSON-encoded predicate.
func NewStatement(subjects []ResourceDescriptor, predicateType string, predicate any) (*Statement, error) {
	raw, err := json.Marshal(predicate)
	if err != nil {
		return nil, fmt.Errorf("intoto: encode predicate: %w", err)
	}
	st := &Statement{Type: StatementTypeV1, Subject: subjects, PredicateType: predicateType, Predicate: raw}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

// Validate enforces the v1 statement parsing rules: correct _type, at least
// one subject, every subject has a valid digest, and a predicateType.
func (s *Statement) Validate() error {
	if s.Type != StatementTypeV1 {
		return fmt.Errorf("%w: _type %q, want %q", ErrInvalidStatement, s.Type, StatementTypeV1)
	}
	if len(s.Subject) == 0 {
		return fmt.Errorf("%w: no subjects", ErrInvalidStatement)
	}
	for i := range s.Subject {
		if len(s.Subject[i].Digest) == 0 {
			return fmt.Errorf("%w: subject %d has no digest", ErrInvalidStatement, i)
		}
		if err := s.Subject[i].Digest.Validate(); err != nil {
			return fmt.Errorf("%w: subject %d: %w", ErrInvalidStatement, i, err)
		}
	}
	if s.PredicateType == "" {
		return fmt.Errorf("%w: empty predicateType", ErrInvalidStatement)
	}
	return nil
}

// ParseStatement decodes and validates a statement.
func ParseStatement(data []byte) (*Statement, error) {
	var s Statement
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidStatement, err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// MatchSubject returns the first subject whose digest matches d.
func (s *Statement) MatchSubject(d DigestSet) (*ResourceDescriptor, bool) {
	for i := range s.Subject {
		if s.Subject[i].Digest.Matches(d) {
			return &s.Subject[i], true
		}
	}
	return nil, false
}

// DecodePredicate unmarshals the predicate into v.
func (s *Statement) DecodePredicate(v any) error {
	if len(s.Predicate) == 0 {
		return fmt.Errorf("%w: empty predicate", ErrInvalidStatement)
	}
	if err := json.Unmarshal(s.Predicate, v); err != nil {
		return fmt.Errorf("intoto: decode predicate: %w", err)
	}
	return nil
}
