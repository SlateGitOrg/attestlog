// Package testutil builds signed fixtures for tests across packages.
package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/archit2501/attestlog/pkg/dsse"
	"github.com/archit2501/attestlog/pkg/intoto"
	"github.com/archit2501/attestlog/pkg/keys"
	"github.com/archit2501/attestlog/pkg/note"
	"github.com/archit2501/attestlog/pkg/slsa"
	"github.com/archit2501/attestlog/pkg/tlog"
)

// Fixture defaults.
const (
	Builder = "https://ci.example.test/builder@v1"
	Repo    = "git+https://git.example.test/acme/app"
	Ref     = "refs/heads/main"
	Origin  = "log.example.test"
)

// Commit is a fixed fake git commit.
var Commit = strings.Repeat("c", 40)

// Signer returns a fresh signer or fails the test.
func Signer(t testing.TB, alg keys.Algorithm) keys.Signer {
	t.Helper()
	s, err := keys.Generate(alg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// LogSigner returns a fresh checkpoint signer named Origin.
func LogSigner(t testing.TB) *note.Signer {
	t.Helper()
	skey, _, err := note.GenerateKey(nil, Origin)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Digest returns the sha256 digest set of content.
func Digest(content string) intoto.DigestSet {
	sum := sha256.Sum256([]byte(content))
	return intoto.DigestSet{"sha256": hex.EncodeToString(sum[:])}
}

// Envelope signs SLSA provenance for an artifact with the given content.
func Envelope(t testing.TB, content, builder string, signers ...keys.Signer) *dsse.Envelope {
	t.Helper()
	p, err := slsa.New(slsa.Options{
		BuilderID: builder, SourceURI: Repo, SourceRef: Ref,
		SourceDigest: intoto.DigestSet{"gitCommit": Commit},
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := intoto.NewStatement([]intoto.ResourceDescriptor{{Name: "artifact", Digest: Digest(content)}}, slsa.PredicateType, p)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := dsse.Sign(intoto.PayloadType, payload, signers...)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// EntryBody returns the canonical log entry body for content.
func EntryBody(t testing.TB, content string, s keys.Signer) []byte {
	t.Helper()
	e, err := tlog.NewEntry(Envelope(t, content, Builder, s), s.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Populate appends n distinct entries to l.
func Populate(t testing.TB, l *tlog.Log, s keys.Signer, prefix string, n int) {
	t.Helper()
	for i := range n {
		if _, err := l.Add(EntryBody(t, fmt.Sprintf("%s-%d", prefix, i), s)); err != nil {
			t.Fatal(err)
		}
	}
}
