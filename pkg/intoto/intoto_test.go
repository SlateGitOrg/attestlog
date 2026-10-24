package intoto

import (
	"errors"
	"strings"
	"testing"
)

const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func TestDigestReader(t *testing.T) {
	d, err := DigestReader(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if d["sha256"] != sha {
		t.Fatalf("sha256 = %s", d["sha256"])
	}
	if !strings.HasPrefix(d["sha512"], "cf83e1357eefb8bd") {
		t.Fatalf("sha512 = %s", d["sha512"])
	}
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDigestValidate(t *testing.T) {
	bad := []DigestSet{
		{},
		{"sha256": "ABC"},
		{"sha256": strings.ToUpper(sha)},
		{"sha256": sha[:10]},
		{"gitCommit": "abc"},
		{"": "x"},
		{"sha1": ""},
	}
	for _, d := range bad {
		if d.Validate() == nil {
			t.Errorf("%v accepted", d)
		}
	}
	good := []DigestSet{
		{"sha256": sha},
		{"gitCommit": strings.Repeat("a", 40)},
		{"gitCommit": strings.Repeat("b", 64)},
		{"customAlg": "Anything-Goes"},
	}
	for _, d := range good {
		if err := d.Validate(); err != nil {
			t.Errorf("%v rejected: %v", d, err)
		}
	}
}

func TestDigestMatches(t *testing.T) {
	a := DigestSet{"sha256": sha, "sha512": "aa"}
	cases := []struct {
		other DigestSet
		want  bool
	}{
		{DigestSet{"sha256": sha}, true},
		{DigestSet{"sha512": "aa"}, true},
		{DigestSet{"sha256": sha, "sha512": "bb"}, false}, // any disagreement fails
		{DigestSet{"sha1": "aa"}, false},                  // nothing shared
		{DigestSet{}, false},
	}
	for _, c := range cases {
		if got := a.Matches(c.other); got != c.want {
			t.Errorf("Matches(%v) = %v", c.other, got)
		}
	}
	if s := a.String(); s != "sha256:"+sha+",sha512:aa" {
		t.Errorf("String() = %s", s)
	}
}

func TestParseDigest(t *testing.T) {
	d, err := ParseDigest("sha256:" + sha)
	if err != nil || d["sha256"] != sha {
		t.Fatalf("ParseDigest: %v", err)
	}
	for _, in := range []string{"sha256", ":abc", "sha256:", "sha256:xyz"} {
		if _, err := ParseDigest(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestStatementValidation(t *testing.T) {
	st, err := NewStatement([]ResourceDescriptor{{Name: "app", Digest: DigestSet{"sha256": sha}}},
		"https://example.test/predicate", map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.MatchSubject(DigestSet{"sha256": sha}); !ok {
		t.Fatal("subject not matched")
	}
	if _, ok := st.MatchSubject(DigestSet{"sha256": strings.Repeat("0", 64)}); ok {
		t.Fatal("wrong digest matched")
	}
	var pred map[string]string
	if err := st.DecodePredicate(&pred); err != nil || pred["k"] != "v" {
		t.Fatalf("DecodePredicate: %v", err)
	}

	bad := map[string]string{
		"wrong type":     `{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"digest":{"sha256":"` + sha + `"}}],"predicateType":"x"}`,
		"no subject":     `{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x"}`,
		"no digest":      `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a"}],"predicateType":"x"}`,
		"bad digest":     `{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"zz"}}],"predicateType":"x"}`,
		"no predicate t": `{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + sha + `"}}]}`,
		"not json":       `[`,
	}
	for name, in := range bad {
		if _, err := ParseStatement([]byte(in)); !errors.Is(err, ErrInvalidStatement) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	empty := &Statement{}
	if err := empty.DecodePredicate(&pred); err == nil {
		t.Error("empty predicate decoded")
	}
	if _, err := NewStatement(nil, "x", nil); err == nil {
		t.Error("statement without subjects built")
	}
	if _, err := NewStatement([]ResourceDescriptor{{Digest: DigestSet{"sha256": sha}}}, "x", func() {}); err == nil {
		t.Error("unencodable predicate accepted")
	}
}

func TestResourceDescriptorValidate(t *testing.T) {
	if (&ResourceDescriptor{}).Validate() == nil {
		t.Error("empty descriptor accepted")
	}
	if (&ResourceDescriptor{URI: "git+https://x"}).Validate() != nil {
		t.Error("uri-only descriptor rejected")
	}
	if (&ResourceDescriptor{Digest: DigestSet{"sha256": "x"}}).Validate() == nil {
		t.Error("bad digest accepted")
	}
}
