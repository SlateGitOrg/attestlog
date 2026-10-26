package checkpoint

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/SlateGitOrg/attestlog/pkg/merkle"
	"github.com/SlateGitOrg/attestlog/pkg/note"
)

func signer(t *testing.T, name string) *note.Signer {
	t.Helper()
	skey, _, err := note.GenerateKey(nil, name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMarshalParseRoundTrip(t *testing.T) {
	c := &Checkpoint{
		Origin:     "log.example.test",
		Size:       42,
		Root:       merkle.LeafHash([]byte("x")),
		Timestamp:  time.UnixMilli(1700000000123).UTC(),
		Extensions: []string{"vendor-ext abc"},
	}
	text, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text, "log.example.test\n42\n") || !strings.Contains(text, "timestamp 1700000000123\n") {
		t.Fatalf("unexpected text:\n%s", text)
	}
	got, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if got.Origin != c.Origin || got.Size != c.Size || got.Root != c.Root ||
		!got.Timestamp.Equal(c.Timestamp) || len(got.Extensions) != 1 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestParseErrors(t *testing.T) {
	root := "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
	for name, text := range map[string]string{
		"no newline":     "o\n1\n" + root,
		"too few lines":  "o\n1\n",
		"empty origin":   "\n1\n" + root + "\n",
		"bad size":       "o\nx\n" + root + "\n",
		"leading zero":   "o\n01\n" + root + "\n",
		"negative":       "o\n-1\n" + root + "\n",
		"bad base64":     "o\n1\n!!!\n",
		"short root":     "o\n1\nAAAA\n",
		"empty ext line": "o\n1\n" + root + "\n\n",
		"bad timestamp":  "o\n1\n" + root + "\ntimestamp x\n",
	} {
		if _, err := Parse(text); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (&Checkpoint{}).Marshal(); err == nil {
		t.Error("empty origin marshalled")
	}
	if _, err := (&Checkpoint{Origin: "o", Extensions: []string{"a\nb"}}).Marshal(); err == nil {
		t.Error("multi-line extension marshalled")
	}
}

func TestSignOpen(t *testing.T) {
	s := signer(t, "log.example.test")
	c := &Checkpoint{Origin: s.Name(), Size: 3, Root: merkle.EmptyRoot()}
	signed, err := Sign(c, s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(signed.Raw, s.Verifier())
	if err != nil {
		t.Fatal(err)
	}
	if got.Size != 3 || string(got.Raw) != string(signed.Raw) {
		t.Fatal("open mismatch")
	}

	other := signer(t, "other.example.test")
	if _, err := Sign(c, other); err == nil {
		t.Error("origin/key mismatch signed")
	}
	if _, err := Open(signed.Raw, other.Verifier()); err == nil {
		t.Error("checkpoint opened with wrong key")
	}
	// A note signed by the right key whose origin line names another log.
	impostor := signer(t, "log.example.test")
	text := "evil.example.test\n3\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n"
	raw, _ := note.Sign(text, impostor)
	if _, err := Open(raw, impostor.Verifier()); err == nil {
		t.Error("origin mismatch accepted")
	}
	raw, _ = note.Sign("log.example.test\nnot-a-number\nAAAA\n", impostor)
	if _, err := Open(raw, impostor.Verifier()); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed body: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add("log\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\ntimestamp 5\n")
	f.Fuzz(func(t *testing.T, text string) {
		c, err := Parse(text)
		if err != nil {
			return
		}
		out, err := c.Marshal()
		if err != nil {
			return
		}
		c2, err := Parse(out)
		if err != nil {
			t.Fatalf("re-parse of marshalled checkpoint failed: %v", err)
		}
		if c2.Size != c.Size || c2.Root != c.Root || c2.Origin != c.Origin {
			t.Fatal("round trip changed checkpoint")
		}
	})
}
