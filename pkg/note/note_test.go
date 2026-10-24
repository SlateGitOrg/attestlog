package note

import (
	"errors"
	"strings"
	"testing"
)

// Vectors from golang.org/x/mod/sumdb/note (note_test.go, BSD-3-Clause).
const (
	peterSKey = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
	peterVKey = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
	peterText = "If you think cryptography is the answer to your problem,\n" +
		"then you don't know what your problem is.\n"
	peterSigned = peterText + "\n" +
		"— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"
)

func TestSumdbNoteVector(t *testing.T) {
	s, err := NewSigner(peterSKey)
	if err != nil {
		t.Fatal(err)
	}
	if s.Verifier().String() != peterVKey {
		t.Fatalf("verifier key = %s", s.Verifier().String())
	}
	msg, err := Sign(peterText, s)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != peterSigned {
		t.Fatalf("signed note mismatch:\n%s", msg)
	}
	v, err := NewVerifier(peterVKey)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open([]byte(peterSigned), v)
	if err != nil {
		t.Fatal(err)
	}
	if n.Text != peterText || len(n.Verified) != 1 || n.Verified[0].Hash != 0xc74f20a3 {
		t.Fatalf("opened note = %+v", n)
	}
	if s.Name() != "PeterNeumann" || v.Name() != "PeterNeumann" || s.KeyHash() != v.KeyHash() {
		t.Fatal("accessor mismatch")
	}
}

func TestGenerateSignOpen(t *testing.T) {
	skey, vkey, err := GenerateKey(nil, "log.example.test")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := GenerateKey(nil, "witness.example.test")
	ws, _ := NewSigner(other)

	msg, err := Sign("hello\nworld\n", s, ws)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Open(msg, v)
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Verified) != 1 || len(n.Unverified) != 1 {
		t.Fatalf("verified=%d unverified=%d", len(n.Verified), len(n.Unverified))
	}
	// Only unknown keys: unverified.
	if _, err := Open(msg, ws.Verifier()); err != nil {
		t.Fatalf("witness verifier: %v", err)
	}
	_, vkey2, _ := GenerateKey(nil, "stranger")
	v2, _ := NewVerifier(vkey2)
	if _, err := Open(msg, v2); !errors.Is(err, ErrUnverified) {
		t.Fatalf("want ErrUnverified, got %v", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	v, _ := NewVerifier(peterVKey)
	tampered := strings.Replace(peterSigned, "cryptography", "Cryptography", 1)
	if _, err := Open([]byte(tampered), v); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered text: %v", err)
	}
	dup := peterSigned + "— PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"
	if _, err := Open([]byte(dup), v); !errors.Is(err, ErrMalformedNote) {
		t.Fatalf("duplicate signature: %v", err)
	}
	for name, msg := range map[string]string{
		"no sig block":     peterText,
		"bad line":         peterText + "\nnot a signature\n",
		"bad base64":       peterText + "\n— PeterNeumann !!!\n",
		"short sig":        peterText + "\n— PeterNeumann AAAA\n",
		"unterminated":     strings.TrimSuffix(peterSigned, "\n"),
		"empty sig block":  peterText + "\n",
		"bad name":         peterText + "\n— Peter+Neumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n",
		"no newline text":  "x\n\n— PeterNeumann AAAAAAAA\n"[1:],
		"blank in text":    "a\n\nb\n\n— PeterNeumann AAAAAAAA\n",
		"oversized":        strings.Repeat("a", MaxNoteSize+1),
		"missing name sep": peterText + "\n— PeterNeumann\n",
	} {
		if _, err := Open([]byte(msg), v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyParsingErrors(t *testing.T) {
	bad := []string{
		"", "PeterNeumann", "PeterNeumann+zz+AAAA", "PeterNeumann+c74f20a3+!!!",
		"PeterNeumann+c74f20a4+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW", // wrong hash
		"PeterNeumann+cc469956+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TWBADKEY==",
		"PeterNeumann+173116ae+ZRpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW", // unknown alg
		"Peter Neumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW",
	}
	for _, k := range bad {
		if _, err := NewVerifier(k); err == nil {
			t.Errorf("verifier %q accepted", k)
		}
	}
	for _, k := range []string{
		peterVKey, // no PRIVATE+KEY prefix
		"PRIVATE+KEY+PeterNeumann+c74f20a4+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz",
		"PRIVATE+KEY+PeterNeumann+c74f20a3+AYEK",
		"PRIVATE+KEY+bad",
	} {
		if _, err := NewSigner(k); err == nil {
			t.Errorf("signer %q accepted", k)
		}
	}
	if _, _, err := GenerateKey(nil, "has space"); err == nil {
		t.Error("invalid name accepted")
	}
}

func TestSignErrors(t *testing.T) {
	s, _ := NewSigner(peterSKey)
	for _, text := range []string{"no newline", "a\n\nb\n", "tab\there\n", "\xff\n"} {
		if _, err := Sign(text, s); err == nil {
			t.Errorf("Sign(%q) accepted", text)
		}
	}
	if _, err := Sign("ok\n"); err == nil {
		t.Error("Sign with no signers accepted")
	}
}

func FuzzOpen(f *testing.F) {
	v, _ := NewVerifier(peterVKey)
	f.Add([]byte(peterSigned))
	f.Add([]byte("a\n\n— x AAAA\n"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		n, err := Open(msg, v)
		if err != nil {
			return
		}
		if n.Text != peterText {
			t.Fatalf("forged note accepted: %q", n.Text)
		}
	})
}
