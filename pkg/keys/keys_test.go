package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
)

func TestGenerateSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{Ed25519, ECDSAP256} {
		t.Run(string(alg), func(t *testing.T) {
			s, err := Generate(alg, nil)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("attest me")
			sig, err := s.Sign(msg)
			if err != nil {
				t.Fatal(err)
			}
			pub := s.Public()
			if pub.Algorithm() != alg {
				t.Fatalf("alg = %s", pub.Algorithm())
			}
			if err := pub.Verify(msg, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := pub.Verify([]byte("tampered"), sig); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("tampered message accepted: %v", err)
			}

			privPEM, err := MarshalPrivatePEM(s)
			if err != nil {
				t.Fatal(err)
			}
			s2, err := ParsePrivatePEM(privPEM)
			if err != nil {
				t.Fatal(err)
			}
			if s2.Public().KeyID() != pub.KeyID() {
				t.Fatal("key ID changed across PEM round trip")
			}
			pub2, err := ParsePublicPEM(pub.MarshalPEM())
			if err != nil {
				t.Fatal(err)
			}
			if !pub2.Equal(pub) || len(pub.KeyID()) != 64 {
				t.Fatal("public PEM round trip mismatch")
			}
			if err := pub2.Verify(msg, sig); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseAlgorithm(t *testing.T) {
	for in, want := range map[string]Algorithm{"ed25519": Ed25519, "ecdsa-p256": ECDSAP256, "P-256": ECDSAP256} {
		got, err := ParseAlgorithm(in)
		if err != nil || got != want {
			t.Errorf("ParseAlgorithm(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseAlgorithm("rsa"); err == nil {
		t.Error("rsa accepted")
	}
	if _, err := Generate("rsa", nil); err == nil {
		t.Error("Generate(rsa) accepted")
	}
}

func TestRejectsUnsupportedKeys(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewPublicKey(&p384.PublicKey); err == nil {
		t.Error("P-384 accepted")
	}
	if _, err := NewSigner(p384); err == nil {
		t.Error("P-384 signer accepted")
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := NewPublicKey(&rk.PublicKey); err == nil {
		t.Error("RSA accepted")
	}
	if _, err := NewSigner(rk); err == nil {
		t.Error("RSA signer accepted")
	}
}

func TestPEMErrors(t *testing.T) {
	s, _ := Generate(Ed25519, nil)
	priv, _ := MarshalPrivatePEM(s)
	pub := s.Public().MarshalPEM()
	cases := map[string]func() error{
		"no block":         func() error { _, err := ParsePublicPEM([]byte("nope")); return err },
		"private as pub":   func() error { _, err := ParsePublicPEM(priv); return err },
		"pub as private":   func() error { _, err := ParsePrivatePEM(pub); return err },
		"trailing data":    func() error { _, err := ParsePublicPEM(append(append([]byte{}, pub...), pub...)); return err },
		"no private block": func() error { _, err := ParsePrivatePEM([]byte("x")); return err },
		"garbage der": func() error {
			_, err := ParsePublicPEM([]byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"))
			return err
		},
		"garbage private der": func() error {
			_, err := ParsePrivatePEM([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if !strings.Contains(string(pub), "BEGIN PUBLIC KEY") {
		t.Error("unexpected PEM type")
	}
}

type foreignSigner struct{ Signer }

func TestMarshalForeignSigner(t *testing.T) {
	s, _ := Generate(Ed25519, nil)
	if _, err := MarshalPrivatePEM(foreignSigner{s}); err == nil {
		t.Error("foreign signer marshalled")
	}
}

func BenchmarkSignVerify(b *testing.B) {
	msg := make([]byte, 1024)
	for _, alg := range []Algorithm{Ed25519, ECDSAP256} {
		s, _ := Generate(alg, nil)
		sig, _ := s.Sign(msg)
		b.Run("sign/"+string(alg), func(b *testing.B) {
			for b.Loop() {
				if _, err := s.Sign(msg); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verify/"+string(alg), func(b *testing.B) {
			for b.Loop() {
				if err := s.Public().Verify(msg, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
