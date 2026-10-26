package dsse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/SlateGitOrg/attestlog/pkg/keys"
)

// The PAE example from the DSSE v1 protocol specification.
func TestPAESpecVector(t *testing.T) {
	got := string(PAE("http://example.com/HelloWorld", []byte("hello world")))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("PAE = %q, want %q", got, want)
	}
	if got := string(PAE("", nil)); got != "DSSEv1 0  0 " {
		t.Fatalf("empty PAE = %q", got)
	}
}

func gen(t *testing.T, alg keys.Algorithm) keys.Signer {
	t.Helper()
	s, err := keys.Generate(alg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyBothAlgorithms(t *testing.T) {
	ed, ec := gen(t, keys.Ed25519), gen(t, keys.ECDSAP256)
	env, err := Sign("application/vnd.in-toto+json", []byte(`{"a":1}`), ed, ec)
	if err != nil {
		t.Fatal(err)
	}
	v, err := env.Verify(2, ed.Public(), ec.Public())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.AcceptedKeys) != 2 || string(v.Payload) != `{"a":1}` {
		t.Fatalf("unexpected verification %+v", v)
	}
	// JSON round trip.
	raw, _ := json.Marshal(env)
	env2, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env2.Verify(1, ec.Public()); err != nil {
		t.Fatal(err)
	}
}

func TestThresholdCountsDistinctKeys(t *testing.T) {
	a := gen(t, keys.Ed25519)
	env, _ := Sign("t", []byte("p"), a, a) // same key twice
	if _, err := env.Verify(2, a.Public()); !errors.Is(err, ErrThresholdNotMet) {
		t.Fatalf("duplicate signature counted twice: %v", err)
	}
	if _, err := env.Verify(1, a.Public()); err != nil {
		t.Fatal(err)
	}
}

func TestKeyIDHintIsNotTrusted(t *testing.T) {
	a, b := gen(t, keys.Ed25519), gen(t, keys.Ed25519)
	env, _ := Sign("t", []byte("p"), a)
	// Lie about the key ID: verification still succeeds against a, and a
	// claim to be b does not make b's verifier accept a's signature.
	env.Signatures[0].KeyID = b.Public().KeyID()
	if _, err := env.Verify(1, b.Public(), a.Public()); err != nil {
		t.Fatalf("hint should only reorder keys: %v", err)
	}
	if _, err := env.Verify(1, b.Public()); !errors.Is(err, ErrThresholdNotMet) {
		t.Fatalf("wrong key accepted via hint: %v", err)
	}
}

func TestTamperingDetected(t *testing.T) {
	a := gen(t, keys.ECDSAP256)
	env, _ := Sign("application/vnd.in-toto+json", []byte("payload"), a)

	typeSwap := *env
	typeSwap.PayloadType = "application/json"
	if _, err := typeSwap.Verify(1, a.Public()); !errors.Is(err, ErrThresholdNotMet) {
		t.Errorf("payloadType swap accepted: %v", err)
	}

	bodySwap := *env
	bodySwap.Payload = base64.StdEncoding.EncodeToString([]byte("payloaD"))
	if _, err := bodySwap.Verify(1, a.Public()); !errors.Is(err, ErrThresholdNotMet) {
		t.Errorf("payload swap accepted: %v", err)
	}

	badSig := *env
	badSig.Signatures = []Signature{{Sig: "!!!notbase64"}}
	if _, err := badSig.Verify(1, a.Public()); !errors.Is(err, ErrThresholdNotMet) {
		t.Errorf("garbage signature accepted: %v", err)
	}
}

func TestURLSafeBase64Accepted(t *testing.T) {
	a := gen(t, keys.Ed25519)
	payload := []byte{0xfb, 0xff, 0xfe, 0x01}
	env, _ := Sign("t", payload, a)
	env.Payload = base64.RawURLEncoding.EncodeToString(payload)
	v, err := env.Verify(1, a.Public())
	if err != nil || string(v.Payload) != string(payload) {
		t.Fatalf("URL-safe payload rejected: %v", err)
	}
}

func TestVerifyArgumentErrors(t *testing.T) {
	a := gen(t, keys.Ed25519)
	env, _ := Sign("t", []byte("p"), a)
	if _, err := env.Verify(0, a.Public()); !errors.Is(err, ErrInvalidThreshold) {
		t.Error(err)
	}
	if _, err := env.Verify(1); !errors.Is(err, ErrNoVerifiers) {
		t.Error(err)
	}
	empty := &Envelope{PayloadType: "t", Payload: "cA=="}
	if _, err := empty.Verify(1, a.Public()); !errors.Is(err, ErrNoSignatures) {
		t.Error(err)
	}
	if _, err := (&Envelope{}).Verify(1, a.Public()); !errors.Is(err, ErrMalformed) {
		t.Error(err)
	}
	if _, err := Sign("", []byte("p"), a); err == nil {
		t.Error("empty type signed")
	}
	if _, err := Sign("t", []byte("p")); err == nil {
		t.Error("signed with no signers")
	}
	if _, err := Sign("t", make([]byte, MaxPayloadSize+1), a); !errors.Is(err, ErrPayloadTooLarge) {
		t.Error(err)
	}
}

func TestParseValidation(t *testing.T) {
	for name, in := range map[string]string{
		"not json":      `{`,
		"no type":       `{"payload":"cA==","signatures":[{"sig":"AA=="}]}`,
		"no payload":    `{"payloadType":"t","signatures":[{"sig":"AA=="}]}`,
		"no signatures": `{"payloadType":"t","payload":"cA==","signatures":[]}`,
		"empty sig":     `{"payloadType":"t","payload":"cA==","signatures":[{"sig":""}]}`,
		"bad payload":   `{"payloadType":"t","payload":"***","signatures":[{"sig":"AA=="}]}`,
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func FuzzVerify(f *testing.F) {
	s, _ := keys.Generate(keys.Ed25519, nil)
	env, _ := Sign("t", []byte("seed"), s)
	raw, _ := json.Marshal(env)
	f.Add(raw)
	f.Add([]byte(`{"payloadType":"t","payload":"","signatures":[{"sig":"AA"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := Parse(data)
		if err != nil {
			return
		}
		v, err := e.Verify(1, s.Public())
		if err != nil {
			return
		}
		// Without the private key, the only acceptable envelope is one that
		// carries the original payload type and payload.
		if string(v.Payload) != "seed" || e.PayloadType != "t" {
			t.Fatalf("forged envelope accepted: %q %q", e.PayloadType, v.Payload)
		}
	})
}
