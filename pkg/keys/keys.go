// Package keys provides the signing-key abstraction used for DSSE envelopes.
//
// Two algorithms are supported, matching the DSSE ecosystem defaults:
//
//   - Ed25519 (pure Ed25519 over the PAE bytes)
//   - ECDSA P-256 with SHA-256, signatures encoded as ASN.1 DER
//
// Keys are serialised as PEM: PKCS#8 for private keys and PKIX
// (SubjectPublicKeyInfo) for public keys. A key's ID is the lowercase hex
// SHA-256 of its PKIX DER encoding, so the same public key always yields the
// same ID regardless of how it was loaded.
package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// Algorithm identifies a signature scheme.
type Algorithm string

// Supported algorithms.
const (
	Ed25519   Algorithm = "ed25519"
	ECDSAP256 Algorithm = "ecdsa-p256-sha256"
)

// ParseAlgorithm accepts the canonical names plus a few common aliases.
func ParseAlgorithm(s string) (Algorithm, error) {
	switch s {
	case "ed25519", "Ed25519":
		return Ed25519, nil
	case "ecdsa-p256-sha256", "ecdsa-p256", "ecdsa", "p256", "P-256":
		return ECDSAP256, nil
	default:
		return "", fmt.Errorf("keys: unsupported algorithm %q (want ed25519 or ecdsa-p256)", s)
	}
}

// ErrInvalidSignature is returned by Verify when a signature does not verify.
var ErrInvalidSignature = errors.New("keys: invalid signature")

// PublicKey is a verification key with a stable key ID.
type PublicKey struct {
	alg   Algorithm
	key   crypto.PublicKey
	der   []byte
	keyID string
}

// Signer produces signatures over arbitrary messages.
type Signer interface {
	// Sign signs msg. For ECDSA the message is hashed with SHA-256 first.
	Sign(msg []byte) ([]byte, error)
	// Public returns the matching verification key.
	Public() *PublicKey
}

// NewPublicKey wraps a crypto public key. Only Ed25519 and ECDSA P-256 keys
// are accepted.
func NewPublicKey(pub crypto.PublicKey) (*PublicKey, error) {
	var alg Algorithm
	switch k := pub.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, errors.New("keys: malformed ed25519 public key")
		}
		alg = Ed25519
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("keys: unsupported ECDSA curve %s (only P-256)", k.Curve.Params().Name)
		}
		alg = ECDSAP256
	default:
		return nil, fmt.Errorf("keys: unsupported public key type %T", pub)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return &PublicKey{alg: alg, key: pub, der: der, keyID: hex.EncodeToString(sum[:])}, nil
}

// Algorithm returns the key's signature algorithm.
func (p *PublicKey) Algorithm() Algorithm { return p.alg }

// KeyID returns the hex SHA-256 of the PKIX encoding of the key.
func (p *PublicKey) KeyID() string { return p.keyID }

// Equal reports whether two keys are the same key.
func (p *PublicKey) Equal(o *PublicKey) bool {
	return p != nil && o != nil && p.keyID == o.keyID
}

// Verify checks sig over msg.
func (p *PublicKey) Verify(msg, sig []byte) error {
	switch p.alg {
	case Ed25519:
		if !ed25519.Verify(p.key.(ed25519.PublicKey), msg, sig) {
			return ErrInvalidSignature
		}
		return nil
	case ECDSAP256:
		digest := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(p.key.(*ecdsa.PublicKey), digest[:], sig) {
			return ErrInvalidSignature
		}
		return nil
	default:
		return fmt.Errorf("keys: unsupported algorithm %q", p.alg)
	}
}

// MarshalPEM encodes the key as a PKIX "PUBLIC KEY" PEM block.
func (p *PublicKey) MarshalPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p.der})
}

// ParsePublicPEM decodes a single PKIX "PUBLIC KEY" PEM block.
func ParsePublicPEM(data []byte) (*PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("keys: no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("keys: unexpected PEM type %q (want PUBLIC KEY)", block.Type)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("keys: trailing data after PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse public key: %w", err)
	}
	return NewPublicKey(pub)
}

type ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  *PublicKey
}

func (s *ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *ed25519Signer) Public() *PublicKey              { return s.pub }

type ecdsaSigner struct {
	priv *ecdsa.PrivateKey
	pub  *PublicKey
	rand io.Reader
}

func (s *ecdsaSigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(s.rand, s.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("keys: ecdsa sign: %w", err)
	}
	return sig, nil
}
func (s *ecdsaSigner) Public() *PublicKey { return s.pub }

// NewSigner wraps an Ed25519 or ECDSA P-256 private key.
func NewSigner(priv crypto.PrivateKey) (Signer, error) {
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, errors.New("keys: malformed ed25519 private key")
		}
		pub, err := NewPublicKey(k.Public())
		if err != nil {
			return nil, err
		}
		return &ed25519Signer{priv: k, pub: pub}, nil
	case *ecdsa.PrivateKey:
		pub, err := NewPublicKey(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		return &ecdsaSigner{priv: k, pub: pub, rand: rand.Reader}, nil
	default:
		return nil, fmt.Errorf("keys: unsupported private key type %T", priv)
	}
}

// Generate creates a new key pair. If r is nil, crypto/rand is used.
func Generate(alg Algorithm, r io.Reader) (Signer, error) {
	if r == nil {
		r = rand.Reader
	}
	switch alg {
	case Ed25519:
		_, priv, err := ed25519.GenerateKey(r)
		if err != nil {
			return nil, fmt.Errorf("keys: generate ed25519: %w", err)
		}
		return NewSigner(priv)
	case ECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), r)
		if err != nil {
			return nil, fmt.Errorf("keys: generate ecdsa: %w", err)
		}
		return NewSigner(priv)
	default:
		return nil, fmt.Errorf("keys: unsupported algorithm %q", alg)
	}
}

// MarshalPrivatePEM encodes a signer created by this package as a PKCS#8
// "PRIVATE KEY" PEM block.
func MarshalPrivatePEM(s Signer) ([]byte, error) {
	var priv crypto.PrivateKey
	switch k := s.(type) {
	case *ed25519Signer:
		priv = k.priv
	case *ecdsaSigner:
		priv = k.priv
	default:
		return nil, fmt.Errorf("keys: cannot marshal signer of type %T", s)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("keys: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivatePEM decodes a PKCS#8 "PRIVATE KEY" PEM block.
func ParsePrivatePEM(data []byte) (Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("keys: no PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("keys: unexpected PEM type %q (want PRIVATE KEY)", block.Type)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keys: parse private key: %w", err)
	}
	return NewSigner(priv)
}
