// Package note implements C2SP signed notes with Ed25519 keys, the envelope
// used for transparency-log checkpoints (https://c2sp.org/signed-note).
//
// A signed note is UTF-8 text ending in a newline, a blank line, and one or
// more signature lines:
//
//	<text>\n
//	\n
//	— <key name> <base64(4-byte key hash || 64-byte signature)>\n
//
// The key hash is the first four bytes of
// SHA-256(name || "\n" || 0x01 || public key), which lets a verifier pick
// the right key without trying all of them. Keys are written as
// "<name>+<hex hash>+<base64(0x01 || key)>"; private keys carry a
// "PRIVATE+KEY+" prefix and the 32-byte seed. The format is wire-compatible
// with golang.org/x/mod/sumdb/note.
package note

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const algEd25519 = 0x01

// MaxNoteSize bounds note parsing to avoid unbounded allocation.
const MaxNoteSize = 1 << 16

var (
	// ErrMalformedNote reports a note that does not follow the format.
	ErrMalformedNote = errors.New("note: malformed note")
	// ErrUnverified reports that no signature from a known key verified.
	ErrUnverified = errors.New("note: no verifiable signature from a known key")
	// ErrInvalidSignature reports a signature from a known key that failed.
	ErrInvalidSignature = errors.New("note: invalid signature from known key")
	// ErrMalformedKey reports an unparsable key string.
	ErrMalformedKey = errors.New("note: malformed key")
)

func keyHash(name string, keyWithAlg []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(keyWithAlg)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

func isValidName(name string) bool {
	return name != "" && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsSpace) < 0 &&
		!strings.Contains(name, "+")
}

// Signer signs notes with an Ed25519 key.
type Signer struct {
	name string
	hash uint32
	key  ed25519.PrivateKey
}

// Verifier verifies note signatures from one Ed25519 key.
type Verifier struct {
	name string
	hash uint32
	key  ed25519.PublicKey
}

// Name returns the key name.
func (s *Signer) Name() string { return s.name }

// KeyHash returns the 32-bit key hash.
func (s *Signer) KeyHash() uint32 { return s.hash }

// Verifier returns the verifier for this signer.
func (s *Signer) Verifier() *Verifier {
	return &Verifier{name: s.name, hash: s.hash, key: s.key.Public().(ed25519.PublicKey)}
}

// Name returns the key name.
func (v *Verifier) Name() string { return v.name }

// KeyHash returns the 32-bit key hash.
func (v *Verifier) KeyHash() uint32 { return v.hash }

// String renders the verifier key in "<name>+<hash>+<base64>" form.
func (v *Verifier) String() string {
	return fmt.Sprintf("%s+%08x+%s", v.name, v.hash,
		base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, v.key...)))
}

// GenerateKey creates a new key pair and returns the encoded private
// ("PRIVATE+KEY+...") and public key strings. If r is nil crypto/rand is used.
func GenerateKey(r io.Reader, name string) (skey, vkey string, err error) {
	if !isValidName(name) {
		return "", "", fmt.Errorf("%w: invalid key name %q", ErrMalformedKey, name)
	}
	if r == nil {
		r = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return "", "", fmt.Errorf("note: generate key: %w", err)
	}
	pubk := append([]byte{algEd25519}, pub...)
	h := keyHash(name, pubk)
	skey = fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, h,
		base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, priv.Seed()...)))
	vkey = fmt.Sprintf("%s+%08x+%s", name, h, base64.StdEncoding.EncodeToString(pubk))
	return skey, vkey, nil
}

func parseKey(s string) (name string, hash uint32, key []byte, err error) {
	name, rest, ok1 := strings.Cut(s, "+")
	hexHash, b64, ok2 := strings.Cut(rest, "+")
	if !ok1 || !ok2 || !isValidName(name) || len(hexHash) != 8 {
		return "", 0, nil, ErrMalformedKey
	}
	h, err := strconv.ParseUint(hexHash, 16, 32)
	if err != nil {
		return "", 0, nil, ErrMalformedKey
	}
	key, err = base64.StdEncoding.DecodeString(b64)
	if err != nil || len(key) == 0 || key[0] != algEd25519 {
		return "", 0, nil, ErrMalformedKey
	}
	return name, uint32(h), key, nil
}

// NewSigner parses a "PRIVATE+KEY+..." string.
func NewSigner(skey string) (*Signer, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(skey), "PRIVATE+KEY+")
	if !ok {
		return nil, ErrMalformedKey
	}
	name, h, key, err := parseKey(rest)
	if err != nil {
		return nil, err
	}
	if len(key) != 1+ed25519.SeedSize {
		return nil, ErrMalformedKey
	}
	priv := ed25519.NewKeyFromSeed(key[1:])
	pubk := append([]byte{algEd25519}, priv.Public().(ed25519.PublicKey)...)
	if keyHash(name, pubk) != h {
		return nil, fmt.Errorf("%w: key hash mismatch", ErrMalformedKey)
	}
	return &Signer{name: name, hash: h, key: priv}, nil
}

// NewVerifier parses a "<name>+<hash>+<base64>" verifier key string.
func NewVerifier(vkey string) (*Verifier, error) {
	name, h, key, err := parseKey(strings.TrimSpace(vkey))
	if err != nil {
		return nil, err
	}
	if len(key) != 1+ed25519.PublicKeySize {
		return nil, ErrMalformedKey
	}
	if keyHash(name, key) != h {
		return nil, fmt.Errorf("%w: key hash mismatch", ErrMalformedKey)
	}
	return &Verifier{name: name, hash: h, key: ed25519.PublicKey(key[1:])}, nil
}

// Signature is one parsed signature line.
type Signature struct {
	Name  string
	Hash  uint32
	Bytes []byte // signature without the 4-byte key hash
}

// Note is an opened note.
type Note struct {
	Text string
	// Verified holds signatures that verified against a supplied verifier.
	Verified []Signature
	// Unverified holds signatures from keys the caller did not supply.
	Unverified []Signature
}

func validText(text string) error {
	if !utf8.ValidString(text) || !strings.HasSuffix(text, "\n") || strings.Contains(text, "\n\n") ||
		strings.ContainsAny(text, "\r\t\x00") {
		return fmt.Errorf("%w: text must be valid UTF-8, end in a newline and contain no blank lines", ErrMalformedNote)
	}
	return nil
}

// Sign returns text followed by signature lines from every signer.
func Sign(text string, signers ...*Signer) ([]byte, error) {
	if err := validText(text); err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, errors.New("note: no signers")
	}
	var buf bytes.Buffer
	buf.WriteString(text)
	buf.WriteString("\n")
	for _, s := range signers {
		sig := ed25519.Sign(s.key, []byte(text))
		var hb [4]byte
		binary.BigEndian.PutUint32(hb[:], s.hash)
		fmt.Fprintf(&buf, "— %s %s\n", s.name, base64.StdEncoding.EncodeToString(append(hb[:], sig...)))
	}
	return buf.Bytes(), nil
}

// Open parses msg and verifies its signatures. It succeeds only if at least
// one signature verifies; a signature from a known key that fails to verify
// is a hard error (it indicates tampering, not an unknown witness).
func Open(msg []byte, verifiers ...*Verifier) (*Note, error) {
	if len(msg) > MaxNoteSize {
		return nil, fmt.Errorf("%w: note too large", ErrMalformedNote)
	}
	s := string(msg)
	split := strings.LastIndex(s, "\n\n")
	if split < 0 {
		return nil, fmt.Errorf("%w: missing signature block", ErrMalformedNote)
	}
	text, sigBlock := s[:split+1], s[split+2:]
	if err := validText(text); err != nil {
		return nil, err
	}
	if sigBlock == "" || !strings.HasSuffix(sigBlock, "\n") {
		return nil, fmt.Errorf("%w: empty or unterminated signature block", ErrMalformedNote)
	}
	n := &Note{Text: text}
	seen := map[uint32]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(sigBlock, "\n"), "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			return nil, fmt.Errorf("%w: bad signature line %q", ErrMalformedNote, line)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok || !isValidName(name) {
			return nil, fmt.Errorf("%w: bad signature line %q", ErrMalformedNote, line)
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) < 5 {
			return nil, fmt.Errorf("%w: bad signature encoding", ErrMalformedNote)
		}
		sig := Signature{Name: name, Hash: binary.BigEndian.Uint32(raw[:4]), Bytes: raw[4:]}
		v := findVerifier(verifiers, name, sig.Hash)
		if v == nil {
			n.Unverified = append(n.Unverified, sig)
			continue
		}
		if seen[sig.Hash] {
			return nil, fmt.Errorf("%w: duplicate signature from %s", ErrMalformedNote, name)
		}
		seen[sig.Hash] = true
		if len(sig.Bytes) != ed25519.SignatureSize || !ed25519.Verify(v.key, []byte(text), sig.Bytes) {
			return nil, fmt.Errorf("%w: %s+%08x", ErrInvalidSignature, name, sig.Hash)
		}
		n.Verified = append(n.Verified, sig)
	}
	if len(n.Verified) == 0 {
		return nil, ErrUnverified
	}
	return n, nil
}

func findVerifier(vs []*Verifier, name string, hash uint32) *Verifier {
	for _, v := range vs {
		if v.name == name && v.hash == hash {
			return v
		}
	}
	return nil
}
