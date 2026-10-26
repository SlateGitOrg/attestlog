package tlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/SlateGitOrg/attestlog/pkg/dsse"
	"github.com/SlateGitOrg/attestlog/pkg/intoto"
	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/merkle"
)

// Entry kinds and versions understood by this log.
const (
	EntryAPIVersion = "attestlog/v1"
	KindDSSE        = "dsse"
	// MaxEntrySize bounds a canonical entry body.
	MaxEntrySize = 1 << 20
)

// ErrInvalidEntry wraps all entry validation failures.
var ErrInvalidEntry = errors.New("tlog: invalid entry")

// Entry is the body that is hashed into a leaf. Its canonical encoding is
// the Go JSON encoding of this struct with public keys normalised (PKIX PEM,
// sorted by key ID, de-duplicated), so a given envelope and key set always
// produce the same leaf hash.
type Entry struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Spec       DSSESpec `json:"spec"`
}

// DSSESpec is the payload of a "dsse" entry.
type DSSESpec struct {
	Envelope   dsse.Envelope `json:"envelope"`
	PublicKeys []string      `json:"publicKeys"`
}

// NewEntry builds an entry from an envelope and the keys that signed it.
func NewEntry(env *dsse.Envelope, pubs ...*keys.PublicKey) (*Entry, error) {
	if env == nil {
		return nil, fmt.Errorf("%w: nil envelope", ErrInvalidEntry)
	}
	if len(pubs) == 0 {
		return nil, fmt.Errorf("%w: at least one public key required", ErrInvalidEntry)
	}
	sorted := slices.Clone(pubs)
	slices.SortFunc(sorted, func(a, b *keys.PublicKey) int { return bytes.Compare([]byte(a.KeyID()), []byte(b.KeyID())) })
	sorted = slices.CompactFunc(sorted, func(a, b *keys.PublicKey) bool { return a.Equal(b) })
	pems := make([]string, len(sorted))
	for i, p := range sorted {
		pems[i] = string(p.MarshalPEM())
	}
	return &Entry{APIVersion: EntryAPIVersion, Kind: KindDSSE, Spec: DSSESpec{Envelope: *env, PublicKeys: pems}}, nil
}

// Canonical returns the canonical body bytes.
func (e *Entry) Canonical() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("tlog: encode entry: %w", err)
	}
	if len(b) > MaxEntrySize {
		return nil, fmt.Errorf("%w: entry is %d bytes, max %d", ErrInvalidEntry, len(b), MaxEntrySize)
	}
	return b, nil
}

// LeafHash returns the Merkle leaf hash of the canonical body.
func (e *Entry) LeafHash() (merkle.Hash, error) {
	b, err := e.Canonical()
	if err != nil {
		return merkle.Hash{}, err
	}
	return merkle.LeafHash(b), nil
}

// ParseEntry decodes body strictly and requires it to be in canonical form,
// so that there is exactly one byte string (and one leaf hash) per entry.
func ParseEntry(body []byte) (*Entry, error) {
	if len(body) > MaxEntrySize {
		return nil, fmt.Errorf("%w: entry too large", ErrInvalidEntry)
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var e Entry
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	if e.APIVersion != EntryAPIVersion || e.Kind != KindDSSE {
		return nil, fmt.Errorf("%w: unsupported apiVersion/kind %q/%q", ErrInvalidEntry, e.APIVersion, e.Kind)
	}
	canon, err := e.Canonical()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canon, body) {
		return nil, fmt.Errorf("%w: body is not in canonical form", ErrInvalidEntry)
	}
	return &e, nil
}

// VerifiedEntry is the result of checking an entry's signatures.
type VerifiedEntry struct {
	Statement *intoto.Statement
	KeyIDs    []string
}

// Keys parses the entry's public keys.
func (e *Entry) Keys() ([]*keys.PublicKey, error) {
	if len(e.Spec.PublicKeys) == 0 {
		return nil, fmt.Errorf("%w: no public keys", ErrInvalidEntry)
	}
	out := make([]*keys.PublicKey, 0, len(e.Spec.PublicKeys))
	for i, p := range e.Spec.PublicKeys {
		k, err := keys.ParsePublicPEM([]byte(p))
		if err != nil {
			return nil, fmt.Errorf("%w: public key %d: %w", ErrInvalidEntry, i, err)
		}
		out = append(out, k)
	}
	return out, nil
}

// Verify checks that every listed key signed the envelope and that the
// payload is a valid in-toto statement. Requiring all keys to have signed
// stops an uploader from attaching unrelated keys to an entry (which would
// make searches by key misleading).
func (e *Entry) Verify() (*VerifiedEntry, error) {
	ks, err := e.Keys()
	if err != nil {
		return nil, err
	}
	if e.Spec.Envelope.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("%w: payloadType %q, want %q", ErrInvalidEntry, e.Spec.Envelope.PayloadType, intoto.PayloadType)
	}
	v, err := e.Spec.Envelope.Verify(len(ks), ks...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	st, err := intoto.ParseStatement(v.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEntry, err)
	}
	return &VerifiedEntry{Statement: st, KeyIDs: v.AcceptedKeys}, nil
}
