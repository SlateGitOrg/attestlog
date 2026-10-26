// Package bundle defines the offline verification bundle: an attestation
// envelope, the keys that signed it, and (optionally) the transparency-log
// receipt — log index, inclusion proof and the signed checkpoint it is
// anchored to. A bundle verifies without contacting the log.
package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/SlateGitOrg/attestlog/pkg/api"
	"github.com/SlateGitOrg/attestlog/pkg/checkpoint"
	"github.com/SlateGitOrg/attestlog/pkg/dsse"
	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/merkle"
	"github.com/SlateGitOrg/attestlog/pkg/note"
	"github.com/SlateGitOrg/attestlog/pkg/tlog"
)

// MediaType identifies the bundle format version.
const MediaType = "application/vnd.attestlog.bundle+json;version=0.1"

// ErrNoLogProof is returned when inclusion is checked on a bundle that has
// no log receipt.
var ErrNoLogProof = errors.New("bundle: no transparency log receipt")

// Bundle is the on-disk bundle document.
type Bundle struct {
	MediaType  string        `json:"mediaType"`
	Envelope   dsse.Envelope `json:"envelope"`
	PublicKeys []string      `json:"publicKeys"`
	Log        *LogReceipt   `json:"log,omitempty"`
}

// LogReceipt anchors the entry in a log.
type LogReceipt struct {
	LogIndex       uint64             `json:"logIndex"`
	Checkpoint     string             `json:"checkpoint"`
	InclusionProof api.InclusionProof `json:"inclusionProof"`
}

// New creates a bundle without a log receipt.
func New(env *dsse.Envelope, pubs ...*keys.PublicKey) (*Bundle, error) {
	e, err := tlog.NewEntry(env, pubs...)
	if err != nil {
		return nil, err
	}
	return &Bundle{MediaType: MediaType, Envelope: e.Spec.Envelope, PublicKeys: e.Spec.PublicKeys}, nil
}

// Entry reconstructs the log entry this bundle claims was logged.
func (b *Bundle) Entry() *tlog.Entry {
	return &tlog.Entry{
		APIVersion: tlog.EntryAPIVersion,
		Kind:       tlog.KindDSSE,
		Spec:       tlog.DSSESpec{Envelope: b.Envelope, PublicKeys: b.PublicKeys},
	}
}

// Keys parses the bundle's public keys.
func (b *Bundle) Keys() ([]*keys.PublicKey, error) { return b.Entry().Keys() }

// VerifyInclusion checks the receipt offline: the checkpoint must carry a
// valid signature from logKey, and the inclusion proof must link the leaf
// hash of the reconstructed entry to the checkpoint's root.
func (b *Bundle) VerifyInclusion(logKey *note.Verifier) (*checkpoint.Signed, error) {
	if b.Log == nil {
		return nil, ErrNoLogProof
	}
	cp, err := checkpoint.Open([]byte(b.Log.Checkpoint), logKey)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	p := b.Log.InclusionProof
	if p.TreeSize != cp.Size || p.LogIndex != b.Log.LogIndex {
		return nil, fmt.Errorf("bundle: proof (index %d, size %d) does not match receipt (index %d, checkpoint size %d)",
			p.LogIndex, p.TreeSize, b.Log.LogIndex, cp.Size)
	}
	body, err := b.Entry().Canonical()
	if err != nil {
		return nil, err
	}
	hashes, err := api.DecodeHashes(p.Hashes)
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	if err := merkle.VerifyInclusion(p.LogIndex, p.TreeSize, merkle.LeafHash(body), hashes, cp.Root); err != nil {
		return nil, fmt.Errorf("bundle: inclusion proof: %w", err)
	}
	return cp, nil
}

// Load reads a bundle file.
func Load(path string) (*Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bundle: read: %w", err)
	}
	return Parse(data)
}

// Parse decodes a bundle and checks its media type.
func Parse(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("bundle: decode: %w", err)
	}
	if b.MediaType != MediaType {
		return nil, fmt.Errorf("bundle: unsupported mediaType %q", b.MediaType)
	}
	if err := b.Envelope.Validate(); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	return &b, nil
}

// Marshal encodes the bundle as indented JSON.
func (b *Bundle) Marshal() ([]byte, error) {
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("bundle: encode: %w", err)
	}
	return append(out, '\n'), nil
}
