// Package checkpoint implements transparency-log checkpoints (signed tree
// heads) in the C2SP tlog-checkpoint format, carried in a signed note:
//
//	<origin>\n
//	<tree size, decimal>\n
//	<root hash, base64>\n
//	[extension lines]\n
//
// attestlog adds one extension line, "timestamp <unix milliseconds>", the
// time the log signed the head (the RFC 6962 STH timestamp).
package checkpoint

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/archit2501/attestlog/pkg/merkle"
	"github.com/archit2501/attestlog/pkg/note"
)

// ErrMalformed is returned for unparsable checkpoint bodies.
var ErrMalformed = errors.New("checkpoint: malformed checkpoint")

const timestampPrefix = "timestamp "

// Checkpoint is an unsigned tree head.
type Checkpoint struct {
	Origin    string
	Size      uint64
	Root      merkle.Hash
	Timestamp time.Time // zero if absent
	// Extensions holds any other extension lines, preserved verbatim.
	Extensions []string
}

// Marshal renders the checkpoint body (the signed-note text).
func (c *Checkpoint) Marshal() (string, error) {
	if c.Origin == "" || strings.ContainsAny(c.Origin, "\n") {
		return "", fmt.Errorf("%w: invalid origin", ErrMalformed)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Size, base64.StdEncoding.EncodeToString(c.Root[:]))
	if !c.Timestamp.IsZero() {
		fmt.Fprintf(&b, "%s%d\n", timestampPrefix, c.Timestamp.UnixMilli())
	}
	for _, e := range c.Extensions {
		if e == "" || strings.Contains(e, "\n") {
			return "", fmt.Errorf("%w: invalid extension line", ErrMalformed)
		}
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// Parse decodes a checkpoint body.
func Parse(text string) (*Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return nil, fmt.Errorf("%w: missing trailing newline", ErrMalformed)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("%w: need at least 3 lines", ErrMalformed)
	}
	c := &Checkpoint{Origin: lines[0]}
	if c.Origin == "" {
		return nil, fmt.Errorf("%w: empty origin", ErrMalformed)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || (len(lines[1]) > 1 && lines[1][0] == '0') {
		return nil, fmt.Errorf("%w: bad tree size %q", ErrMalformed, lines[1])
	}
	c.Size = size
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad root hash encoding", ErrMalformed)
	}
	if c.Root, err = merkle.HashFromBytes(root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	for _, l := range lines[3:] {
		if l == "" {
			return nil, fmt.Errorf("%w: empty extension line", ErrMalformed)
		}
		if ts, ok := strings.CutPrefix(l, timestampPrefix); ok && c.Timestamp.IsZero() {
			ms, err := strconv.ParseInt(ts, 10, 64)
			if err != nil || ms < 0 {
				return nil, fmt.Errorf("%w: bad timestamp", ErrMalformed)
			}
			c.Timestamp = time.UnixMilli(ms).UTC()
			continue
		}
		c.Extensions = append(c.Extensions, l)
	}
	return c, nil
}

// Signed is a checkpoint together with the exact signed-note bytes it came
// from. The raw bytes are kept because they are the evidence: two Signed
// values with valid signatures and conflicting contents prove misbehaviour.
type Signed struct {
	Checkpoint
	Raw []byte
}

// Sign marshals and signs a checkpoint.
func Sign(c *Checkpoint, signer *note.Signer) (*Signed, error) {
	if c.Origin != signer.Name() {
		return nil, fmt.Errorf("checkpoint: origin %q does not match key name %q", c.Origin, signer.Name())
	}
	text, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	raw, err := note.Sign(text, signer)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: sign: %w", err)
	}
	return &Signed{Checkpoint: *c, Raw: raw}, nil
}

// Open verifies the log's signature on raw and parses the checkpoint. The
// origin line must equal the verifier's key name, binding the checkpoint to
// the log identity.
func Open(raw []byte, logKey *note.Verifier) (*Signed, error) {
	n, err := note.Open(raw, logKey)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	c, err := Parse(n.Text)
	if err != nil {
		return nil, err
	}
	if c.Origin != logKey.Name() {
		return nil, fmt.Errorf("checkpoint: origin %q does not match log key %q", c.Origin, logKey.Name())
	}
	return &Signed{Checkpoint: *c, Raw: append([]byte(nil), raw...)}, nil
}
