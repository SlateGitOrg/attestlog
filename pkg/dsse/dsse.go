// Package dsse implements Dead Simple Signing Envelopes (DSSE v1).
//
// The signature in a DSSE envelope covers the Pre-Authentication Encoding
// (PAE) of the payload type and payload, never the raw JSON. This prevents
// type-confusion attacks where the same bytes are interpreted under a
// different payload type.
//
//	PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
//
// where LEN is the ASCII decimal byte length and SP is a single space.
package dsse

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/archit2501/attestlog/pkg/keys"
)

// MaxPayloadSize bounds decoded payloads to keep verification memory-safe.
const MaxPayloadSize = 4 << 20

// Envelope is the DSSE JSON envelope.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signature inside an envelope. KeyID is an unauthenticated
// hint; verification never trusts it for anything but key selection order.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Errors returned by verification.
var (
	ErrNoSignatures     = errors.New("dsse: envelope has no signatures")
	ErrThresholdNotMet  = errors.New("dsse: signature threshold not met")
	ErrMalformed        = errors.New("dsse: malformed envelope")
	ErrPayloadTooLarge  = errors.New("dsse: payload too large")
	ErrNoVerifiers      = errors.New("dsse: no verification keys supplied")
	ErrInvalidThreshold = errors.New("dsse: threshold must be >= 1")
)

// PAE returns the pre-authentication encoding of payloadType and payload.
func PAE(payloadType string, payload []byte) []byte {
	t := strconv.Itoa(len(payloadType))
	p := strconv.Itoa(len(payload))
	out := make([]byte, 0, 6+1+len(t)+1+len(payloadType)+1+len(p)+1+len(payload))
	out = append(out, "DSSEv1 "...)
	out = append(out, t...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, p...)
	out = append(out, ' ')
	out = append(out, payload...)
	return out
}

// Sign creates an envelope over payload signed by every signer.
func Sign(payloadType string, payload []byte, signers ...keys.Signer) (*Envelope, error) {
	if payloadType == "" {
		return nil, fmt.Errorf("%w: empty payload type", ErrMalformed)
	}
	if len(signers) == 0 {
		return nil, errors.New("dsse: at least one signer required")
	}
	if len(payload) > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	env := &Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
	}
	pae := PAE(payloadType, payload)
	for _, s := range signers {
		sig, err := s.Sign(pae)
		if err != nil {
			return nil, fmt.Errorf("dsse: sign: %w", err)
		}
		env.Signatures = append(env.Signatures, Signature{
			KeyID: s.Public().KeyID(),
			Sig:   base64.StdEncoding.EncodeToString(sig),
		})
	}
	return env, nil
}

// decodeB64 accepts standard or URL-safe base64, padded or not, as the DSSE
// specification permits either.
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w: invalid base64", ErrMalformed)
}

// DecodePayload returns the raw payload bytes.
func (e *Envelope) DecodePayload() ([]byte, error) {
	if base64.StdEncoding.DecodedLen(len(e.Payload)) > MaxPayloadSize+3 {
		return nil, ErrPayloadTooLarge
	}
	return decodeB64(e.Payload)
}

// Verification describes a successful verification.
type Verification struct {
	// AcceptedKeys holds the key IDs of the distinct trusted keys that
	// produced a valid signature, in the order they were first matched.
	AcceptedKeys []string
	// Payload is the decoded, authenticated payload.
	Payload []byte
}

// Verify checks that at least threshold distinct keys from verifiers signed
// the envelope. A single key signing twice counts once.
func (e *Envelope) Verify(threshold int, verifiers ...*keys.PublicKey) (*Verification, error) {
	if threshold < 1 {
		return nil, ErrInvalidThreshold
	}
	if len(verifiers) == 0 {
		return nil, ErrNoVerifiers
	}
	if e.PayloadType == "" {
		return nil, fmt.Errorf("%w: empty payload type", ErrMalformed)
	}
	if len(e.Signatures) == 0 {
		return nil, ErrNoSignatures
	}
	payload, err := e.DecodePayload()
	if err != nil {
		return nil, err
	}
	pae := PAE(e.PayloadType, payload)

	accepted := make(map[string]bool)
	var order []string
	for _, s := range e.Signatures {
		raw, err := decodeB64(s.Sig)
		if err != nil || len(raw) == 0 {
			continue
		}
		for _, v := range orderedVerifiers(verifiers, s.KeyID) {
			if accepted[v.KeyID()] {
				continue
			}
			if v.Verify(pae, raw) == nil {
				accepted[v.KeyID()] = true
				order = append(order, v.KeyID())
				break
			}
		}
	}
	if len(order) < threshold {
		return nil, fmt.Errorf("%w: %d of %d required valid signatures", ErrThresholdNotMet, len(order), threshold)
	}
	return &Verification{AcceptedKeys: order, Payload: payload}, nil
}

// orderedVerifiers tries the key whose ID matches the hint first; the hint
// only optimises the search and never excludes other keys.
func orderedVerifiers(vs []*keys.PublicKey, hint string) []*keys.PublicKey {
	if hint == "" {
		return vs
	}
	out := make([]*keys.PublicKey, 0, len(vs))
	for _, v := range vs {
		if v.KeyID() == hint {
			out = append(out, v)
		}
	}
	for _, v := range vs {
		if v.KeyID() != hint {
			out = append(out, v)
		}
	}
	return out
}

// Parse decodes a JSON envelope and performs structural validation.
func Parse(data []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return &env, nil
}

// Validate performs structural checks without verifying signatures.
func (e *Envelope) Validate() error {
	if e.PayloadType == "" {
		return fmt.Errorf("%w: empty payloadType", ErrMalformed)
	}
	if e.Payload == "" {
		return fmt.Errorf("%w: empty payload", ErrMalformed)
	}
	if len(e.Signatures) == 0 {
		return ErrNoSignatures
	}
	for i, s := range e.Signatures {
		if s.Sig == "" {
			return fmt.Errorf("%w: signature %d is empty", ErrMalformed, i)
		}
	}
	if _, err := e.DecodePayload(); err != nil {
		return err
	}
	return nil
}
