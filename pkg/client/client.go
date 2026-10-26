// Package client is a verifying HTTP client for an attestlog server. It
// treats the server as untrusted: checkpoints are checked against the
// pinned log key, entries are re-hashed locally, and every proof is
// verified before a result is returned.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/SlateGitOrg/attestlog/pkg/api"
	"github.com/SlateGitOrg/attestlog/pkg/bundle"
	"github.com/SlateGitOrg/attestlog/pkg/checkpoint"
	"github.com/SlateGitOrg/attestlog/pkg/dsse"
	"github.com/SlateGitOrg/attestlog/pkg/intoto"
	"github.com/SlateGitOrg/attestlog/pkg/keys"
	"github.com/SlateGitOrg/attestlog/pkg/merkle"
	"github.com/SlateGitOrg/attestlog/pkg/note"
	"github.com/SlateGitOrg/attestlog/pkg/tlog"
)

// maxResponse bounds every response body read from the server.
const maxResponse = 4 << 20

// ErrServer wraps non-2xx responses.
var ErrServer = errors.New("client: server error")

// ErrMisbehaviour reports a server response that failed verification.
var ErrMisbehaviour = errors.New("client: log response failed verification")

// Client talks to one log.
type Client struct {
	base   *url.URL
	hc     *http.Client
	logKey *note.Verifier
}

// New returns a client for the log at baseURL whose checkpoints must verify
// under logKey. If hc is nil a client with a 30s timeout is used.
func New(baseURL string, logKey *note.Verifier, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("client: invalid server URL %q", baseURL)
	}
	if logKey == nil {
		return nil, errors.New("client: log key is required")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: u, hc: hc, logKey: logKey}, nil
}

// LogKey returns the pinned checkpoint verifier.
func (c *Client) LogKey() *note.Verifier { return c.logKey }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body []byte) ([]byte, error) {
	u := *c.base
	u.Path += path
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, fmt.Errorf("client: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("client: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("client: read response: %w", err)
	}
	if len(data) > maxResponse {
		return nil, fmt.Errorf("client: response exceeds %d bytes", maxResponse)
	}
	if resp.StatusCode/100 != 2 {
		var e api.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("%w: %d: %s", ErrServer, resp.StatusCode, e.Error)
		}
		return nil, fmt.Errorf("%w: status %d", ErrServer, resp.StatusCode)
	}
	return data, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	data, err := c.do(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("client: decode %s: %w", path, err)
	}
	return nil
}

// Checkpoint fetches and verifies the latest signed checkpoint.
func (c *Client) Checkpoint(ctx context.Context) (*checkpoint.Signed, error) {
	data, err := c.do(ctx, http.MethodGet, api.PathCheckpoint, nil, nil)
	if err != nil {
		return nil, err
	}
	cp, err := checkpoint.Open(data, c.logKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMisbehaviour, err)
	}
	return cp, nil
}

// Submit logs env and returns a bundle carrying a verified receipt.
func (c *Client) Submit(ctx context.Context, env *dsse.Envelope, pubs ...*keys.PublicKey) (*bundle.Bundle, bool, error) {
	b, err := bundle.New(env, pubs...)
	if err != nil {
		return nil, false, err
	}
	reqBody, err := json.Marshal(api.SubmitRequest{Envelope: b.Envelope, PublicKeys: b.PublicKeys})
	if err != nil {
		return nil, false, fmt.Errorf("client: encode request: %w", err)
	}
	data, err := c.do(ctx, http.MethodPost, api.PathEntries, nil, reqBody)
	if err != nil {
		return nil, false, err
	}
	var resp api.SubmitResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, false, fmt.Errorf("client: decode submit response: %w", err)
	}
	b.Log = &bundle.LogReceipt{
		LogIndex:       resp.LogIndex,
		Checkpoint:     resp.Checkpoint,
		InclusionProof: resp.InclusionProof,
	}
	// The receipt is only useful if it verifies; check it now so a lying
	// server is caught at submission time, not at the first audit.
	if _, err := b.VerifyInclusion(c.logKey); err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrMisbehaviour, err)
	}
	return b, resp.Duplicate, nil
}

// Entry fetches entry index, checks the server's leaf hash against the body
// and returns the parsed entry with its locally computed leaf hash.
func (c *Client) Entry(ctx context.Context, index uint64) (*tlog.Entry, merkle.Hash, error) {
	var resp api.EntryResponse
	if err := c.getJSON(ctx, api.PathEntries+"/"+strconv.FormatUint(index, 10), nil, &resp); err != nil {
		return nil, merkle.Hash{}, err
	}
	leaf := merkle.LeafHash(resp.Body)
	if resp.LeafHash != leaf.String() || resp.LogIndex != index {
		return nil, merkle.Hash{}, fmt.Errorf("%w: entry %d leaf hash or index mismatch", ErrMisbehaviour, index)
	}
	e, err := tlog.ParseEntry(resp.Body)
	if err != nil {
		return nil, merkle.Hash{}, fmt.Errorf("%w: %w", ErrMisbehaviour, err)
	}
	return e, leaf, nil
}

// InclusionProof fetches the raw audit path for index at treeSize.
func (c *Client) InclusionProof(ctx context.Context, index, treeSize uint64) ([]merkle.Hash, error) {
	q := url.Values{"index": {strconv.FormatUint(index, 10)}, "treeSize": {strconv.FormatUint(treeSize, 10)}}
	var resp api.InclusionProof
	if err := c.getJSON(ctx, api.PathInclusion, q, &resp); err != nil {
		return nil, err
	}
	if resp.LogIndex != index || resp.TreeSize != treeSize {
		return nil, fmt.Errorf("%w: proof is for a different index or size", ErrMisbehaviour)
	}
	return api.DecodeHashes(resp.Hashes)
}

// VerifyInclusion proves leaf is at index in the tree committed to by cp.
func (c *Client) VerifyInclusion(ctx context.Context, index uint64, leaf merkle.Hash, cp *checkpoint.Signed) ([]merkle.Hash, error) {
	proof, err := c.InclusionProof(ctx, index, cp.Size)
	if err != nil {
		return nil, err
	}
	if err := merkle.VerifyInclusion(index, cp.Size, leaf, proof, cp.Root); err != nil {
		return proof, fmt.Errorf("%w: inclusion of %d in tree %d: %w", ErrMisbehaviour, index, cp.Size, err)
	}
	return proof, nil
}

// ConsistencyProof fetches the raw proof that tree from is a prefix of to.
func (c *Client) ConsistencyProof(ctx context.Context, from, to uint64) ([]merkle.Hash, error) {
	q := url.Values{"from": {strconv.FormatUint(from, 10)}, "to": {strconv.FormatUint(to, 10)}}
	var resp api.ConsistencyProof
	if err := c.getJSON(ctx, api.PathConsistency, q, &resp); err != nil {
		return nil, err
	}
	if resp.From != from || resp.To != to {
		return nil, fmt.Errorf("%w: proof is for different sizes", ErrMisbehaviour)
	}
	return api.DecodeHashes(resp.Hashes)
}

// Search returns indices of entries whose subject matches d.
func (c *Client) Search(ctx context.Context, d intoto.DigestSet) ([]uint64, error) {
	var out []uint64
	seen := map[uint64]bool{}
	for alg, v := range d {
		var resp api.SearchResponse
		if err := c.getJSON(ctx, api.PathEntries, url.Values{"subject": {alg + ":" + v}}, &resp); err != nil {
			return nil, err
		}
		for _, i := range resp.LogIndices {
			if !seen[i] {
				seen[i] = true
				out = append(out, i)
			}
		}
	}
	return out, nil
}
