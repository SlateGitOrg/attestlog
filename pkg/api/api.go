// Package api defines the JSON wire types of the attestlog HTTP API, shared
// by the server and the verifying client.
//
// Endpoints (all under /api/v1/log):
//
//	POST /entries                      submit a DSSE entry          -> SubmitResponse
//	GET  /entries/{index}              fetch an entry body          -> EntryResponse
//	GET  /entries?subject=alg:hex      search by subject digest     -> SearchResponse
//	GET  /checkpoint                   latest signed checkpoint     (text/plain signed note)
//	GET  /proof/inclusion?index=&treeSize=      or ?leafHash=&treeSize= -> InclusionProof
//	GET  /proof/consistency?from=&to=  consistency proof            -> ConsistencyProof
//	GET  /publickey                    checkpoint verifier key      (text/plain)
package api

import (
	"encoding/hex"
	"fmt"

	"github.com/archit2501/attestlog/pkg/dsse"
	"github.com/archit2501/attestlog/pkg/merkle"
)

// Paths.
const (
	PathPrefix       = "/api/v1/log"
	PathEntries      = PathPrefix + "/entries"
	PathCheckpoint   = PathPrefix + "/checkpoint"
	PathInclusion    = PathPrefix + "/proof/inclusion"
	PathConsistency  = PathPrefix + "/proof/consistency"
	PathPublicKey    = PathPrefix + "/publickey"
	PathHealth       = "/healthz"
	CheckpointMedia  = "text/plain; charset=utf-8"
	MaxRequestBodyKB = 2048
)

// SubmitRequest submits an envelope and the public keys that signed it.
type SubmitRequest struct {
	Envelope   dsse.Envelope `json:"envelope"`
	PublicKeys []string      `json:"publicKeys"`
}

// SubmitResponse is returned for accepted (or duplicate) entries.
type SubmitResponse struct {
	LogIndex       uint64         `json:"logIndex"`
	LeafHash       string         `json:"leafHash"`
	Duplicate      bool           `json:"duplicate"`
	Checkpoint     string         `json:"checkpoint"`
	InclusionProof InclusionProof `json:"inclusionProof"`
}

// EntryResponse carries an entry's canonical body (base64 in JSON).
type EntryResponse struct {
	LogIndex uint64 `json:"logIndex"`
	LeafHash string `json:"leafHash"`
	Body     []byte `json:"body"`
}

// SearchResponse lists matching entry indices.
type SearchResponse struct {
	LogIndices []uint64 `json:"logIndices"`
}

// InclusionProof is an audit path; hashes are hex, leaf-to-root.
type InclusionProof struct {
	LogIndex uint64   `json:"logIndex"`
	TreeSize uint64   `json:"treeSize"`
	Hashes   []string `json:"hashes"`
}

// ConsistencyProof proves tree From is a prefix of tree To.
type ConsistencyProof struct {
	From   uint64   `json:"from"`
	To     uint64   `json:"to"`
	Hashes []string `json:"hashes"`
}

// ErrorResponse is the body of every non-2xx JSON response.
type ErrorResponse struct {
	Error string `json:"error"`
}

// EncodeHashes renders hashes as hex strings.
func EncodeHashes(hs []merkle.Hash) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = h.String()
	}
	return out
}

// DecodeHashes parses hex hashes, rejecting any malformed element.
func DecodeHashes(ss []string) ([]merkle.Hash, error) {
	out := make([]merkle.Hash, len(ss))
	for i, s := range ss {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("api: proof hash %d: %w", i, err)
		}
		if out[i], err = merkle.HashFromBytes(b); err != nil {
			return nil, fmt.Errorf("api: proof hash %d: %w", i, err)
		}
	}
	return out, nil
}
