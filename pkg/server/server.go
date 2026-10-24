// Package server exposes a tlog.Log over HTTP. The server is deliberately
// untrusted by design: every response it produces is verifiable by the
// client against the log's public key (see package client).
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/archit2501/attestlog/pkg/api"
	"github.com/archit2501/attestlog/pkg/intoto"
	"github.com/archit2501/attestlog/pkg/keys"
	"github.com/archit2501/attestlog/pkg/merkle"
	"github.com/archit2501/attestlog/pkg/tlog"
)

// Server is the HTTP front end of a log.
type Server struct {
	log    *tlog.Log
	logger *slog.Logger
	mux    *http.ServeMux
}

// New builds the handler tree for l.
func New(l *tlog.Log, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s := &Server{log: l, logger: logger, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST "+api.PathEntries, s.handleSubmit)
	s.mux.HandleFunc("GET "+api.PathEntries+"/{index}", s.handleEntry)
	s.mux.HandleFunc("GET "+api.PathEntries, s.handleSearch)
	s.mux.HandleFunc("GET "+api.PathCheckpoint, s.handleCheckpoint)
	s.mux.HandleFunc("GET "+api.PathInclusion, s.handleInclusion)
	s.mux.HandleFunc("GET "+api.PathConsistency, s.handleConsistency)
	s.mux.HandleFunc("GET "+api.PathPublicKey, s.handlePublicKey)
	s.mux.HandleFunc("GET "+api.PathHealth, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "treeSize": l.Size()})
	})
	return s
}

// HTTPServer wraps the handler in an http.Server with conservative timeouts.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// statusRecorder captures the response status for access logs.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// ServeHTTP adds panic recovery and structured access logging.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	defer func() {
		if p := recover(); p != nil {
			s.logger.Error("panic in handler", "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			writeError(rec, http.StatusInternalServerError, "internal error")
		}
		s.logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds())
	}()
	s.mux.ServeHTTP(rec, r)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, api.ErrorResponse{Error: msg})
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, api.MaxRequestBodyKB<<10)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var req api.SubmitRequest
	if err := json.Unmarshal(data, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	pubs := make([]*keys.PublicKey, 0, len(req.PublicKeys))
	for i, p := range req.PublicKeys {
		k, err := keys.ParsePublicPEM([]byte(p))
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("public key %d: %v", i, err))
			return
		}
		pubs = append(pubs, k)
	}
	entry, err := tlog.NewEntry(&req.Envelope, pubs...)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	body, err := entry.Canonical()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.log.Add(body)
	if err != nil {
		if errors.Is(err, tlog.ErrInvalidEntry) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("append failed", "err", err)
		writeError(w, http.StatusInternalServerError, "append failed")
		return
	}
	status := http.StatusCreated
	if res.Duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, api.SubmitResponse{
		LogIndex:   res.Index,
		LeafHash:   res.LeafHash.String(),
		Duplicate:  res.Duplicate,
		Checkpoint: string(res.Checkpoint.Raw),
		InclusionProof: api.InclusionProof{
			LogIndex: res.Index, TreeSize: res.Checkpoint.Size, Hashes: api.EncodeHashes(res.Proof),
		},
	})
}

func parseUint(r *http.Request, name string) (uint64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, fmt.Errorf("missing query parameter %q", name)
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("query parameter %q must be a non-negative integer", name)
	}
	return n, nil
}

func (s *Server) handleEntry(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.ParseUint(r.PathValue("index"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "index must be a non-negative integer")
		return
	}
	body, leaf, err := s.log.Entry(idx)
	if err != nil {
		writeError(w, http.StatusNotFound, "no entry at that index")
		return
	}
	writeJSON(w, http.StatusOK, api.EntryResponse{LogIndex: idx, LeafHash: leaf.String(), Body: body})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	subject := r.URL.Query().Get("subject")
	d, err := intoto.ParseDigest(subject)
	if err != nil {
		writeError(w, http.StatusBadRequest, "subject must be alg:hex, e.g. sha256:<64 hex>")
		return
	}
	idx := s.log.Search(d)
	if idx == nil {
		idx = []uint64{}
	}
	writeJSON(w, http.StatusOK, api.SearchResponse{LogIndices: idx})
}

func (s *Server) handleCheckpoint(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", api.CheckpointMedia)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(s.log.Head().Raw)
}

func (s *Server) handlePublicKey(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", api.CheckpointMedia)
	_, _ = io.WriteString(w, s.log.Verifier().String()+"\n")
}

func (s *Server) handleInclusion(w http.ResponseWriter, r *http.Request) {
	size, err := parseUint(r, "treeSize")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var (
		idx   uint64
		proof []merkle.Hash
	)
	if lh := r.URL.Query().Get("leafHash"); lh != "" {
		h, perr := merkle.ParseHash(lh)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "leafHash must be 64 hex characters")
			return
		}
		idx, proof, err = s.log.InclusionProofByHash(h, size)
	} else {
		if idx, err = parseUint(r, "index"); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		proof, err = s.log.InclusionProof(idx, size)
	}
	if err != nil {
		writeError(w, proofStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.InclusionProof{LogIndex: idx, TreeSize: size, Hashes: api.EncodeHashes(proof)})
}

func (s *Server) handleConsistency(w http.ResponseWriter, r *http.Request) {
	from, err := parseUint(r, "from")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	to, err := parseUint(r, "to")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	proof, err := s.log.ConsistencyProof(from, to)
	if err != nil {
		writeError(w, proofStatus(err), err.Error())
		return
	}
	writeJSON(w, http.StatusOK, api.ConsistencyProof{From: from, To: to, Hashes: api.EncodeHashes(proof)})
}

func proofStatus(err error) int {
	switch {
	case errors.Is(err, tlog.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, merkle.ErrSizeOutOfRange), errors.Is(err, merkle.ErrIndexOutOfRange),
		errors.Is(err, merkle.ErrInconsistentSize), errors.Is(err, merkle.ErrEmptyConsistency):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
