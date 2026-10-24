package tlog

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// Store persists entry bodies in append order. Implementations must make an
// Append durable before returning, because the log signs a checkpoint that
// commits to the entry immediately afterwards.
type Store interface {
	// Append durably stores the next body.
	Append(body []byte) error
	// Load calls fn with every stored body in order.
	Load(fn func(body []byte) error) error
	// Close releases resources.
	Close() error
}

// MemoryStore keeps bodies in memory; useful for tests and ephemeral logs.
type MemoryStore struct {
	mu     sync.Mutex
	bodies [][]byte
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{} }

// Append implements Store.
func (m *MemoryStore) Append(body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, append([]byte(nil), body...))
	return nil
}

// Load implements Store.
func (m *MemoryStore) Load(fn func([]byte) error) error {
	m.mu.Lock()
	bodies := m.bodies
	m.mu.Unlock()
	for _, b := range bodies {
		if err := fn(b); err != nil {
			return err
		}
	}
	return nil
}

// Close implements Store.
func (m *MemoryStore) Close() error { return nil }

// FileStore appends framed records to a single file:
//
//	[4-byte big-endian length][body][4-byte CRC-32C of body]
//
// Each Append is followed by fsync. On open, a torn final record (a crash
// between write and fsync, so never acknowledged or signed) is truncated
// away; a complete record with a bad checksum is a hard error.
type FileStore struct {
	mu     sync.Mutex
	f      *os.File
	logger *slog.Logger
}

// ErrCorruptStore reports a damaged record that is not a torn tail.
var ErrCorruptStore = errors.New("tlog: corrupt entry store")

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

const entriesFile = "entries.log"

// OpenFileStore opens (creating if needed) the store in dir.
func OpenFileStore(dir string, logger *slog.Logger) (*FileStore, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tlog: create data dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, entriesFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("tlog: open store: %w", err)
	}
	return &FileStore{f: f, logger: logger}, nil
}

// Append implements Store.
func (s *FileStore) Append(body []byte) error {
	if len(body) == 0 || len(body) > MaxEntrySize {
		return fmt.Errorf("tlog: record size %d out of range", len(body))
	}
	rec := make([]byte, 0, 8+len(body))
	rec = binary.BigEndian.AppendUint32(rec, uint32(len(body))) //nolint:gosec // len(body) <= MaxEntrySize, checked above
	rec = append(rec, body...)
	rec = binary.BigEndian.AppendUint32(rec, crc32.Checksum(body, castagnoli))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("tlog: seek: %w", err)
	}
	if _, err := s.f.Write(rec); err != nil {
		return fmt.Errorf("tlog: write record: %w", err)
	}
	if err := s.f.Sync(); err != nil {
		return fmt.Errorf("tlog: fsync: %w", err)
	}
	return nil
}

// Load implements Store. It truncates a torn tail record.
func (s *FileStore) Load(fn func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("tlog: seek: %w", err)
	}
	st, err := s.f.Stat()
	if err != nil {
		return fmt.Errorf("tlog: stat: %w", err)
	}
	total := st.Size()
	r := bufio.NewReader(s.f)
	var off int64
	var hdr [4]byte
	for off < total {
		torn := func(why string) error {
			s.logger.Warn("truncating torn tail record", "offset", off, "reason", why, "bytes", total-off)
			if err := s.f.Truncate(off); err != nil {
				return fmt.Errorf("tlog: truncate torn tail: %w", err)
			}
			return s.f.Sync()
		}
		if total-off < 8 {
			return torn("short header")
		}
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return fmt.Errorf("tlog: read header: %w", err)
		}
		n := int64(binary.BigEndian.Uint32(hdr[:]))
		if n == 0 || n > MaxEntrySize {
			return fmt.Errorf("%w: record at offset %d has length %d", ErrCorruptStore, off, n)
		}
		if off+8+n > total {
			return torn("short body")
		}
		buf := make([]byte, n+4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return fmt.Errorf("tlog: read record: %w", err)
		}
		body, sum := buf[:n], binary.BigEndian.Uint32(buf[n:])
		// A complete record with a bad checksum may have been acknowledged
		// and signed, so it is never silently dropped.
		if crc32.Checksum(body, castagnoli) != sum {
			return fmt.Errorf("%w: checksum mismatch at offset %d", ErrCorruptStore, off)
		}
		if err := fn(body); err != nil {
			return err
		}
		off += 8 + n
	}
	return nil
}

// Close implements Store.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}
