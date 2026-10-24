package tlog

import (
	"log/slog"
	"sync"
	"syscall"
)

// FileFaults injects I/O failures into a FileStore. It is compiled only
// into tests. All fields are read under the store's lock; set them between
// operations.
type FileFaults struct {
	mu sync.Mutex
	// WriteFail makes the next Write store only WritePartial bytes of the
	// record and then return ENOSPC.
	WriteFail    bool
	WritePartial int
	// SyncFailures makes the next SyncFailures calls to Sync return EIO.
	SyncFailures int
	// TruncateFail makes every Truncate return EIO.
	TruncateFail bool
}

// Set updates the faults under their lock.
func (ff *FileFaults) Set(fn func(*FileFaults)) {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	fn(ff)
}

// Reset clears every fault.
func (ff *FileFaults) Reset() {
	ff.Set(func(f *FileFaults) {
		f.WriteFail, f.WritePartial, f.SyncFailures, f.TruncateFail = false, 0, 0, false
	})
}

type faultyFile struct {
	storeFile
	ff *FileFaults
}

func (f *faultyFile) Write(p []byte) (int, error) {
	f.ff.mu.Lock()
	fail, partial := f.ff.WriteFail, f.ff.WritePartial
	f.ff.WriteFail = false
	f.ff.mu.Unlock()
	if !fail {
		return f.storeFile.Write(p)
	}
	n, err := f.storeFile.Write(p[:min(partial, len(p))])
	if err != nil {
		return n, err
	}
	return n, &injectedError{syscall.ENOSPC}
}

func (f *faultyFile) Sync() error {
	f.ff.mu.Lock()
	fail := f.ff.SyncFailures > 0
	if fail {
		f.ff.SyncFailures--
	}
	f.ff.mu.Unlock()
	if fail {
		return &injectedError{syscall.EIO}
	}
	return f.storeFile.Sync()
}

func (f *faultyFile) Truncate(size int64) error {
	f.ff.mu.Lock()
	fail := f.ff.TruncateFail
	f.ff.mu.Unlock()
	if fail {
		return &injectedError{syscall.EIO}
	}
	return f.storeFile.Truncate(size)
}

type injectedError struct{ errno syscall.Errno }

func (e *injectedError) Error() string { return "injected: " + e.errno.Error() }
func (e *injectedError) Unwrap() error { return e.errno }

// OpenFaultyFileStore opens a FileStore in dir whose file I/O passes
// through ff.
func OpenFaultyFileStore(dir string, logger *slog.Logger, ff *FileFaults) (*FileStore, error) {
	s, err := OpenFileStore(dir, logger)
	if err != nil {
		return nil, err
	}
	s.f = &faultyFile{storeFile: s.f, ff: ff}
	return s, nil
}
