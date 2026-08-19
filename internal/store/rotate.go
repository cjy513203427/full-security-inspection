package store

import (
	"fmt"
	"os"
	"sync"
)

// RotatingFile is a size-bounded, append-only file writer. Once a write
// would push the file past maxBytes, the current file is renamed out to a
// numbered backup (path+".1", the previous ".1" becomes ".2", and so on,
// dropping anything beyond maxBackups) and a fresh file is started.
//
// Exported so cmd/netwatch can put the same bound on the plain-text
// netwatch.log, not just the JSONL event logs this package writes itself
// — a monitor meant to run for weeks needs every one of its log files
// bounded, or "runs forever" just means "the data directory grows
// forever".
type RotatingFile struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	f          *os.File
	size       int64
}

// NewRotatingFile opens (or creates) path for appending. maxBytes is the
// size threshold that triggers a rotation; maxBackups is how many rotated
// copies are kept alongside the active file (path+".1" .. path+".N").
func NewRotatingFile(path string, maxBytes int64, maxBackups int) (*RotatingFile, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	var size int64
	if info, statErr := f.Stat(); statErr == nil {
		size = info.Size()
	}
	return &RotatingFile{path: path, maxBytes: maxBytes, maxBackups: maxBackups, f: f, size: size}, nil
}

// Write implements io.Writer, so a RotatingFile can be handed straight to
// log.SetOutput / io.MultiWriter.
func (r *RotatingFile) Write(b []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size+int64(len(b)) > r.maxBytes {
		r.rotateLocked()
	}
	if r.f == nil {
		return 0, fmt.Errorf("rotating file %s: not open (rotation failed to reopen it)", r.path)
	}
	n, err := r.f.Write(b)
	r.size += int64(n)
	return n, err
}

func (r *RotatingFile) rotateLocked() {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}

	// Shift existing backups up one slot, oldest first so nothing gets
	// clobbered mid-shift, dropping whatever would land beyond maxBackups.
	for i := r.maxBackups - 1; i >= 1; i-- {
		_ = os.Rename(r.backupPath(i), r.backupPath(i+1))
	}
	_ = os.Remove(r.backupPath(r.maxBackups + 1))
	_ = os.Rename(r.path, r.backupPath(1))

	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		// Best-effort, matching this package's policy elsewhere: a rotation
		// hiccup (e.g. antivirus briefly holding the old file) shouldn't
		// crash the monitor. r.f stays nil; Write reports an error rather
		// than writing, and the next rotation attempt will retry reopening.
		return
	}
	r.f = f
	r.size = 0
}

func (r *RotatingFile) backupPath(n int) string {
	return fmt.Sprintf("%s.%d", r.path, n)
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
