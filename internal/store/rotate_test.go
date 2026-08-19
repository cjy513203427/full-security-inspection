package store

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFile_RotatesAtSizeAndCapsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Small threshold so a handful of writes force several rotations.
	rf, err := NewRotatingFile(path, 100, 3)
	if err != nil {
		t.Fatalf("NewRotatingFile: %v", err)
	}
	defer rf.Close()

	chunk := make([]byte, 40)
	for i := range chunk {
		chunk[i] = 'x'
	}

	// Enough writes to roll past the 3-backup cap several times over.
	for i := 0; i < 40; i++ {
		if _, err := rf.Write(chunk); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected active file to exist: %v", err)
	}
	for _, n := range []int{1, 2, 3} {
		p := fmt.Sprintf("%s.%d", path, n)
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected backup %s to exist: %v", p, err)
		}
	}
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Error("expected no backup beyond the configured cap of 3, but .4 exists")
	}
}

func TestRotatingFile_ResumesExistingSizeAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	rf, err := NewRotatingFile(path, 1000, 2)
	if err != nil {
		t.Fatalf("NewRotatingFile: %v", err)
	}
	if _, err := rf.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := rf.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopening (simulating a process restart) must pick up the existing
	// file's size rather than resetting the counter to 0 — otherwise a
	// program that restarts often would delay rotation well past maxBytes.
	rf2, err := NewRotatingFile(path, 1000, 2)
	if err != nil {
		t.Fatalf("NewRotatingFile (reopen): %v", err)
	}
	defer rf2.Close()
	if rf2.size != 10 {
		t.Fatalf("expected resumed size 10, got %d", rf2.size)
	}
}

func TestJSONLWriter_WritesValidNDJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")

	w, err := newJSONLWriter(path)
	if err != nil {
		t.Fatalf("newJSONLWriter: %v", err)
	}
	w.Write(map[string]any{"seq": 1})
	w.Write(map[string]any{"seq": 2})
	w.Close()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(b)
	want := "{\"seq\":1}\n{\"seq\":2}\n"
	if got != want {
		t.Fatalf("unexpected file contents:\ngot:  %q\nwant: %q", got, want)
	}
}
