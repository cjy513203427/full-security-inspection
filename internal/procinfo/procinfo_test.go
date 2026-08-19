//go:build windows

package procinfo

import (
	"os"
	"testing"
	"time"

	"netwatch/internal/model"
)

// This is the exact gap found in production: an ETW process-start event
// with no image name and no resolvable parent must not leave the process
// permanently unidentified — something has to fall back to a direct OS
// query, the same fallback Lookup already uses for a PID it never saw an
// ETW record for. Using our own PID means this exercises the real
// OpenProcess/Toolhelp32 syscalls (not a mock) and still runs without
// admin, since a process can always query itself.
//
// The OS-query fallback runs on the async enrichment worker pool (not
// inside Observe itself — see enrich's doc comment for why), so this
// drives that worker synchronously for a deterministic result; the
// separate test below exercises the real asynchronous path end to end.
func TestObserve_FallsBackToOSQueryWhenNameAndParentBothMissing(t *testing.T) {
	c := New(nil)
	selfPID := uint32(os.Getpid())

	c.Observe(model.ProcessInfo{PID: selfPID, PPID: 0, Name: "", StartTime: time.Now()})
	c.enrich(selfPID)

	got := c.Lookup(selfPID)
	if got.Name == "" {
		t.Fatalf("expected the OS-query fallback to resolve our own PID %d, got empty Name", selfPID)
	}
	if got.ImagePath == "" {
		t.Fatalf("expected ImagePath to be resolved alongside Name, got empty ImagePath")
	}
}

// The production path: Observe() queues the job and a background worker
// resolves it, pushing the result out through onUpdate — nothing here
// should require the caller to prod anything.
func TestObserve_AsyncEnrichmentReachesOnUpdate(t *testing.T) {
	selfPID := uint32(os.Getpid())
	updates := make(chan model.ProcessInfo, 10)
	c := New(func(p model.ProcessInfo) { updates <- p })

	c.Observe(model.ProcessInfo{PID: selfPID, PPID: 0, Name: "", StartTime: time.Now()})

	select {
	case p := <-updates:
		if p.Name == "" {
			t.Fatal("expected async enrichment to eventually resolve a name, got empty")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for async enrichment to resolve our own PID")
	}
}

// Parent inheritance should still be tried first (cheaper, no syscalls)
// and should win when the parent is already known.
func TestObserve_PrefersParentInheritanceOverOSQuery(t *testing.T) {
	c := New(nil)

	const parentPID = 424242
	const childPID = 424243

	c.Observe(model.ProcessInfo{PID: parentPID, Name: "chrome.exe", ImagePath: `C:\Program Files\Google\Chrome\Application\chrome.exe`, StartTime: time.Now()})
	c.Observe(model.ProcessInfo{PID: childPID, PPID: parentPID, Name: "", StartTime: time.Now()})

	got := c.Lookup(childPID)
	if got.Name != "chrome.exe" {
		t.Fatalf("expected child to inherit parent's name chrome.exe, got %q", got.Name)
	}
	if !got.NameInherited {
		t.Fatalf("expected NameInherited=true so the UI can be honest this was inferred")
	}
}
