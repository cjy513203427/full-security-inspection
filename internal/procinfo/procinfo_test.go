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

// This is the production race behind the "身份不明" alert that resolves to
// a perfectly identifiable, signed process one event later (e.g.
// msedgewebview2.exe) instead of one that genuinely disappeared: Observe()
// plants a Name=="" placeholder (ETW start record missing ImageName, no
// parent identity yet) and queues async enrichment, but HandleFile/HandleNet
// call Lookup — not enrich — the moment a sensitive-file touch or connect
// happens, which can easily land before the background worker gets to it.
// Lookup must not just hand back that empty placeholder forever; it should
// retry the same cheap OS query enrich would eventually do anyway.
func TestLookup_ResolvesPlaceholderSynchronouslyWithoutWaitingForAsyncWorker(t *testing.T) {
	c := New(nil)
	selfPID := uint32(os.Getpid())

	// Simulate the ETW process-start record arriving with no name and no
	// resolvable parent — Observe() has no choice but to cache a
	// placeholder and queue async enrichment (which we deliberately never
	// drive here, unlike the test above, to prove Lookup doesn't depend on it).
	c.Observe(model.ProcessInfo{PID: selfPID, PPID: 0, Name: "", StartTime: time.Now()})

	got := c.Lookup(selfPID)
	if got.Name == "" {
		t.Fatalf("expected Lookup to resolve the placeholder synchronously instead of returning it empty, got PID %d with no Name", selfPID)
	}
	if got.ImagePath == "" {
		t.Fatalf("expected ImagePath to be resolved alongside Name, got empty ImagePath")
	}

	// A second Lookup for the same (already-resolved) PID should just
	// return the cached identity, not pay for another OS query.
	got2 := c.Lookup(selfPID)
	if got2.Name != got.Name {
		t.Fatalf("expected stable identity across repeated Lookups, got %q then %q", got.Name, got2.Name)
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
