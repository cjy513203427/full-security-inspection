//go:build windows

// Package procinfo maintains a cache of everything we know about each PID
// we have observed: image path, command line, Authenticode signature
// status and whether it runs from a location commonly abused by malware.
// Enrichment (signature check + hashing) is comparatively slow, so it
// happens on a small worker pool and the cache is updated asynchronously;
// callers get an immediate best-effort answer and an OnUpdate callback
// fires once enrichment completes.
package procinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"netwatch/internal/config"
	"netwatch/internal/model"
)

type Cache struct {
	mu       sync.RWMutex
	m        map[uint32]*model.ProcessInfo
	onUpdate func(model.ProcessInfo)

	sigMu    sync.Mutex
	sigCache map[string]sigResult // keyed by lower-cased image path

	jobs       chan uint32
	knownApps  map[string]bool
	suspicious []string
}

type sigResult struct {
	signed bool
	signer string
	sha256 string
}

func New(onUpdate func(model.ProcessInfo)) *Cache {
	c := &Cache{
		m:          make(map[uint32]*model.ProcessInfo),
		onUpdate:   onUpdate,
		sigCache:   make(map[string]sigResult),
		jobs:       make(chan uint32, 512),
		knownApps:  config.KnownBrowsers(),
		suspicious: config.SuspiciousPathFragments(),
	}
	for i := 0; i < 3; i++ {
		go c.worker()
	}
	return c
}

// Observe records a process-start event coming from ETW. The event usually
// carries PID/PPID/ImagePath/CommandLine already, but when it doesn't (seen
// in practice for some ETW process-start records — not limited to any one
// app), this runs the exact same fallback ladder Lookup uses for a
// completely unfamiliar PID, so a process is never left unidentified just
// because it happened to arrive via the ETW path instead of the "we'd
// never heard of this PID before" path:
//  1. parent-process inheritance (cheap, no syscalls) — a child of a
//     process we've already identified is presumed part of the same app
//     (e.g. Chrome's sandboxed subprocesses are still chrome.exe);
//  2. a direct OS query (queryBasic: OpenProcess + Toolhelp32 snapshot).
//
// Only if both fail does the record stay genuinely unidentified.
func (c *Cache) Observe(pi model.ProcessInfo) {
	if pi.Name == "" && pi.PPID != 0 {
		c.mu.RLock()
		parent, ok := c.m[pi.PPID]
		c.mu.RUnlock()
		if ok && parent.Name != "" {
			pi.Name = parent.Name
			pi.ImagePath = parent.ImagePath
			pi.NameInherited = true
		}
	}
	if pi.Name == "" {
		if qb := queryBasic(pi.PID); qb.Name != "" {
			pi.Name = qb.Name
			if pi.ImagePath == "" {
				pi.ImagePath = qb.ImagePath
			}
			if pi.PPID == 0 {
				pi.PPID = qb.PPID
			}
		}
	}
	c.applyHeuristics(&pi)
	c.mu.Lock()
	cp := pi
	c.m[pi.PID] = &cp
	c.mu.Unlock()
	c.queue(pi.PID)
}

func (c *Cache) applyHeuristics(pi *model.ProcessInfo) {
	pi.SuspiciousLoc = pathLooksSuspicious(pi.ImagePath, c.suspicious)
	pi.Known = c.knownApps[strings.ToLower(pi.Name)]
}

func (c *Cache) MarkExited(pid uint32, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.m[pid]; ok {
		p.Exited = true
		p.ExitTime = t
	}
}

// Lookup returns what we know about pid, querying the OS synchronously
// (cheap: one OpenProcess + QueryFullProcessImageName syscall pair) the
// first time an unfamiliar PID is seen — e.g. a browser that was already
// running before this tool started. Slow enrichment (signature + hash) is
// queued to happen in the background.
func (c *Cache) Lookup(pid uint32) model.ProcessInfo {
	c.mu.RLock()
	p, ok := c.m[pid]
	c.mu.RUnlock()
	if ok {
		return *p
	}

	pi := queryBasic(pid)
	c.applyHeuristics(&pi)

	c.mu.Lock()
	cp := pi
	c.m[pid] = &cp
	c.mu.Unlock()

	c.queue(pid)
	return pi
}

func (c *Cache) queue(pid uint32) {
	select {
	case c.jobs <- pid:
	default: // worker pool saturated, enrichment will just happen next time Lookup misses a signature
	}
}

func (c *Cache) worker() {
	for pid := range c.jobs {
		c.enrich(pid)
	}
}

func (c *Cache) enrich(pid uint32) {
	c.mu.RLock()
	p, ok := c.m[pid]
	c.mu.RUnlock()
	if !ok || p.ImagePath == "" {
		return
	}
	key := strings.ToLower(p.ImagePath)

	c.sigMu.Lock()
	res, cached := c.sigCache[key]
	c.sigMu.Unlock()

	if !cached {
		signed, signer := checkSignature(p.ImagePath)
		sum := sha256File(p.ImagePath)
		res = sigResult{signed: signed, signer: signer, sha256: sum}
		c.sigMu.Lock()
		c.sigCache[key] = res
		c.sigMu.Unlock()
	}

	c.mu.Lock()
	if p2, ok := c.m[pid]; ok {
		p2.Signed = res.signed
		p2.SignerName = res.signer
		p2.SHA256 = res.sha256
		p2.SigChecked = true
		p = p2
	}
	c.mu.Unlock()

	if c.onUpdate != nil && p != nil {
		c.onUpdate(*p)
	}
}

func pathLooksSuspicious(path string, fragments []string) bool {
	if path == "" {
		return false
	}
	lp := strings.ToLower(path)
	for _, f := range fragments {
		if strings.Contains(lp, f) {
			return true
		}
	}
	return false
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 64<<20)); err != nil { // cap at 64MB, plenty for exes
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// queryBasic asks the OS for what it knows about a PID we have no ETW
// process-start record for (e.g. it started before this tool did).
//
// Two independent methods are combined because neither is reliable alone:
// OpenProcess+QueryFullProcessImageName gives the full path but can be
// denied by a hardened process DACL (Chrome/Edge sandbox children) even
// from an elevated, SeDebugPrivilege-enabled caller in some configurations;
// Process32Next's Toolhelp32 snapshot enumeration gives PID/PPID/base exe
// name for essentially any process on the system since it doesn't open a
// handle to that specific target at all, so it succeeds where the first
// method sometimes can't.
func queryBasic(pid uint32) model.ProcessInfo {
	pi := model.ProcessInfo{PID: pid}

	if entry, err := findProcessEntry(pid); err == nil {
		pi.PPID = entry.ParentProcessID
		pi.Name = windows.UTF16ToString(entry.ExeFile[:])
	}

	if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid); err == nil {
		defer windows.CloseHandle(h)
		buf := make([]uint16, 4096)
		size := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
			path := windows.UTF16ToString(buf[:size])
			pi.ImagePath = path
			pi.Name = baseName(path) // full-path-derived name is authoritative when available
		}
	}
	return pi
}

// findProcessEntry looks up pid in a fresh system-wide process snapshot.
func findProcessEntry(pid uint32) (windows.ProcessEntry32, error) {
	var entry windows.ProcessEntry32
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return entry, err
	}
	defer windows.CloseHandle(snapshot)

	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return entry, err
	}
	for {
		if entry.ProcessID == pid {
			return entry, nil
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			return entry, err
		}
	}
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	if i := strings.LastIndex(path, "\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}
