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

	// lookupRetried marks PIDs for which Lookup has already paid for one
	// synchronous OS query while the cached entry still had no Name (see
	// Lookup's doc comment for why this exists and why it's capped at one).
	lookupRetried map[uint32]bool

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

// enrichWorkers/enrichQueueSize are sized for real observed process churn
// (systems easily rack up several hundred processes in normal use — each
// browser tab/helper, each service, etc.) now that this queue also carries
// name-resolution jobs, not just signature checks.
const enrichWorkers = 4
const enrichQueueSize = 2048

func New(onUpdate func(model.ProcessInfo)) *Cache {
	c := &Cache{
		m:             make(map[uint32]*model.ProcessInfo),
		onUpdate:      onUpdate,
		lookupRetried: make(map[uint32]bool),
		sigCache:      make(map[string]sigResult),
		jobs:          make(chan uint32, enrichQueueSize),
		knownApps:     config.KnownBrowsers(),
		suspicious:    config.SuspiciousPathFragments(),
	}
	for i := 0; i < enrichWorkers; i++ {
		go c.worker()
	}
	return c
}

// Observe records a process-start event coming from ETW. The event usually
// carries PID/PPID/ImagePath/CommandLine already, but when it doesn't (seen
// in practice for some ETW process-start records — not limited to any one
// app), Observe tries the cheap fallback itself (parent-process
// inheritance: a child of a process we've already identified is presumed
// part of the same app, e.g. Chrome's sandboxed subprocesses are still
// chrome.exe) and leaves the expensive one (queryBasic: OpenProcess +
// a full Toolhelp32 process-snapshot walk) to the background worker in
// enrich.
//
// That split matters: Observe runs synchronously on the ETW dispatch
// goroutine — the same single goroutine every network/file/DNS event also
// flows through — so anything slow here risks the consumer falling behind
// and Windows dropping ETW events under load, which would silently lose
// real security-relevant data, not just a process name. A cache miss on a
// name is comparatively cheap to live with (the correlation engine already
// treats "identity unknown" as a distinct, honestly-scored case, not a
// dropped event).
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
	c.applyHeuristics(&pi)
	c.mu.Lock()
	cp := pi
	c.m[pi.PID] = &cp
	c.mu.Unlock()
	c.queue(pi.PID) // enrich() will try queryBasic too if Name is still empty, off this hot path
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
// (cheap: one OpenProcess + QueryFullProcessImageName syscall pair, plus a
// Toolhelp32 snapshot walk) the first time an unfamiliar PID is seen — e.g.
// a browser that was already running before this tool started. Slow
// enrichment (signature + hash) is queued to happen in the background.
//
// The same synchronous query also fires once when the cached entry exists
// but still has no Name — that happens when Observe() planted a placeholder
// because the ETW process-start record itself had no ImageName and no
// parent identity to inherit yet (see Observe's doc comment), and the
// background enrichment worker hasn't resolved it yet. Without this,
// HandleFile/HandleNet would keep returning that empty placeholder forever
// for every subsequent event on the same PID, producing an "identity
// unknown" alert for a process that was perfectly resolvable the entire
// time — the process wasn't gone, the cache just never rechecked. Capped at
// one retry per PID (lookupRetried) because HandleNet calls Lookup on every
// single network event, not just alert-worthy ones, and the Toolhelp32 walk
// is exactly the "expensive, keep off the hot ETW dispatch goroutine" path
// Observe deliberately avoids — repeating it on every event for a PID that
// truly never resolves (already exited by the time anyone asked) would risk
// the same event-loss problem that split is there to prevent.
func (c *Cache) Lookup(pid uint32) model.ProcessInfo {
	c.mu.RLock()
	p, ok := c.m[pid]
	retried := c.lookupRetried[pid]
	c.mu.RUnlock()
	if ok && (p.Name != "" || retried) {
		return *p
	}

	qb := queryBasic(pid)
	c.applyHeuristics(&qb)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.lookupRetried[pid] = true
	if existing, ok := c.m[pid]; ok {
		if existing.Name == "" && qb.Name != "" {
			existing.Name = qb.Name
			if existing.ImagePath == "" {
				existing.ImagePath = qb.ImagePath
			}
			if existing.PPID == 0 {
				existing.PPID = qb.PPID
			}
			c.applyHeuristics(existing)
		}
		return *existing
	}
	cp := qb
	c.m[pid] = &cp
	c.queue(pid)
	return qb
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
	if !ok {
		return
	}

	// Observe() only tries the cheap parent-inheritance fallback; this is
	// where the expensive one (OpenProcess + a full Toolhelp32 snapshot
	// walk) actually runs, off the ETW dispatch hot path. Push the
	// resolved identity to the UI immediately even if we don't get as far
	// as a signature check below (e.g. the file has since been deleted).
	if p.Name == "" {
		if qb := queryBasic(pid); qb.Name != "" {
			c.mu.Lock()
			if p2, ok := c.m[pid]; ok && p2.Name == "" {
				p2.Name = qb.Name
				if p2.ImagePath == "" {
					p2.ImagePath = qb.ImagePath
				}
				if p2.PPID == 0 {
					p2.PPID = qb.PPID
				}
				c.applyHeuristics(p2)
				p = p2
			}
			c.mu.Unlock()
			if c.onUpdate != nil {
				c.onUpdate(*p)
			}
		}
	}

	if p.ImagePath == "" {
		return // nothing to check a signature/hash against
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
