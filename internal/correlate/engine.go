// Package correlate is the detection core: it turns raw file/network/DNS
// events into an audit trail, and — where a real red flag shows up — into
// a scored Alert naming the responsible process.
//
// The headline rule is the one the tool exists for: a process that is not
// the owner of a browser/app's cookie or password store touches that
// store, and within a short window afterwards the SAME process opens an
// outbound connection. That sequence is exactly what an infostealer /
// session-hijacker does (read the credential DB, phone it home) and is
// scored CRITICAL. Everything else (unsigned+suspicious-path processes
// phoning home, regular "beaconing" connections) is scored lower and
// exists to catch variants of the same behavior.
package correlate

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netwatch/internal/config"
	"netwatch/internal/i18n"
	"netwatch/internal/model"
	"netwatch/internal/procinfo"
)

type fileTouch struct {
	at     time.Time
	target config.SensitiveTarget
	path   string
}

type dnsRecord struct {
	domain string
	at     time.Time
}

type connSample struct {
	at time.Time
}

// beaconKey identifies one (process, destination) pair for beacon
// tracking. A struct key rather than a formatted string avoids both an
// allocation per connect event and a subtler bug: keying on ProcName as
// well would silently fragment a single process's history into two
// buckets if its name resolves asynchronously (empty, then populated)
// between connects to the same address.
type beaconKey struct {
	pid  uint32
	addr string
}

type Engine struct {
	procs   *procinfo.Cache
	targets []config.SensitiveTarget

	onFile  func(model.SensitiveFileEvent)
	onNet   func(model.NetEvent)
	onDNS   func(model.DNSEvent)
	onAlert func(model.Alert)

	mu           sync.Mutex
	recentTouch  map[uint32][]fileTouch
	dnsByIP      map[string]dnsRecord
	connHistory  map[beaconKey][]connSample
	sweepCounter uint64 // opportunistic-sweep cadence, see maybeSweepLocked

	fileSeq uint64
	netSeq  uint64
	dnsSeq  uint64
}

type Handlers struct {
	OnFile  func(model.SensitiveFileEvent)
	OnNet   func(model.NetEvent)
	OnDNS   func(model.DNSEvent)
	OnAlert func(model.Alert)
}

func New(procs *procinfo.Cache, h Handlers) *Engine {
	return &Engine{
		procs:       procs,
		targets:     config.SensitiveTargets(),
		onFile:      h.OnFile,
		onNet:       h.OnNet,
		onDNS:       h.OnDNS,
		onAlert:     h.OnAlert,
		recentTouch: make(map[uint32][]fileTouch),
		dnsByIP:     make(map[string]dnsRecord),
		connHistory: make(map[beaconKey][]connSample),
	}
}

func (e *Engine) nextSeq(counter *uint64) uint64 {
	return atomic.AddUint64(counter, 1)
}

// HandleFile processes a raw sensitive-path file touch reported by ETW.
func (e *Engine) HandleFile(rawPath string, pid uint32, kind model.FileAccessKind) {
	lp := strings.ToLower(rawPath)
	target, ok := matchTarget(e.targets, lp)
	if !ok {
		return
	}

	proc := e.procs.Lookup(pid)
	// own is only ever true when we positively matched the process name
	// against the target's owner list — an unresolved identity is treated
	// as "we don't know", never silently coerced into "so it must be fine".
	own := !proc.IdentityUnknown() && isOwner(proc.Name, target.Owners)
	now := time.Now()
	appName := config.TargetAppName(target)

	fe := model.SensitiveFileEvent{
		Seq:      e.nextSeq(&e.fileSeq),
		Time:     now,
		PID:      pid,
		ProcName: proc.Name,
		Path:     rawPath,
		App:      appName,
		Kind:     kind,
		OwnFile:  own,
	}
	if e.onFile != nil {
		e.onFile(fe)
	}

	if !target.Critical || own {
		// Non-critical target (coarse folder-level pattern) or the file's
		// own app touching it: expected behavior, logged above for the
		// audit trail but not alert-worthy.
		return
	}

	e.mu.Lock()
	list := append(pruneTouchesAt(e.recentTouch[pid], now), fileTouch{at: now, target: target, path: rawPath})
	e.recentTouch[pid] = list
	e.mu.Unlock()

	e.raiseFileAlert(proc, fe, target)
}

func (e *Engine) raiseFileAlert(proc model.ProcessInfo, fe model.SensitiveFileEvent, target config.SensitiveTarget) {
	var score int
	var reasons []string
	title := i18n.T("alert.file.title", fe.App)

	if proc.IdentityUnknown() {
		// We could not attach any name to this PID at all (tried direct
		// query, Toolhelp32 enumeration, and parent-process inheritance).
		// That's worth surfacing, but "unnamed" is not the same claim as
		// "confirmed a stranger did this" — score and word it accordingly
		// rather than asserting certainty we don't have.
		score = 30
		title = i18n.T("alert.file.title_unknown", fe.App)
		reasons = append(reasons, i18n.T("reason.identity_unknown_full"))
	} else {
		score = 40
		reasons = append(reasons, i18n.T("reason.non_owner_access", fe.App, config.CategoryLabel(target.Category)))
		if proc.SigChecked && !proc.Signed {
			score += 20
			reasons = append(reasons, i18n.T("reason.unsigned"))
		}
		if proc.SuspiciousLoc {
			score += 20
			reasons = append(reasons, i18n.T("reason.suspicious_path_long"))
		}
	}

	a := model.Alert{
		// Seq is intentionally left unset here: Store.AddAlert assigns it
		// from a single counter shared across every alert producer (see its
		// doc comment) — correlate.Engine is no longer the only one now
		// that internal/certcheck also raises alerts.
		Time:      fe.Time,
		Severity:  scoreToSeverity(score),
		Rule:      "sensitive_file_access",
		Title:     title,
		Detail:    strings.Join(reasons, "; ") + i18n.T("alert.file.detail_suffix", fe.Path),
		PID:       fe.PID,
		ProcName:  fe.ProcName,
		ImagePath: proc.ImagePath,
		Process:   &proc,
		Related:   []uint64{fe.Seq},
	}
	if e.onAlert != nil {
		e.onAlert(a)
	}
}

// HandleNet processes a connect/accept/disconnect event reported by ETW.
func (e *Engine) HandleNet(ne model.NetEvent) {
	proc := e.procs.Lookup(ne.PID)
	ne.ProcName = proc.Name
	if ne.Time.IsZero() {
		ne.Time = time.Now()
	}

	e.mu.Lock()
	rec, hasDNS := e.dnsByIP[ne.RemoteAddr]
	if hasDNS && time.Since(rec.at) < config.DNSCacheWindowSeconds*time.Second {
		ne.Domain = rec.domain
	} else {
		hasDNS = false
	}
	ne.AIService = config.MatchAIService(ne.Domain)
	var touches []fileTouch
	if ne.Direction == "connect" {
		touches = pruneTouchesAt(e.recentTouch[ne.PID], ne.Time)
		e.recentTouch[ne.PID] = touches
	}
	e.maybeSweepLocked(ne.Time)
	e.mu.Unlock()

	if e.onNet != nil {
		e.onNet(ne)
	}

	if ne.Direction != "connect" {
		return
	}
	if isPrivateOrLoopback(ne.RemoteAddr) {
		return
	}

	e.trackBeacon(ne, proc)

	if len(touches) > 0 {
		e.raiseExfilAlert(proc, ne, touches, hasDNS)
		return
	}

	// No sensitive-file correlation. Still flag the narrower case of an
	// unknown, unsigned process running from a suspicious location that is
	// reaching out to the network on its own — kept conservative (all
	// three conditions required) to avoid drowning the feed in noise from
	// legitimate but unsigned/portable software.
	if !proc.Known && proc.SigChecked && !proc.Signed && proc.SuspiciousLoc {
		e.raiseSuspiciousNetAlert(proc, ne, hasDNS)
	}
}

func (e *Engine) raiseExfilAlert(proc model.ProcessInfo, ne model.NetEvent, touches []fileTouch, hasDNS bool) {
	score := 70
	var apps []string
	seen := map[string]bool{}
	for _, t := range touches {
		appName := config.TargetAppName(t.target)
		if !seen[appName] {
			apps = append(apps, appName)
			seen[appName] = true
		}
	}
	var extra []string
	if proc.IdentityUnknown() {
		extra = append(extra, i18n.T("reason.identity_unknown_check_pid"))
	} else if proc.SigChecked && !proc.Signed {
		score += 15
		extra = append(extra, i18n.T("reason.unsigned_short"))
	}
	if proc.SuspiciousLoc {
		score += 10
		extra = append(extra, i18n.T("reason.suspicious_path_short"))
	}
	if !hasDNS {
		score += 10
		extra = append(extra, i18n.T("reason.no_dns_seen"))
	}

	dest := ne.RemoteAddr
	if ne.Domain != "" {
		dest = fmt.Sprintf("%s (%s)", ne.Domain, ne.RemoteAddr)
	}

	title := i18n.T("alert.exfil.title")
	if ne.AIService != "" {
		score += 15
		title = i18n.T("alert.exfil.title_ai", ne.AIService)
	}

	detail := i18n.T("alert.exfil.detail", config.CorrelationWindowSeconds, strings.Join(apps, i18n.T("common.list_sep")), dest, ne.RemotePort)
	if len(extra) > 0 {
		detail += " " + strings.Join(extra, "; ")
	}

	a := model.Alert{
		Time:      ne.Time,
		Severity:  scoreToSeverity(score),
		Rule:      "file_then_network_exfil",
		Title:     title,
		Detail:    detail,
		PID:       ne.PID,
		ProcName:  ne.ProcName,
		ImagePath: proc.ImagePath,
		AIService: ne.AIService,
		Process:   &proc,
		Related:   []uint64{ne.Seq},
	}
	if e.onAlert != nil {
		e.onAlert(a)
	}
}

func (e *Engine) raiseSuspiciousNetAlert(proc model.ProcessInfo, ne model.NetEvent, hasDNS bool) {
	dest := ne.RemoteAddr
	if ne.Domain != "" {
		dest = fmt.Sprintf("%s (%s)", ne.Domain, ne.RemoteAddr)
	}
	score := 30
	title := i18n.T("alert.suspnet.title")
	detail := i18n.T("alert.suspnet.detail", dest, ne.RemotePort)
	if !hasDNS {
		detail += "; " + i18n.T("reason.no_dns_seen")
	}
	if ne.AIService != "" {
		score += 25
		title = i18n.T("alert.suspnet.title_ai", ne.AIService)
		detail += i18n.T("alert.suspnet.detail_ai", ne.AIService)
	}
	a := model.Alert{
		Time:      ne.Time,
		Severity:  scoreToSeverity(score),
		Rule:      "suspicious_process_network",
		Title:     title,
		Detail:    detail,
		PID:       ne.PID,
		ProcName:  ne.ProcName,
		ImagePath: proc.ImagePath,
		AIService: ne.AIService,
		Process:   &proc,
		Related:   []uint64{ne.Seq},
	}
	if e.onAlert != nil {
		e.onAlert(a)
	}
}

// trackBeacon looks for suspiciously regular, repeated connections from the
// same process to the same remote address — a classic sign of malware
// "phoning home" on a timer.
func (e *Engine) trackBeacon(ne model.NetEvent, proc model.ProcessInfo) {
	if proc.Known {
		return // browsers/known apps legitimately keep-alive on a schedule
	}
	key := beaconKey{pid: ne.PID, addr: ne.RemoteAddr}

	e.mu.Lock()
	cutoff := ne.Time.Add(-config.BeaconWindowSeconds * time.Second)
	kept := make([]connSample, 0, len(e.connHistory[key])+1)
	for _, s := range e.connHistory[key] {
		if s.at.After(cutoff) {
			kept = append(kept, s)
		}
	}
	kept = append(kept, connSample{at: ne.Time})
	e.connHistory[key] = kept
	n := len(kept)
	e.mu.Unlock()

	if n < config.BeaconMinSamples {
		return
	}

	intervals := make([]float64, 0, n-1)
	for i := 1; i < n; i++ {
		intervals = append(intervals, kept[i].at.Sub(kept[i-1].at).Seconds())
	}
	mean := meanF(intervals)
	if mean < config.BeaconMinIntervalSeconds { // fast, regular polling is usually legitimate software, not C2
		return
	}
	maxDev := 0.0
	for _, iv := range intervals {
		d := math.Abs(iv-mean) / mean
		if d > maxDev {
			maxDev = d
		}
	}
	if maxDev > config.BeaconJitterFraction {
		return
	}

	dest := ne.RemoteAddr
	if ne.Domain != "" {
		dest = ne.Domain
	}
	score := 30
	title := i18n.T("alert.beacon.title")
	if ne.AIService != "" {
		score += 25
		title = i18n.T("alert.beacon.title_ai", ne.AIService)
	}
	a := model.Alert{
		Time:     ne.Time,
		Severity: scoreToSeverity(score),
		Rule:     "beaconing",
		Title:    title,
		// mean/jitter are pre-formatted to whole-number strings here rather
		// than left as floats for the template to round via "%[N].0f": Go's
		// fmt package doesn't allow an explicit argument index ([N]) to be
		// combined with a width/precision on the same verb — that combo
		// silently renders as "%!f(BADINDEX)" instead of erroring at compile
		// time, which is exactly what shipped in production here (see the
		// git history/CLAUDE.md note on this). %[N]s with a pre-rounded
		// string sidesteps the restriction entirely.
		Detail: i18n.T("alert.beacon.detail",
			ne.ProcName, ne.PID, config.BeaconWindowSeconds,
			fmt.Sprintf("%.0f", mean), dest, fmt.Sprintf("%.0f", config.BeaconJitterFraction*100)),
		PID:       ne.PID,
		ProcName:  ne.ProcName,
		ImagePath: proc.ImagePath,
		AIService: ne.AIService,
		Process:   &proc,
	}
	if e.onAlert != nil {
		e.onAlert(a)
	}

	e.mu.Lock()
	delete(e.connHistory, key) // avoid re-alerting on every subsequent connect; a fresh entry starts cleanly if it beacons again
	e.mu.Unlock()
}

// sweepIntervalEvents is how often (in HandleNet calls) maybeSweepLocked
// actually does anything, rather than every single call.
const sweepIntervalEvents = 200

// maybeSweepLocked evicts time-expired entries from the correlation maps.
// Callers must already hold e.mu.
//
// Without this, a monitor left running for weeks (which is the whole
// point of this tool) would accumulate one dnsByIP/connHistory/recentTouch
// entry for every distinct resolved IP and every distinct (process,
// destination) pair it has EVER seen — forever. Each of those three maps
// only prunes the *contents* of a given key's slice on its own; a key that
// simply stops being visited (the process exits, or just stops talking to
// that address) has nothing left to trigger its own removal, so this does
// a periodic sweep instead of relying on that.
func (e *Engine) maybeSweepLocked(now time.Time) {
	e.sweepCounter++
	if e.sweepCounter%sweepIntervalEvents != 0 {
		return
	}

	dnsCutoff := now.Add(-config.DNSCacheWindowSeconds * time.Second)
	for ip, rec := range e.dnsByIP {
		if rec.at.Before(dnsCutoff) {
			delete(e.dnsByIP, ip)
		}
	}

	beaconCutoff := now.Add(-config.BeaconWindowSeconds * time.Second)
	for key, samples := range e.connHistory {
		if len(samples) == 0 || samples[len(samples)-1].at.Before(beaconCutoff) {
			delete(e.connHistory, key)
		}
	}

	touchCutoff := now.Add(-config.CorrelationWindowSeconds * time.Second)
	for pid, touches := range e.recentTouch {
		if len(touches) == 0 || touches[len(touches)-1].at.Before(touchCutoff) {
			delete(e.recentTouch, pid)
		}
	}
}

// HandleDNS processes a domain resolution event and feeds the IP->domain
// cache used to enrich connection events.
func (e *Engine) HandleDNS(de model.DNSEvent) {
	proc := e.procs.Lookup(de.PID)
	de.ProcName = proc.Name
	de.AIService = config.MatchAIService(de.Query)
	if de.Time.IsZero() {
		de.Time = time.Now()
	}

	e.mu.Lock()
	for _, ip := range de.Results {
		e.dnsByIP[ip] = dnsRecord{domain: de.Query, at: de.Time}
	}
	e.mu.Unlock()

	if e.onDNS != nil {
		e.onDNS(de)
	}
}

func matchTarget(targets []config.SensitiveTarget, lowerPath string) (config.SensitiveTarget, bool) {
	var fallback config.SensitiveTarget
	haveFallback := false
	for _, t := range targets {
		if !strings.Contains(lowerPath, t.Pattern) {
			continue
		}
		// BasePath, when set, scopes a generic filename pattern (e.g.
		// "network\cookies", identical across every Chromium-based browser
		// and every app embedding the WebView2 runtime for its own
		// unrelated cookie jar) to one specific app's own profile folder —
		// see the doc comment on the chromiumBrowsers loop in config.go.
		if t.BasePath != "" && !strings.Contains(lowerPath, t.BasePath) {
			continue
		}
		if t.Critical {
			return t, true
		}
		if !haveFallback {
			fallback = t
			haveFallback = true
		}
	}
	return fallback, haveFallback
}

func isOwner(procName string, owners []string) bool {
	pn := strings.ToLower(procName)
	for _, o := range owners {
		if pn == strings.ToLower(o) {
			return true
		}
	}
	return false
}

func pruneTouchesAt(list []fileTouch, now time.Time) []fileTouch {
	cutoff := now.Add(-config.CorrelationWindowSeconds * time.Second)
	out := list[:0:0]
	for _, t := range list {
		if t.at.After(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func scoreToSeverity(score int) model.Severity {
	switch {
	case score >= 80:
		return model.SevCritical
	case score >= 55:
		return model.SevHigh
	case score >= 30:
		return model.SevMedium
	default:
		return model.SevLow
	}
}

func isPrivateOrLoopback(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func meanF(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}
