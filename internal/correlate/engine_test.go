//go:build windows

package correlate

import (
	"sync"
	"testing"
	"time"

	"netwatch/internal/model"
	"netwatch/internal/procinfo"
)

type alertSink struct {
	mu     sync.Mutex
	alerts []model.Alert
}

func (s *alertSink) add(a model.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
}

func (s *alertSink) byRule(rule string) []model.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []model.Alert
	for _, a := range s.alerts {
		if a.Rule == rule {
			out = append(out, a)
		}
	}
	return out
}

func newTestEngine() (*Engine, *alertSink) {
	sink := &alertSink{}
	procs := procinfo.New(nil)
	e := New(procs, Handlers{
		OnAlert: sink.add,
	})
	return e, sink
}

// The headline scenario the whole tool exists for: a process that is not
// the browser touches the browser's Cookies database, then immediately
// opens an outbound connection -> must produce a critical
// file_then_network_exfil alert naming that process.
func TestExfilCorrelation_NonOwnerFileThenConnect(t *testing.T) {
	e, sink := newTestEngine()

	const evilPID = 91001
	e.procs.Observe(model.ProcessInfo{
		PID:       evilPID,
		Name:      "evil.exe",
		ImagePath: `C:\Users\bob\AppData\Local\Temp\evil.exe`, // deterministic SuspiciousLoc=true, no async wait needed
		StartTime: time.Now(),
	})

	e.HandleFile(`\Device\HarddiskVolume3\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`, evilPID, model.FileOpen)

	fileAlerts := sink.byRule("sensitive_file_access")
	if len(fileAlerts) != 1 {
		t.Fatalf("expected 1 sensitive_file_access alert, got %d: %+v", len(fileAlerts), fileAlerts)
	}
	if fileAlerts[0].Severity != model.SevHigh && fileAlerts[0].Severity != model.SevCritical {
		t.Fatalf("expected high/critical severity for non-owner suspicious-path file touch, got %s", fileAlerts[0].Severity)
	}

	e.HandleNet(model.NetEvent{
		PID: evilPID, Time: time.Now(), Proto: "TCP", Direction: "connect",
		RemoteAddr: "203.0.113.5", RemotePort: 443,
	})

	exfilAlerts := sink.byRule("file_then_network_exfil")
	if len(exfilAlerts) != 1 {
		t.Fatalf("expected 1 file_then_network_exfil alert, got %d", len(exfilAlerts))
	}
	if exfilAlerts[0].Severity != model.SevCritical {
		t.Fatalf("expected critical severity, got %s: %s", exfilAlerts[0].Severity, exfilAlerts[0].Detail)
	}
	if exfilAlerts[0].ProcName != "evil.exe" || exfilAlerts[0].PID != evilPID {
		t.Fatalf("alert doesn't name the responsible process: %+v", exfilAlerts[0])
	}
}

// Chrome reading its own Cookies file is completely normal and must never
// alert, no matter how it's touched.
func TestNoAlert_OwnerTouchesOwnCookies(t *testing.T) {
	e, sink := newTestEngine()

	const chromePID = 91002
	e.procs.Observe(model.ProcessInfo{
		PID: chromePID, Name: "chrome.exe",
		ImagePath: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		StartTime: time.Now(),
	})

	e.HandleFile(`C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`, chromePID, model.FileOpen)

	if got := sink.byRule("sensitive_file_access"); len(got) != 0 {
		t.Fatalf("expected no alert for owner touching its own cookies, got %+v", got)
	}

	e.HandleNet(model.NetEvent{
		PID: chromePID, Time: time.Now(), Proto: "TCP", Direction: "connect",
		RemoteAddr: "142.250.72.14", RemotePort: 443, // a real Google IP range, plausible browser traffic
	})
	if got := sink.byRule("file_then_network_exfil"); len(got) != 0 {
		t.Fatalf("expected no exfil alert (no prior sensitive touch), got %+v", got)
	}
}

// A process making regular, evenly-spaced connections to the same remote
// address is a classic beacon pattern and should be flagged after enough
// samples, using event-supplied timestamps (not wall-clock sleeps).
func TestBeaconDetection(t *testing.T) {
	e, sink := newTestEngine()

	const beaconPID = 91003
	e.procs.Observe(model.ProcessInfo{
		PID: beaconPID, Name: "beacon.exe",
		ImagePath: `C:\Users\bob\AppData\Roaming\svchost32\svchost32.exe`,
		StartTime: time.Now(),
	})

	base := time.Now()
	for i := 0; i < 6; i++ {
		e.HandleNet(model.NetEvent{
			PID: beaconPID, Time: base.Add(time.Duration(i) * 15 * time.Second),
			Proto: "TCP", Direction: "connect",
			RemoteAddr: "203.0.113.77", RemotePort: 443,
		})
	}

	got := sink.byRule("beaconing")
	if len(got) == 0 {
		t.Fatalf("expected at least one beaconing alert after 6 evenly-spaced connects")
	}
}

// Fast, regular polling (a few seconds apart) is common for legitimate
// background software (update checkers, vendor telemetry) and must not be
// flagged with the same confidence as slower, more C2-typical intervals.
func TestNoBeaconAlert_TooFastToBeMeaningful(t *testing.T) {
	e, sink := newTestEngine()

	const fastPID = 91005
	e.procs.Observe(model.ProcessInfo{
		PID: fastPID, Name: "vendorupdater.exe",
		ImagePath: `C:\Program Files\Vendor\vendorupdater.exe`,
		StartTime: time.Now(),
	})

	base := time.Now()
	for i := 0; i < 6; i++ {
		e.HandleNet(model.NetEvent{
			PID: fastPID, Time: base.Add(time.Duration(i) * 2 * time.Second),
			Proto: "TCP", Direction: "connect",
			RemoteAddr: "203.0.113.88", RemotePort: 443,
		})
	}

	if got := sink.byRule("beaconing"); len(got) != 0 {
		t.Fatalf("2-second interval polling should be below the beacon floor, got %+v", got)
	}
}

// This is the exact false positive observed in production: Chrome's own
// sandboxed Network Service subprocess reads Chrome's Cookies database.
// ETW's process-start event for it carried no image name, but it *does*
// carry a ParentProcessID pointing at the already-known chrome.exe — that
// must be enough to recognize it as Chrome's own subsystem and NOT alert,
// rather than falling through to "unidentified process reading cookies".
func TestNoAlert_ChromeSandboxedChildInheritsParentIdentity(t *testing.T) {
	e, sink := newTestEngine()

	const chromeMainPID = 91101
	const networkServicePID = 91102

	e.procs.Observe(model.ProcessInfo{
		PID: chromeMainPID, Name: "chrome.exe",
		ImagePath: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		StartTime: time.Now(),
	})
	// Simulate the ETW Kernel-Process event for the child carrying an empty
	// ImageName (the real-world gap) but a valid ParentProcessID.
	e.procs.Observe(model.ProcessInfo{
		PID: networkServicePID, PPID: chromeMainPID, Name: "",
		StartTime: time.Now(),
	})

	e.HandleFile(`\Device\HarddiskVolume3\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`, networkServicePID, model.FileOpen)

	if got := sink.byRule("sensitive_file_access"); len(got) != 0 {
		t.Fatalf("Chrome's own sandboxed child should inherit chrome.exe's identity and not alert, got %+v", got)
	}
}

// When a PID's identity genuinely cannot be resolved by any method (no ETW
// record, no parent to inherit from, OS query failed), the file-access
// alert must still fire — but scored/worded as "unconfirmed", not asserted
// as a confirmed non-owner, and it must never be silently dropped.
func TestAlert_UnresolvedIdentity_HonestNotSuppressed(t *testing.T) {
	e, sink := newTestEngine()

	const ghostPID = 91103 // never Observe()'d, and queryBasic will fail for a PID that doesn't exist on this machine
	e.HandleFile(`C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`, ghostPID, model.FileOpen)

	got := sink.byRule("sensitive_file_access")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 alert for an unresolvable identity touching Cookies, got %d", len(got))
	}
	a := got[0]
	if a.Severity == model.SevCritical || a.Severity == model.SevHigh {
		t.Fatalf("an unconfirmed identity should not be scored as confidently as a confirmed non-owner, got severity %s", a.Severity)
	}
	if a.Process == nil || !a.Process.IdentityUnknown() {
		t.Fatalf("expected Process.IdentityUnknown()==true attached as evidence, got %+v", a.Process)
	}
}

// Connections resolving to a watched AI-service domain must be tagged, and
// when that's also the target of a file-then-network correlation the
// alert should call the service out by name.
func TestAIServiceTagging_ExfilToClaudeDomain(t *testing.T) {
	e, sink := newTestEngine()

	const evilPID = 91104
	e.procs.Observe(model.ProcessInfo{
		PID: evilPID, Name: "evil.exe",
		ImagePath: `C:\Users\bob\AppData\Local\Temp\evil.exe`,
		StartTime: time.Now(),
	})

	e.HandleDNS(model.DNSEvent{
		PID: evilPID, Time: time.Now(), Query: "claude.ai", Results: []string{"160.79.104.10"},
	})
	e.HandleFile(`\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`, evilPID, model.FileOpen)
	e.HandleNet(model.NetEvent{
		PID: evilPID, Time: time.Now(), Proto: "TCP", Direction: "connect",
		RemoteAddr: "160.79.104.10", RemotePort: 443,
	})

	exfil := sink.byRule("file_then_network_exfil")
	if len(exfil) != 1 {
		t.Fatalf("expected 1 exfil alert, got %d", len(exfil))
	}
	if exfil[0].AIService == "" {
		t.Fatalf("expected AIService to be tagged for a claude.ai destination, got %+v", exfil[0])
	}
	if exfil[0].Severity != model.SevCritical {
		t.Fatalf("AI-service exfil should be critical, got %s", exfil[0].Severity)
	}
}

// A known browser's normal periodic keep-alive traffic must not be flagged
// as beaconing.
func TestNoBeaconAlert_KnownBrowser(t *testing.T) {
	e, sink := newTestEngine()

	const chromePID = 91004
	e.procs.Observe(model.ProcessInfo{
		PID: chromePID, Name: "chrome.exe",
		ImagePath: `C:\Program Files\Google\Chrome\Application\chrome.exe`,
		StartTime: time.Now(),
	})

	base := time.Now()
	for i := 0; i < 6; i++ {
		e.HandleNet(model.NetEvent{
			PID: chromePID, Time: base.Add(time.Duration(i) * 5 * time.Second),
			Proto: "TCP", Direction: "connect",
			RemoteAddr: "142.250.72.14", RemotePort: 443,
		})
	}

	if got := sink.byRule("beaconing"); len(got) != 0 {
		t.Fatalf("known browser should not trigger beaconing alert, got %+v", got)
	}
}

// A monitor left running for weeks must not accumulate one
// dnsByIP/connHistory/recentTouch entry per distinct IP/process/pair it
// has ever seen forever — maybeSweepLocked's periodic eviction is what
// bounds that. Seed clearly-stale entries directly, then drive enough
// unrelated HandleNet calls to cross the sweep threshold, and confirm the
// stale entries are gone while nothing crashes for the entries that do get
// touched along the way.
func TestMaybeSweepEvictsStaleEntries(t *testing.T) {
	e, _ := newTestEngine()

	const staleProcPID = 92001
	old := time.Now().Add(-2 * time.Hour) // far past every cutoff this package uses

	e.mu.Lock()
	e.dnsByIP["203.0.113.200"] = dnsRecord{domain: "stale.example.com", at: old}
	e.connHistory[beaconKey{pid: staleProcPID, addr: "203.0.113.201"}] = []connSample{{at: old}}
	e.recentTouch[staleProcPID] = []fileTouch{{at: old}}
	e.mu.Unlock()

	for i := 0; i < sweepIntervalEvents; i++ {
		e.HandleNet(model.NetEvent{
			PID: 1, Time: time.Now(), Proto: "TCP", Direction: "connect",
			RemoteAddr: "198.51.100.1", RemotePort: 443,
		})
	}

	e.mu.Lock()
	_, dnsStillThere := e.dnsByIP["203.0.113.200"]
	_, beaconStillThere := e.connHistory[beaconKey{pid: staleProcPID, addr: "203.0.113.201"}]
	_, touchStillThere := e.recentTouch[staleProcPID]
	e.mu.Unlock()

	if dnsStillThere {
		t.Error("expected stale dnsByIP entry to be swept")
	}
	if beaconStillThere {
		t.Error("expected stale connHistory entry to be swept")
	}
	if touchStillThere {
		t.Error("expected stale recentTouch entry to be swept")
	}
}
