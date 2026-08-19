// Package store is the single place that holds "current state" for the
// dashboard: bounded in-memory ring buffers for fast initial page loads,
// append-only JSONL files on disk so nothing is lost once the ring buffer
// wraps (this is what makes the tool useful for after-the-fact forensics,
// not just a live view), and a simple pub/sub hub that cmd/netwatch relays
// into the Wails frontend as it runs — Store itself doesn't know Wails
// exists, it's just a plain publisher.
package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"netwatch/internal/model"
)

// Envelope is the shape every event takes on the pub/sub feed.
type Envelope struct {
	Type string `json:"type"` // "net" | "dns" | "file" | "alert" | "proc"
	Data any    `json:"data"`
}

const ringSize = 5000
const alertRingSize = 2000

// A monitor that's meant to run for weeks needs bounded log files, not
// just bounded in-memory state — LogMaxBytes/LogMaxBackups are the JSONL
// event logs' rotation settings (see RotatingFile in rotate.go). Worst
// case per file: LogMaxBytes * (LogMaxBackups+1); four JSONL logs at the
// defaults below is at most ~320MB total, which is generous for forensic
// history without being "the disk just fills up eventually".
const LogMaxBytes = 20 << 20 // 20MB
const LogMaxBackups = 3

// A 24/7-running monitor will eventually observe far more processes than
// anyone needs kept around once they've exited — procExitRetention bounds
// that growth by sweeping old exited entries out of the map periodically
// (see sweepExitedProcsLocked), rather than keeping every process this
// tool has ever seen for the life of the run.
const procExitRetention = 2 * time.Hour
const procSweepEvery = 500 // opportunistic sweep cadence, in UpdateProc calls

type Store struct {
	mu     sync.RWMutex
	nets   []model.NetEvent
	dns    []model.DNSEvent
	files  []model.SensitiveFileEvent
	alerts []model.Alert
	procs  map[uint32]model.ProcessInfo

	procUpdateCount uint64

	logDir   string
	netLog   *jsonlWriter
	dnsLog   *jsonlWriter
	fileLog  *jsonlWriter
	alertLog *jsonlWriter

	subMu sync.Mutex
	subs  map[chan Envelope]struct{}

	// criticalCount is read from a different goroutine (the tray icon
	// poller) than it's written from (the ETW/correlation pipeline, and
	// whatever goroutine Wails dispatches AckAlert calls on) — atomic.Int64
	// makes that a compile-time-enforced property instead of a convention
	// that a future plain-field access could quietly violate.
	criticalCount atomic.Int64
}

func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		procs:  make(map[uint32]model.ProcessInfo),
		logDir: dataDir,
		subs:   make(map[chan Envelope]struct{}),
	}
	var err error
	if s.netLog, err = newJSONLWriter(filepath.Join(dataDir, "connections.jsonl")); err != nil {
		return nil, err
	}
	if s.dnsLog, err = newJSONLWriter(filepath.Join(dataDir, "dns.jsonl")); err != nil {
		return nil, err
	}
	if s.fileLog, err = newJSONLWriter(filepath.Join(dataDir, "file_access.jsonl")); err != nil {
		return nil, err
	}
	if s.alertLog, err = newJSONLWriter(filepath.Join(dataDir, "alerts.jsonl")); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() {
	s.netLog.Close()
	s.dnsLog.Close()
	s.fileLog.Close()
	s.alertLog.Close()
}

// --- writers -----------------------------------------------------------

func (s *Store) AddNet(e model.NetEvent) {
	s.mu.Lock()
	s.nets = appendRing(s.nets, e, ringSize)
	s.mu.Unlock()
	s.netLog.Write(e)
	s.publish(Envelope{Type: "net", Data: e})
}

func (s *Store) AddDNS(e model.DNSEvent) {
	s.mu.Lock()
	s.dns = appendRing(s.dns, e, ringSize)
	s.mu.Unlock()
	s.dnsLog.Write(e)
	s.publish(Envelope{Type: "dns", Data: e})
}

func (s *Store) AddFile(e model.SensitiveFileEvent) {
	s.mu.Lock()
	s.files = appendRing(s.files, e, ringSize)
	s.mu.Unlock()
	s.fileLog.Write(e)
	s.publish(Envelope{Type: "file", Data: e})
}

func (s *Store) AddAlert(a model.Alert) {
	s.mu.Lock()
	s.alerts = appendRing(s.alerts, a, alertRingSize)
	s.mu.Unlock()
	s.alertLog.Write(a)
	if a.Severity == model.SevCritical || a.Severity == model.SevHigh {
		s.criticalCount.Add(1)
	}
	s.publish(Envelope{Type: "alert", Data: a})
}

func (s *Store) UpdateProc(p model.ProcessInfo) {
	s.mu.Lock()
	s.procs[p.PID] = p
	s.procUpdateCount++
	if s.procUpdateCount%procSweepEvery == 0 {
		s.sweepExitedProcsLocked()
	}
	s.mu.Unlock()
	s.publish(Envelope{Type: "proc", Data: p})
}

// sweepExitedProcsLocked drops processes that exited more than
// procExitRetention ago. Callers must hold s.mu. Without this, a monitor
// left running for weeks would accumulate every process it ever observed
// — thousands of short-lived helper processes — forever.
func (s *Store) sweepExitedProcsLocked() {
	cutoff := time.Now().Add(-procExitRetention)
	for pid, p := range s.procs {
		if p.Exited && p.ExitTime.Before(cutoff) {
			delete(s.procs, pid)
		}
	}
}

// AckAlert marks an alert acknowledged (dismissed from the "needs
// attention" count shown on the tray icon) without deleting it from
// history.
func (s *Store) AckAlert(seq uint64) {
	s.mu.Lock()
	for i := range s.alerts {
		if s.alerts[i].Seq == seq && !s.alerts[i].Ack {
			s.alerts[i].Ack = true
			if s.alerts[i].Severity == model.SevCritical || s.alerts[i].Severity == model.SevHigh {
				s.criticalCount.Add(-1)
			}
			break
		}
	}
	s.mu.Unlock()
}

// UnacknowledgedCriticalCount returns the number of unacknowledged
// critical/high alerts. Safe to call from any goroutine — it's what the
// tray-icon color poller reads.
func (s *Store) UnacknowledgedCriticalCount() int64 {
	return s.criticalCount.Load()
}

// --- readers -------------------------------------------------------------

func (s *Store) RecentNets(n int) []model.NetEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastN(s.nets, n)
}

func (s *Store) RecentDNS(n int) []model.DNSEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastN(s.dns, n)
}

func (s *Store) RecentFiles(n int) []model.SensitiveFileEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastN(s.files, n)
}

func (s *Store) RecentAlerts(n int) []model.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return lastN(s.alerts, n)
}

func (s *Store) AllProcs() []model.ProcessInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ProcessInfo, 0, len(s.procs))
	for _, p := range s.procs {
		out = append(out, p)
	}
	return out
}

// --- pub/sub -------------------------------------------------------------

func (s *Store) Subscribe() chan Envelope {
	ch := make(chan Envelope, 256)
	s.subMu.Lock()
	s.subs[ch] = struct{}{}
	s.subMu.Unlock()
	return ch
}

func (s *Store) Unsubscribe(ch chan Envelope) {
	s.subMu.Lock()
	delete(s.subs, ch)
	s.subMu.Unlock()
	close(ch)
}

func (s *Store) publish(env Envelope) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for ch := range s.subs {
		select {
		case ch <- env:
		default:
			// slow subscriber: drop the event rather than block the
			// collector pipeline. The dashboard's initial snapshot
			// (RecentX calls) covers anything missed on (re)connect.
		}
	}
}

// --- helpers ---------------------------------------------------------------

func appendRing[T any](s []T, v T, max int) []T {
	s = append(s, v)
	if len(s) > max {
		s = s[len(s)-max:]
	}
	return s
}

func lastN[T any](s []T, n int) []T {
	if n <= 0 || n >= len(s) {
		out := make([]T, len(s))
		copy(out, s)
		return out
	}
	out := make([]T, n)
	copy(out, s[len(s)-n:])
	return out
}

// jsonlWriter is a thin JSON-encoding layer over a RotatingFile — the
// rotation mechanics live in rotate.go, shared with cmd/netwatch's
// plain-text log.
type jsonlWriter struct {
	rf *RotatingFile
}

func newJSONLWriter(path string) (*jsonlWriter, error) {
	rf, err := NewRotatingFile(path, LogMaxBytes, LogMaxBackups)
	if err != nil {
		return nil, err
	}
	return &jsonlWriter{rf: rf}, nil
}

func (w *jsonlWriter) Write(v any) {
	if w == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = w.rf.Write(b) // best-effort; a full disk shouldn't crash the monitor
}

func (w *jsonlWriter) Close() {
	if w == nil {
		return
	}
	_ = w.rf.Close()
}
