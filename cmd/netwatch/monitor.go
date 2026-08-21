package main

import (
	"context"
	"log"
	"sync"

	"netwatch/internal/certcheck"
	"netwatch/internal/etwmon"
	"netwatch/internal/store"
)

// monitorController owns the lifecycle of the two things that actually
// generate findings — the ETW collector and the periodic cert-check
// prober — independently of the store/window/tray/process, which live for
// the whole run regardless. This is what makes the dashboard's "Stop
// Monitoring" a real pause rather than requiring exiting the whole app: it
// tears down and (on a later Start) rebuilds the ETW real-time session and
// cert-check ticker, while the store keeps serving already-collected
// history and the window/tray stay exactly as they were. Contrast with
// Quit/doQuit in main.go, which tears down everything including the
// process itself.
//
// Both the collector and the checker are rebuilt from scratch on every
// Start rather than reusing a stopped instance. That's a deliberate
// simplification, not an oversight: certcheck.Checker.Stop() closes its
// own stopCh exactly once (see its source) — calling Start() again on that
// same instance afterward would find the channel already permanently
// closed and its loop would return immediately, silently monitoring
// nothing. Rebuilding both sidesteps having to reason about which of the
// two objects would actually tolerate a restart in place and which
// wouldn't; etwmon.New/certcheck.New are both cheap (no real work happens
// until Start).
//
// Stop/Start also close and reopen the on-disk log files (the store's five
// JSONL logs, plus netwatch.log) — not just the collector/checker that
// feed them. Nothing about "pausing collection" strictly requires that;
// it's here because Windows blocks deleting a file that's still open for
// append, even by the same process that opened it, regardless of whether
// anything is actively being written to it. Without closing these
// handles too, the settings panel's Clean Logs button could only ever
// fully succeed after Exit Program — Stop Monitoring alone would leave
// every active log file locked. Store.Close/CloseLogFiles ordinarily runs
// once at final shutdown; here it's paired with a later ReopenLogFiles so
// the store's in-memory ring buffers, subscribers, and alert history are
// completely unaffected by the gap.
type monitorController struct {
	// buildCollector/buildChecker are the ingredients captured once by
	// main() — the same Handlers, selfPID, -debug-etw path, etc. every
	// time — used to construct a fresh instance on every Start.
	// buildChecker returns nil when cert-checking is disabled
	// (-disable-cert-check), in which case Start just skips it.
	buildCollector func() (*etwmon.Collector, error)
	buildChecker   func() *certcheck.Checker

	// st/appLog are the log-file owners closed on Stop and reopened on
	// Start, alongside the collector/checker — see the type doc comment.
	// appLog is nil when netwatch.log failed to open at startup (main()
	// already degrades to stderr-only logging in that case; Stop/Start
	// just skip it too rather than erroring).
	st     *store.Store
	appLog *store.RotatingFile

	mu          sync.Mutex
	running     bool
	collector   *etwmon.Collector
	certChecker *certcheck.Checker
	cancel      context.CancelFunc
}

func newMonitorController(buildCollector func() (*etwmon.Collector, error), buildChecker func() *certcheck.Checker, st *store.Store, appLog *store.RotatingFile) *monitorController {
	return &monitorController{buildCollector: buildCollector, buildChecker: buildChecker, st: st, appLog: appLog}
}

// adopt registers a collector/checker/cancel that main() already
// constructed and started itself at boot (with its own fatal-on-failure
// handling — see main()'s comment on why that stays separate from Start,
// below). From this point on, Stop/Start manage its lifecycle.
func (m *monitorController) adopt(c *etwmon.Collector, cc *certcheck.Checker, cancel context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collector = c
	m.certChecker = cc
	m.cancel = cancel
	m.running = true
}

// Running reports whether the collector/checker are currently active.
func (m *monitorController) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Stop tears down the collector/checker if running, then closes the log
// file handles they were feeding (see the type doc comment for why); a
// no-op otherwise. Everything else in the process — the store's in-memory
// state, window, tray — is untouched.
func (m *monitorController) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *monitorController) stopLocked() {
	if !m.running {
		return
	}
	if m.cancel != nil {
		m.cancel()
	}
	if m.collector != nil {
		m.collector.Stop()
	}
	if m.certChecker != nil {
		m.certChecker.Stop()
	}
	m.collector = nil
	m.certChecker = nil
	m.cancel = nil
	m.running = false

	// Closed last, after the producers that write to these files are
	// fully torn down — any trailing event still in flight from that
	// teardown hits a nil file handle and is silently dropped
	// (RotatingFile.Write's existing best-effort behavior) rather than
	// racing a live write against Close.
	if m.st != nil {
		m.st.CloseLogFiles()
	}
	if m.appLog != nil {
		_ = m.appLog.Close()
	}
}

// Start (re)builds and starts a fresh collector (and checker, unless
// disabled) if not already running, after first reopening the log files
// Stop closed (see the type doc comment). Unlike main()'s own initial-boot
// start sequence, a failure here is returned rather than treated as fatal
// — this is reachable from the running dashboard's "Start Monitoring"
// button, and a bad restart attempt should surface an error to the user,
// not take the whole app down with it.
func (m *monitorController) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
	}

	// Reopened before the collector/checker exist, so there's no window
	// where they could already be emitting events into files that aren't
	// back open yet. Best-effort: a file that fails to reopen (e.g. its
	// directory got removed out from under the running process) just
	// silently drops writes going forward, same as any other RotatingFile
	// hiccup elsewhere in this codebase — it shouldn't block monitoring
	// from resuming.
	if m.st != nil {
		if err := m.st.ReopenLogFiles(); err != nil {
			log.Printf("reopen store log files: %v", err)
		}
	}
	if m.appLog != nil {
		if err := m.appLog.Reopen(); err != nil {
			log.Printf("reopen netwatch.log: %v", err)
		}
	}

	collector, err := m.buildCollector()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := collector.Start(ctx); err != nil {
		cancel()
		return err
	}

	var checker *certcheck.Checker
	if m.buildChecker != nil {
		checker = m.buildChecker()
		if checker != nil {
			_ = checker.Start(ctx) // always succeeds — see its own doc comment
		}
	}

	m.collector = collector
	m.certChecker = checker
	m.cancel = cancel
	m.running = true
	return nil
}
