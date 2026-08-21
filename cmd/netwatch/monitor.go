package main

import (
	"context"
	"sync"

	"netwatch/internal/certcheck"
	"netwatch/internal/etwmon"
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
type monitorController struct {
	// buildCollector/buildChecker are the ingredients captured once by
	// main() — the same Handlers, selfPID, -debug-etw path, etc. every
	// time — used to construct a fresh instance on every Start.
	// buildChecker returns nil when cert-checking is disabled
	// (-disable-cert-check), in which case Start just skips it.
	buildCollector func() (*etwmon.Collector, error)
	buildChecker   func() *certcheck.Checker

	mu          sync.Mutex
	running     bool
	collector   *etwmon.Collector
	certChecker *certcheck.Checker
	cancel      context.CancelFunc
}

func newMonitorController(buildCollector func() (*etwmon.Collector, error), buildChecker func() *certcheck.Checker) *monitorController {
	return &monitorController{buildCollector: buildCollector, buildChecker: buildChecker}
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

// Stop tears down the collector/checker if running; a no-op otherwise.
// Everything else in the process — store, window, tray — is untouched.
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
}

// Start (re)builds and starts a fresh collector (and checker, unless
// disabled) if not already running. Unlike main()'s own initial-boot start
// sequence, a failure here is returned rather than treated as fatal — this
// is reachable from the running dashboard's "Start Monitoring" button, and
// a bad restart attempt should surface an error to the user, not take the
// whole app down with it.
func (m *monitorController) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return nil
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
