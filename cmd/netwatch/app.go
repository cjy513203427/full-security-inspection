package main

import (
	"context"
	"sync"

	"netwatch/internal/i18n"
	"netwatch/internal/model"
	"netwatch/internal/store"
	"netwatch/internal/tray"
)

// App is Wails' bound object: its exported methods become directly
// callable from the frontend as window.go.main.App.<Method>(...), each
// returning a Promise resolving to the JSON-marshaled return value.
type App struct {
	st *store.Store

	// dataDir is where this instance logs/stores its JSONL history and
	// netwatch.log — plumbed through from main()'s -data-dir flag so the
	// settings panel's log-directory display/open/clean actions (see
	// app_settings.go) don't need their own separate path resolution.
	dataDir string

	// ctx is written once, from Wails' OnStartup callback, and read from
	// other goroutines afterward (the tray icon's click handlers, the
	// critical-count poller). Those reads can in principle happen before
	// OnStartup ever fires (nothing prevents the tray icon from being
	// clicked immediately on process start), so this needs real
	// synchronization rather than a bare pointer field — a torn or
	// stale read here would either panic or silently no-op a window
	// show/quit request.
	ctxMu sync.RWMutex
	ctx   context.Context

	// quitFn is main()'s doQuit closure (set once, right after
	// construction, via SetQuitFunc) — the single real shutdown sequence
	// shared between the tray's "Exit Program" menu item and Quit, below,
	// so the dashboard's own settings-modal button doesn't need (and
	// can't accidentally drift from) its own copy of that ordering.
	quitFn func()

	// mon is main()'s monitorController (set once via SetMonitor) — lets
	// the dashboard's "Stop Monitoring"/"Start Monitoring" toggle
	// (app_settings.go) pause and resume the ETW collector/cert-checker
	// without touching the window, tray, or process itself, unlike Quit.
	mon *monitorController
}

func NewApp(st *store.Store, dataDir string) *App {
	return &App{st: st, dataDir: dataDir}
}

// startup is Wails' OnStartup hook target; ctx becomes usable for
// runtime.EventsEmit/WindowShow/etc. only after this fires.
func (a *App) startup(ctx context.Context) {
	a.ctxMu.Lock()
	a.ctx = ctx
	a.ctxMu.Unlock()
}

// Context returns the Wails runtime context and true once startup has
// completed, or (nil, false) if called before then.
func (a *App) Context() (context.Context, bool) {
	a.ctxMu.RLock()
	defer a.ctxMu.RUnlock()
	return a.ctx, a.ctx != nil
}

// SetQuitFunc records the shutdown sequence Quit should invoke. Called
// exactly once, synchronously, from main() right after NewApp — before the
// tray goroutine is spawned or wails.Run (and therefore any JS-reachable
// call to Quit) starts, so no synchronization is needed around the field
// itself: the write happens-before every possible read.
func (a *App) SetQuitFunc(fn func()) {
	a.quitFn = fn
}

// Quit stops monitoring and exits the whole process — the dashboard's
// "Quit Monitoring" button in the settings modal, doing exactly what the
// tray icon's "quit" menu item does (they share the same closure; see
// main()'s doQuit). The frontend is expected to confirm with the user
// first: unlike closing the window (which just hides it, per
// HideWindowOnClose), this really does end monitoring.
func (a *App) Quit() {
	if a.quitFn != nil {
		a.quitFn()
	}
}

// SetMonitor records the monitorController Stop/StartMonitoring should
// drive. Called exactly once, synchronously, from main() — same
// happens-before reasoning as SetQuitFunc above, so no synchronization is
// needed around the field itself.
func (a *App) SetMonitor(m *monitorController) {
	a.mon = m
}

// Snapshot is the initial-load payload the dashboard fetches once on
// startup, before live updates take over via Wails events.
type Snapshot struct {
	Alerts     []model.Alert              `json:"alerts"`
	Nets       []model.NetEvent           `json:"nets"`
	Files      []model.SensitiveFileEvent `json:"files"`
	DNS        []model.DNSEvent           `json:"dns"`
	Procs      []model.ProcessInfo        `json:"procs"`
	CertChecks []model.CertCheckEvent     `json:"certChecks"`
}

// GetSnapshot returns the current in-memory state for the dashboard's
// first render.
func (a *App) GetSnapshot() Snapshot {
	return Snapshot{
		Alerts:     a.st.RecentAlerts(500),
		Nets:       a.st.RecentNets(500),
		Files:      a.st.RecentFiles(500),
		DNS:        a.st.RecentDNS(500),
		Procs:      a.st.AllProcs(),
		CertChecks: a.st.RecentCertChecks(500),
	}
}

// AckAlert marks an alert acknowledged.
func (a *App) AckAlert(seq uint64) {
	a.st.AckAlert(seq)
}

// GetLanguage returns the backend's currently active UI language code
// ("zh"/"en"/"de") — the dashboard's language switcher reads this once on
// load, before it has any persisted localStorage preference of its own
// (e.g. the very first launch on a fresh profile), so a brand-new install
// still opens in whatever language internal/i18n.Init() resolved (a
// previously saved preference, else the Windows UI language) instead of
// defaulting to English regardless of the user's system.
func (a *App) GetLanguage() string {
	return string(i18n.Current())
}

// SetLanguage switches the active language for everything outside the
// dashboard's own DOM: future alert/certcheck Title/Detail text, the tray
// menu (relabeled immediately, not just on the next launch), and CLI/log
// output on the next launch — and persists the choice. The dashboard's own
// static UI text is translated entirely client-side (see
// internal/web/static/i18n.js) and doesn't wait on this call to update; it
// calls this in the background purely so the rest of the app follows suit.
// An unrecognized code falls back to English rather than silently no-op'ing
// — defensive rather than expected, since the frontend only ever sends one
// of the three languages it itself offers.
func (a *App) SetLanguage(lang string) string {
	l, ok := i18n.ParseLang(lang)
	if !ok {
		l = i18n.EN
	}
	_ = i18n.Set(l) // best-effort persistence; the in-memory switch happens regardless of whether the write to disk succeeds
	tray.Relabel()
	return string(l)
}
