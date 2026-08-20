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
}

func NewApp(st *store.Store) *App {
	return &App{st: st}
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
