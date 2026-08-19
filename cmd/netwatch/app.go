package main

import (
	"context"
	"sync"

	"netwatch/internal/model"
	"netwatch/internal/store"
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
	Alerts []model.Alert              `json:"alerts"`
	Nets   []model.NetEvent           `json:"nets"`
	Files  []model.SensitiveFileEvent `json:"files"`
	DNS    []model.DNSEvent           `json:"dns"`
	Procs  []model.ProcessInfo        `json:"procs"`
}

// GetSnapshot returns the current in-memory state for the dashboard's
// first render.
func (a *App) GetSnapshot() Snapshot {
	return Snapshot{
		Alerts: a.st.RecentAlerts(500),
		Nets:   a.st.RecentNets(500),
		Files:  a.st.RecentFiles(500),
		DNS:    a.st.RecentDNS(500),
		Procs:  a.st.AllProcs(),
	}
}

// AckAlert marks an alert acknowledged.
func (a *App) AckAlert(seq uint64) {
	a.st.AckAlert(seq)
}
