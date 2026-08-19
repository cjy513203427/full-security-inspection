package main

import (
	"context"

	"netwatch/internal/model"
	"netwatch/internal/store"
)

// App is Wails' bound object: its exported methods become directly
// callable from the frontend as window.go.main.App.<Method>(...), each
// returning a Promise resolving to the JSON-marshaled return value.
type App struct {
	ctx context.Context
	st  *store.Store
}

func NewApp(st *store.Store) *App {
	return &App{st: st}
}

// startup is Wails' OnStartup hook target; ctx becomes usable for
// runtime.EventsEmit/WindowShow/etc. only after this fires.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
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
