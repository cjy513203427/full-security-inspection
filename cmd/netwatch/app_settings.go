package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"netwatch/internal/i18n"
)

// GetDataDir returns the directory this instance is logging/storing its
// JSONL history and netwatch.log into — the dashboard's settings panel
// displays this and offers to open it directly, so a user reporting a bug
// doesn't have to go hunting for -data-dir's default first.
func (a *App) GetDataDir() string {
	return a.dataDir
}

// OpenDataDir opens the data directory in Windows Explorer.
func (a *App) OpenDataDir() error {
	return exec.Command("explorer.exe", a.dataDir).Start()
}

// CleanLogsResult is what CleanLogs reports back to the dashboard.
type CleanLogsResult struct {
	FreedBytes int64 `json:"freedBytes"`
	// Error is set when some file(s) still couldn't be removed even after
	// CleanLogs paused monitoring around the delete (see CleanLogs) — at
	// that point the file's own open-for-append handle is out of the
	// picture, so a lingering lock here means something else entirely has
	// it open (antivirus scanning it, a text editor, Explorer's preview
	// pane, ...). Deliberately a string field rather than this method
	// itself returning (CleanLogsResult, error): a partial clean freeing
	// real disk space while also reporting that some files are locked is
	// an expected, tell-the-user-about-it outcome here, not a failed RPC
	// call — Wails would reject the whole JS Promise (discarding
	// FreedBytes) if this were a real Go error return instead.
	Error string `json:"error,omitempty"`
}

// CleanLogs runs the same cleanup the -clean-logs CLI flag performs, but
// from a live, already-running instance — called from the dashboard's
// settings panel. That changes what it can actually delete: rotated
// backups (base.1, base.2, ...) aren't held open by anything and always
// go; the *active* log files (netwatch.log, alerts.jsonl, ...) are open
// for append by this process, and Windows won't let even the process that
// opened them delete them out from under itself without FILE_SHARE_DELETE
// (which they weren't opened with) — for as long as that handle stays
// open.
//
// Rather than making the user manually stop monitoring first (or exit the
// whole app) to release those handles, CleanLogs does it itself: if
// monitoring is currently running, it's paused for the duration of the
// delete (closing every log file's handle — see monitorController.Stop)
// and resumed right after (reopening them — see monitorController.Start),
// so a single click always fully cleans regardless of monitoring state.
// If monitoring wasn't running to begin with, this is just a plain delete
// — the handles are already closed. A failure resuming monitoring
// afterward is logged but not folded into CleanLogsResult.Error, which
// means specifically "a log file is still locked" — the dashboard's
// existing "monitoring status" refresh (GetMonitoring) is what surfaces a
// resume failure, not this call.
func (a *App) CleanLogs() CleanLogsResult {
	wasRunning := a.mon != nil && a.mon.Running()
	if wasRunning {
		a.mon.Stop()
	}

	freed, err := cleanLogFiles(a.dataDir)

	if wasRunning {
		if startErr := a.mon.Start(); startErr != nil {
			log.Printf("resume monitoring after clean logs: %v", startErr)
		}
	}

	res := CleanLogsResult{FreedBytes: freed}
	if err != nil {
		res.Error = err.Error()
	}
	return res
}

// GetMonitoring reports whether the ETW collector/cert-checker are
// currently active. false either right after StopMonitoring, or (rare,
// -skip-elevate debug builds only) if the very first Start at boot never
// managed to actually collect anything.
func (a *App) GetMonitoring() bool {
	if a.mon == nil {
		return false
	}
	return a.mon.Running()
}

// StopMonitoring pauses collection (the ETW collector and the periodic
// cert-check prober) without exiting the program — unlike Quit, the
// window, tray, and store all stay up. Already-collected history stays
// visible in the dashboard; nothing new arrives until StartMonitoring.
//
// It also releases the on-disk log files' Windows file handles (see
// monitorController.Stop) — not because the user needs to invoke this
// specifically for that; CleanLogs (below) calls Stop/Start around its
// own delete itself, so the user never has to. StopMonitoring closes them
// unconditionally on every call regardless, since there's no reason to
// keep those handles open while collection is paused anyway.
func (a *App) StopMonitoring() {
	if a.mon == nil {
		return
	}
	log.Println(i18n.T("log.monitoring_stopped_by_user"))
	a.mon.Stop()
}

// StartMonitoring resumes collection after StopMonitoring, rebuilding the
// ETW collector/cert-checker from scratch (see monitorController's doc
// comment for why) — and, before that, reopening the log files
// StopMonitoring closed. Returns an error rather than treating a failure
// as fatal — unlike the very first start at boot, a restart failing here
// should be reported back to the dashboard, not take the whole process
// down with it.
func (a *App) StartMonitoring() error {
	if a.mon == nil {
		return nil
	}
	if err := a.mon.Start(); err != nil {
		return err
	}
	log.Println(i18n.T("log.monitoring_started_by_user"))
	return nil
}

// GetAutostartEnabled reports whether the login scheduled task (see
// autostart_windows.go) is currently registered.
func (a *App) GetAutostartEnabled() bool {
	return autostartEnabled()
}

// SetAutostart installs or removes the login scheduled task and returns
// the resulting state, so the dashboard's checkbox can reflect what
// actually happened rather than optimistically assuming the toggle
// succeeded.
func (a *App) SetAutostart(enabled bool) (bool, error) {
	if enabled {
		exe, err := os.Executable()
		if err != nil {
			return autostartEnabled(), fmt.Errorf("resolve own executable path: %w", err)
		}
		if err := installAutostart(exe); err != nil {
			return autostartEnabled(), err
		}
	} else {
		if err := uninstallAutostart(); err != nil {
			return autostartEnabled(), err
		}
	}
	return autostartEnabled(), nil
}
