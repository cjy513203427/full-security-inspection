//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

const taskName = "NetWatchCookieGuard"

// installAutostart registers a Scheduled Task that launches the monitor
// (elevated, window hidden, tray icon only) at user logon, so it comes
// back after every reboot without the user having to remember to relaunch
// it. Using Task Scheduler with /RL HIGHEST rather than a plain Run
// registry key means Windows grants it Administrator rights directly at
// logon instead of a UAC prompt appearing every time.
func installAutostart(exePath string) error {
	args := []string{
		"/Create", "/F",
		"/SC", "ONLOGON",
		"/RL", "HIGHEST",
		"/TN", taskName,
		"/TR", fmt.Sprintf(`"%s" -start-hidden`, exePath),
	}
	cmd := exec.Command("schtasks.exe", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Create failed: %v: %s", err, string(out))
	}
	return nil
}

func uninstallAutostart() error {
	cmd := exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Delete failed: %v: %s", err, string(out))
	}
	return nil
}

// autostartEnabled reports whether the scheduled task is currently
// registered, by asking Task Scheduler directly rather than tracking our
// own state — that way it's always correct even if the task was
// registered/removed by an older build's CLI flags, or edited by hand.
// schtasks /Query exits non-zero (and writes an error to stderr, discarded
// here) when the task doesn't exist; that exit status alone is all this
// needs; parsing its human-readable output would be far more fragile.
func autostartEnabled() bool {
	cmd := exec.Command("schtasks.exe", "/Query", "/TN", taskName)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run() == nil
}
