//go:build windows

// Package tray manages the Windows notification-area icon: a calm blue dot
// while nothing is wrong, switching to red the moment there is an
// unacknowledged high/critical alert, so a glance at the taskbar is enough
// to know something needs attention without keeping the dashboard window open.
package tray

import (
	_ "embed"
	"runtime"

	"github.com/energye/systray"

	"netwatch/internal/i18n"
)

//go:embed assets/icon_normal.ico
var iconNormal []byte

//go:embed assets/icon_alert.ico
var iconAlert []byte

// Run blocks until the user chooses the tray menu's "quit" item (tray.quit
// in internal/i18n's catalog). onOpen is invoked on a left click (or the
// right-click menu's "open" item); onQuit is invoked once, right before the
// tray loop tears down, and is expected to perform cleanup and terminate
// the process.
//
// cmd/netwatch calls this from its own dedicated goroutine (Wails' own
// window claims the main goroutine/thread instead), which is exactly the
// case that needs care: on Windows a window's message queue lives on the
// OS thread that created it — GetMessage/DispatchMessage (and therefore
// every click, including quit) only ever get delivered to that same
// thread. systray's package init() calls runtime.LockOSThread(), but that
// pins whichever goroutine happens to run package initialization (the
// program's main goroutine, here already spoken for by Wails) — it does
// nothing to protect a goroutine spawned later by our own code. Without a
// second, explicit LockOSThread() right here, the Go scheduler is free to
// migrate this goroutine to a different OS thread at any preemption point
// (Go 1.14+ can preempt essentially anywhere), silently orphaning the tray
// window's message queue on the old thread — GetMessage on the new thread
// then blocks forever with nothing left to deliver. That's the "sometimes
// right-click does nothing / the tray hangs" bug: non-deterministic
// because it only manifests on whichever run the scheduler happens to move
// this goroutine at an inopportune moment.
func Run(onOpen func(), onQuit func()) {
	runtime.LockOSThread()
	systray.Run(func() { onReady(onOpen, onQuit) }, func() {})
}

// openItem/statusItem/quitItem are kept at package scope (rather than only
// as onReady locals) so Relabel can re-set their text after a language
// switch — systray never exposes a way to enumerate a running instance's
// own menu items back out, so whatever created them has to be the one
// holding onto them.
var (
	openItem   *systray.MenuItem
	statusItem *systray.MenuItem
	quitItem   *systray.MenuItem
)

func onReady(onOpen func(), onQuit func()) {
	systray.SetIcon(iconNormal)
	systray.SetTooltip(i18n.T("tray.tooltip_normal"))

	openItem = systray.AddMenuItem(i18n.T("tray.open"), i18n.T("tray.open_desc"))
	systray.AddSeparator()
	statusItem = systray.AddMenuItem(i18n.T("tray.status_normal"), "")
	statusItem.Disable()
	systray.AddSeparator()
	quitItem = systray.AddMenuItem(i18n.T("tray.quit"), i18n.T("tray.quit_desc"))
	open, quit := openItem, quitItem

	// Menu item clicks, and SetOnClick/SetOnRClick below, run synchronously
	// on the tray's own message-loop thread — called directly from wndProc,
	// unlike the previous getlantern/systray, which dispatched over a
	// channel to a separate goroutine (see MenuItem.ClickedCh in the old
	// API). onOpen/onQuit do real work (Wails window calls, stopping the
	// ETW collector, closing log files...), so each is bounced onto its own
	// goroutine here to keep the message pump itself from ever blocking on
	// it — the exact class of bug already fixed once in this file (see
	// Run's doc comment above) isn't worth risking again.
	open.Click(func() {
		if onOpen != nil {
			go onOpen()
		}
	})
	quit.Click(func() {
		if onQuit != nil {
			go onQuit()
		}
	})

	// Left click opens the dashboard directly; right click shows the menu.
	// getlantern/systray (the library this used to run on) shows the same
	// native menu for either click with no way to tell them apart — that's
	// why this package moved to energye/systray, a fork that exposes
	// SetOnClick/SetOnRClick separately. Once SetOnRClick is set, the
	// library stops auto-showing the menu on right click (see its doc
	// comment), so ShowMenu() has to be called explicitly here to keep that
	// behavior.
	systray.SetOnClick(func(_ systray.IMenu) {
		if onOpen != nil {
			go onOpen()
		}
	})
	systray.SetOnRClick(func(menu systray.IMenu) {
		_ = menu.ShowMenu()
	})
}

// SetAlert switches the tray icon between the calm/blue and alert/red
// states and updates the tooltip text.
func SetAlert(active bool, tooltip string) {
	if active {
		systray.SetIcon(iconAlert)
	} else {
		systray.SetIcon(iconNormal)
	}
	systray.SetTooltip(tooltip)
}

// Quit tears down the tray icon; call after onQuit has finished cleanup.
func Quit() {
	systray.Quit()
}

// Relabel re-applies internal/i18n's current-language text to the tray's
// static menu items (the tooltip icon-state text is rebuilt fresh every
// 2s poll by cmd/netwatch already, so it needs no help here). Call this
// right after internal/i18n.Set switches the active language, so a
// language change made from the dashboard is reflected in the tray
// immediately rather than only on the next restart. A no-op if called
// before onReady has run (nothing to relabel yet).
func Relabel() {
	if openItem == nil {
		return
	}
	openItem.SetTitle(i18n.T("tray.open"))
	openItem.SetTooltip(i18n.T("tray.open_desc"))
	statusItem.SetTitle(i18n.T("tray.status_normal"))
	quitItem.SetTitle(i18n.T("tray.quit"))
	quitItem.SetTooltip(i18n.T("tray.quit_desc"))
}
