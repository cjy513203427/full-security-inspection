//go:build windows

// Package tray manages the Windows notification-area icon: a calm blue dot
// while nothing is wrong, switching to red the moment there is an
// unacknowledged high/critical alert, so a glance at the taskbar is enough
// to know something needs attention without keeping the dashboard tab open.
package tray

import (
	_ "embed"

	"github.com/getlantern/systray"
)

//go:embed assets/icon_normal.ico
var iconNormal []byte

//go:embed assets/icon_alert.ico
var iconAlert []byte

// Run blocks until the user chooses "退出" from the tray menu. onOpen is
// invoked when the user clicks "打开监控面板"; onQuit is invoked once, right
// before the tray loop tears down, and is expected to perform cleanup and
// terminate the process.
func Run(onOpen func(), onQuit func()) {
	systray.Run(func() { onReady(onOpen, onQuit) }, func() {})
}

func onReady(onOpen func(), onQuit func()) {
	systray.SetIcon(iconNormal)
	systray.SetTooltip("NetWatch CookieGuard - 正常监控中")

	open := systray.AddMenuItem("打开监控面板", "在浏览器中打开仪表盘")
	systray.AddSeparator()
	status := systray.AddMenuItem("状态: 正常监控中", "")
	status.Disable()
	systray.AddSeparator()
	quit := systray.AddMenuItem("退出监控", "停止监控并退出")

	go func() {
		for {
			select {
			case <-open.ClickedCh:
				if onOpen != nil {
					onOpen()
				}
			case <-quit.ClickedCh:
				if onQuit != nil {
					onQuit()
				}
				return
			}
		}
	}()
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
