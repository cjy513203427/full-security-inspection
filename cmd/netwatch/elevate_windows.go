//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// isElevated reports whether the current process token has admin rights.
// ETW real-time kernel sessions require this.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated re-executes the current exe with the same arguments via
// ShellExecute's "runas" verb, which triggers the standard UAC consent
// dialog. It does not wait for the child; the caller should exit
// immediately after this returns successfully.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := make([]string, len(os.Args)-1)
	for i, a := range os.Args[1:] {
		if strings.ContainsAny(a, " \t\"") {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		args[i] = a
	}
	return shellExecute("runas", exe, strings.Join(args, " "))
}

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

const swShowNormal = 1

func shellExecute(verb, file, args string) error {
	v, err := syscall.UTF16PtrFromString(verb)
	if err != nil {
		return err
	}
	f, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return err
	}
	a, err := syscall.UTF16PtrFromString(args)
	if err != nil {
		return err
	}
	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(v)),
		uintptr(unsafe.Pointer(f)),
		uintptr(unsafe.Pointer(a)),
		0,
		uintptr(swShowNormal),
	)
	if ret <= 32 {
		return fmt.Errorf("ShellExecute(runas) failed, code %d (user likely declined the UAC prompt)", ret)
	}
	return nil
}

// singleInstanceMutex identifies the one running monitor instance for this
// user session, checked BEFORE any of the real (and occasionally fallible)
// startup work — opening the data dir, starting an ETW session, etc.
//
// Wails' own SingleInstanceLock (see main.go's options.App) also dedups,
// but only once wails.Run() actually gets called — every double-click
// still redoes all the startup work first and, if that startup work ever
// fails, each independent attempt would pop its own error box before
// Wails' dedup ever got a chance to run. Gating here instead means a
// second launch never does any of that work and never shows anything —
// it just quietly asks the first instance to come to the front and exits.
const singleInstanceMutex = "NetWatchCookieGuard_EarlyGate_v1"

// acquireSingleInstance reports whether another instance already holds the
// gate. The held handle is intentionally leaked for the process's
// lifetime — the OS releases it on exit, which is exactly the signal
// relied on here.
func acquireSingleInstance() (alreadyRunning bool) {
	name, err := syscall.UTF16PtrFromString(singleInstanceMutex)
	if err != nil {
		return false // fail open: never block startup over a name-encoding error
	}
	_, err = windows.CreateMutex(nil, false, name)
	if err == nil {
		return false // we are the first/only instance
	}
	if errno, ok := err.(syscall.Errno); ok && errno == windows.ERROR_ALREADY_EXISTS {
		return true
	}
	return false // unexpected error: fail open rather than ever block startup
}

// focusExistingWindow brings the already-running instance's window to the
// front, best-effort — findWindow failing just means the user has to find
// it in the taskbar/tray themselves, which is a minor inconvenience, not
// worth popping anything up over.
func focusExistingWindow() {
	title, err := syscall.UTF16PtrFromString("NetWatch CookieGuard")
	if err != nil {
		return
	}
	hwnd := findWindow(title)
	if hwnd == 0 {
		return
	}
	const swRestore = 9
	showWindow(hwnd, swRestore)
	setForegroundWindow(hwnd)
}

var (
	user32               = syscall.NewLazyDLL("user32.dll")
	procFindWindowW      = user32.NewProc("FindWindowW")
	procShowWindow       = user32.NewProc("ShowWindow")
	procSetForegroundWnd = user32.NewProc("SetForegroundWindow")

	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
)

func findWindow(windowName *uint16) uintptr {
	ret, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(windowName)))
	return ret
}

func showWindow(hwnd uintptr, cmd int) {
	_, _, _ = procShowWindow.Call(hwnd, uintptr(cmd))
}

func setForegroundWindow(hwnd uintptr) {
	_, _, _ = procSetForegroundWnd.Call(hwnd)
}

// hasConsole reports whether this process is attached to a console window
// — true for netwatch-debug.exe run from an actual terminal (where a
// fmt.Println is already visible), false for the windowsgui release build
// double-clicked from Explorer (where a message box is the only way to
// show anything) and also false for any non-interactive/background
// invocation. Used to skip popping a confirmation dialog when the console
// output already covers it — a modal box with nobody there to click it
// would otherwise just hang the process.
func hasConsole() bool {
	ret, _, _ := procGetConsoleWindow.Call()
	return ret != 0
}

const (
	mbOK            = 0x00000000
	mbIconError     = 0x00000010
	mbIconInfo      = 0x00000040
	mbTopmost       = 0x00040000
	mbSetForeground = 0x00010000
)

// showErrorBox surfaces a message even when running under the windowsgui
// subsystem (no console for log output to appear on). Always shown,
// console or not — a fatal error is rare and important enough to warrant
// the belt-and-suspenders visibility, and fatalWithBox already calls
// log.Print alongside it for the console case.
func showErrorBox(title, msg string) {
	messageBox(title, msg, mbIconError)
}

// showInfoBox is for routine one-off confirmations (-install-autostart,
// -clean-logs, ...) that also already print to stdout. It's skipped
// whenever a console is attached, for two reasons: the printed text is
// already visible there, and — more importantly — MessageBox blocks until
// someone clicks it, so if this were ever invoked from a non-interactive
// context (a script, a scheduled task, this tool's own test suite) with no
// console and no one to click "OK", the process would just hang forever.
// hasConsole() is an imperfect proxy for "interactive", but it's the same
// signal that correctly separates "run from Explorer" (needs the popup)
// from "run from a terminal" (doesn't).
func showInfoBox(title, msg string) {
	if hasConsole() {
		return
	}
	messageBox(title, msg, mbIconInfo)
}

func messageBox(title, msg string, icon uint32) {
	t, err1 := syscall.UTF16PtrFromString(title)
	m, err2 := syscall.UTF16PtrFromString(msg)
	if err1 != nil || err2 != nil {
		return
	}
	_, _ = windows.MessageBox(0, m, t, mbOK|icon|mbTopmost|mbSetForeground)
}
