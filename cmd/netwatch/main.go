// Command netwatch (NetWatch CookieGuard) is a background monitor that
// watches, per-process, outbound network connections and access to
// browser/app cookie & credential stores, and raises an alert the moment a
// process that doesn't own a credential file touches it and then phones
// home — the signature behavior of an infostealer.
//
// It needs Administrator rights (to open real-time ETW kernel sessions) and
// self-elevates via UAC on launch. Everything it collects stays on this
// machine: JSONL logs under the data directory, and a native window (via
// WebView2) hosting the dashboard — no network port, no browser dependency.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"netwatch/internal/certcheck"
	"netwatch/internal/correlate"
	"netwatch/internal/etwmon"
	"netwatch/internal/i18n"
	"netwatch/internal/model"
	"netwatch/internal/procinfo"
	"netwatch/internal/store"
	"netwatch/internal/tray"
	"netwatch/internal/web"
)

// singleInstanceID is an arbitrary fixed string identifying this app to
// Wails' built-in single-instance lock (see options.App.SingleInstanceLock
// below) — a second launch is detected and handed off automatically
// (window brought to front) instead of racing the first for resources.
const singleInstanceID = "netwatch-cookieguard-9f3e7b2a"

func main() {
	// Must run before any flag.String/flag.Bool call below: their
	// description text is built immediately, via i18n.T(), from whatever
	// language Init() resolves (a persisted preference, else the Windows UI
	// language) — including for -h/--help output, which never gets a chance
	// to touch anything else in this file first.
	i18n.Init()

	dataDir := flag.String("data-dir", defaultDataDir(), i18n.T("flag.data_dir"))
	debugETW := flag.String("debug-etw", "", i18n.T("flag.debug_etw"))
	skipElevate := flag.Bool("skip-elevate", false, i18n.T("flag.skip_elevate"))
	startHidden := flag.Bool("start-hidden", false, i18n.T("flag.start_hidden"))
	installAuto := flag.Bool("install-autostart", false, i18n.T("flag.install_autostart"))
	uninstallAuto := flag.Bool("uninstall-autostart", false, i18n.T("flag.uninstall_autostart"))
	cleanLogs := flag.Bool("clean-logs", false, i18n.T("flag.clean_logs"))
	disableCertCheck := flag.Bool("disable-cert-check", false, i18n.T("flag.disable_cert_check"))
	langFlag := flag.String("lang", "", i18n.T("flag.lang"))
	// Accepted for backward compatibility with scheduled tasks registered by
	// older builds (pre-native-window); no longer meaningful, silently ignored.
	flag.Bool("no-browser", false, i18n.T("flag.deprecated_no_browser"))
	flag.Int("port", 0, i18n.T("flag.deprecated_port"))
	flag.Parse()

	// A one-off override for this run only (doesn't persist — see
	// i18n.SetSession's doc comment); the dashboard's language switcher is
	// what persists a choice across launches.
	if *langFlag != "" {
		if l, ok := i18n.ParseLang(*langFlag); ok {
			i18n.SetSession(l)
		} else {
			log.Printf("unrecognized -lang %q, ignoring (expected zh/en/de)", *langFlag)
		}
	}

	// Doesn't touch anything that needs Administrator rights (it's just
	// deleting the user's own files under %LOCALAPPDATA%), so this is
	// handled before the elevation gate below — no reason to make the user
	// click through a UAC prompt just to free up disk space.
	if *cleanLogs {
		freed, err := cleanLogFiles(*dataDir)
		if err != nil {
			fatalWithBox(i18n.T("log.clean_logs_failed"), err)
		}
		msg := i18n.T("log.clean_logs_done", float64(freed)/(1<<20))
		fmt.Println(msg)
		showInfoBox("NetWatch CookieGuard", msg)
		return
	}

	if !*skipElevate && !isElevated() {
		log.Println(i18n.T("log.requesting_elevation"))
		if err := relaunchElevated(); err != nil {
			fatalWithBox(i18n.T("log.elevation_failed"), err)
		}
		return
	}

	if *installAuto {
		exe, err := os.Executable()
		if err != nil {
			fatalWithBox(i18n.T("log.get_self_path_failed"), err)
		}
		if err := installAutostart(exe); err != nil {
			fatalWithBox(i18n.T("log.install_autostart_failed"), err)
		}
		msg := i18n.T("log.install_autostart_done")
		fmt.Println(msg)
		showInfoBox("NetWatch CookieGuard", msg)
		return
	}
	if *uninstallAuto {
		if err := uninstallAutostart(); err != nil {
			fatalWithBox(i18n.T("log.uninstall_autostart_failed"), err)
		}
		msg := i18n.T("log.uninstall_autostart_done")
		fmt.Println(msg)
		showInfoBox("NetWatch CookieGuard", msg)
		return
	}

	// Silent gate: a second launch (another double-click, a second
	// scheduled-task trigger, whatever) just brings the existing window
	// forward and exits — no popup, no re-doing the ETW/store startup work
	// a second time. See acquireSingleInstance's doc comment for why this
	// has to happen before the fallible work below, not only inside
	// Wails' own (later) single-instance handling.
	if acquireSingleInstance() {
		focusExistingWindow()
		return
	}

	// See privilege_windows.go: without this, even an elevated process
	// gets Access Denied opening a handle to Chrome/Edge's sandboxed
	// subprocesses, which then show up as an unidentifiable process
	// touching the browser's own cookie file — a false alarm this fixes
	// at the source.
	enableDebugPrivilege()

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		fatalWithBox(i18n.T("log.mkdir_data_dir_failed"), *dataDir, err)
	}

	// The release build runs with the windowsgui subsystem (no console
	// window), so stderr goes nowhere the user can see — mirror all
	// logging into a file too, otherwise a startup failure would just look
	// like the tool silently never opened.
	// Plain-text status log, not the JSONL event logs — much lower volume
	// (a line per alert/startup, not per raw event) so a smaller rotation
	// threshold than store.LogMaxBytes is plenty.
	if logFile, err := store.NewRotatingFile(filepath.Join(*dataDir, "netwatch.log"), 5<<20, 3); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, logFile))
		// (not deferring logFile.Close(): see the note below about why
		// defers don't run on this process's exit paths — the OS reclaims
		// the handle fine either way.)
	}

	// Note: this process only ever leaves main() via os.Exit — either a
	// startup fatalWithBox, or the tray quit handler below, which does its
	// own explicit cleanup before exiting. Neither path returns normally, so
	// `defer`s placed here would never actually run; cleanup is done
	// explicitly instead of relying on them.
	st, err := store.New(*dataDir)
	if err != nil {
		fatalWithBox(i18n.T("log.init_store_failed"), err)
	}

	selfPID := uint32(os.Getpid())

	procs := procinfo.New(func(p model.ProcessInfo) { st.UpdateProc(p) })

	engine := correlate.New(procs, correlate.Handlers{
		OnFile: st.AddFile,
		OnNet:  st.AddNet,
		OnDNS:  st.AddDNS,
		OnAlert: func(a model.Alert) {
			st.AddAlert(a)
			log.Printf("[ALERT %s] %s — %s (PID %d %s)", a.Severity, a.Title, a.Detail, a.PID, a.ProcName)
		},
	})

	// buildCollector/buildChecker capture everything needed to construct a
	// fresh ETW collector / cert-checker — used for the very first start
	// right below, and again by monitorController.Start on every
	// subsequent restart the dashboard's "Start Monitoring" button
	// triggers (see monitor.go's doc comment for why *fresh* instances
	// rather than reusing stopped ones).
	buildCollector := func() (*etwmon.Collector, error) {
		return etwmon.New(etwmon.Handlers{
			OnProcessStart: func(p model.ProcessInfo) {
				procs.Observe(p)
				st.UpdateProc(p)
			},
			OnProcessStop: func(pid uint32, t time.Time) {
				procs.MarkExited(pid, t)
			},
			OnFile: engine.HandleFile,
			OnNet:  engine.HandleNet,
			OnDNS:  engine.HandleDNS,
		}, selfPID, *debugETW)
	}
	// certChecker is the one thing in this tool that initiates its own
	// outbound connections (a handful of HTTPS probes every few minutes)
	// rather than only passively observing everyone else's via ETW — see
	// internal/certcheck's package doc for why. selfPID exclusion in
	// etwmon.New above already keeps this process's own traffic out of the
	// normal file/net event stream, so these probes never show up
	// mislabeled as "a process phoning home".
	buildChecker := func() *certcheck.Checker {
		if *disableCertCheck {
			return nil
		}
		return certcheck.New(certcheck.Handlers{
			OnCheck: st.AddCertCheck,
			OnAlert: func(a model.Alert) {
				st.AddAlert(a)
				log.Printf("[ALERT %s] %s — %s", a.Severity, a.Title, a.Detail)
			},
		}, filepath.Join(*dataDir, "certcheck_baseline.json"))
	}

	// The very first start keeps its own fatal-on-failure handling here
	// rather than going through monitorController.Start: a failure at boot
	// means this whole app can't do its one job and should say so loudly;
	// a failure restarting later from the dashboard (mon.Start, via
	// App.StartMonitoring) should just report an error back to the
	// dashboard instead of taking the whole process down with it.
	collector, err := buildCollector()
	if err != nil {
		fatalWithBox(i18n.T("log.init_etw_failed"), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := collector.Start(ctx); err != nil {
		if *skipElevate {
			// -skip-elevate is a UI-debugging escape hatch: keep the
			// dashboard usable even though no events will ever arrive,
			// instead of refusing to start.
			log.Printf(i18n.T("log.etw_start_skipped"), err)
		} else {
			fatalWithBox(i18n.T("log.etw_start_failed"), err)
		}
	}
	certChecker := buildChecker()
	if certChecker != nil {
		_ = certChecker.Start(ctx) // always succeeds — see Start's doc comment
	}

	mon := newMonitorController(buildCollector, buildChecker)
	mon.adopt(collector, certChecker, cancel)

	assets, err := web.Assets()
	if err != nil {
		fatalWithBox(i18n.T("log.load_assets_failed"), err)
	}

	app := NewApp(st, *dataDir)
	app.SetMonitor(mon)

	// doQuit is the one shutdown path for the whole *process* — reached
	// from the tray's "Exit Program" menu item, or the dashboard's own
	// Settings-modal "Exit Program" button (App.Quit, in app_settings.go,
	// just calls whatever was handed to app.SetQuitFunc below). Contrast
	// with the dashboard's separate "Stop Monitoring" (App.StopMonitoring
	// -> mon.Stop()), which pauses collection without touching any of
	// this — doQuit is for when the user wants the app itself gone, not
	// just paused. Keeping this as a single named closure rather than
	// duplicating the sequence in both call sites means there's exactly
	// one place that can drift out of correct shutdown order.
	doQuit := func() {
		log.Println(i18n.T("log.stopping_monitor"))
		// Make the window/tray disappear immediately, before the slower
		// cleanup below — mon.Stop() (specifically the ETW collector
		// teardown inside it) can take a second or more: Windows only
		// signals a real-time ETW session's ProcessTrace call to actually
		// return on its own buffer-flush cadence, which is an OS-level
		// characteristic nothing in this codebase controls, not a bug to
		// fix in the collector itself. Without this reordering, quitting
		// looked hung for a couple of seconds even though it wasn't — the
		// process was already on its way out, just not visibly.
		if ctx, ok := app.Context(); ok {
			wailsRuntime.WindowHide(ctx)
		}
		tray.Quit()
		mon.Stop()
		st.Close()
		if ctx, ok := app.Context(); ok {
			wailsRuntime.Quit(ctx)
		}
		os.Exit(0)
	}
	app.SetQuitFunc(doQuit)

	log.Print(i18n.T("log.starting_window"))
	log.Printf(i18n.T("log.data_dir"), *dataDir)
	if *debugETW != "" {
		log.Printf(i18n.T("log.debug_etw_mode"), *debugETW)
	}

	go func() {
		tray.Run(
			func() {
				if ctx, ok := app.Context(); ok {
					wailsRuntime.WindowShow(ctx)
					wailsRuntime.WindowUnminimise(ctx)
				}
			},
			doQuit,
		)
	}()

	// Poll the store's unacknowledged critical/high count to drive the tray
	// icon color; simple and avoids threading another callback through the
	// whole pipeline for a purely cosmetic signal. Also re-checks the
	// active language every tick (not just the alert count) so a language
	// switch made from the dashboard while an alert is already active still
	// gets picked up here within one poll interval, not only on the next
	// state transition.
	go func() {
		last := false
		lastLang := i18n.Current()
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			count := st.UnacknowledgedCriticalCount()
			active := count > 0
			lang := i18n.Current()
			if active != last || lang != lastLang {
				tooltip := i18n.T("tray.tooltip_normal")
				if active {
					tooltip = i18n.T("tray.tooltip_alert", count)
				}
				tray.SetAlert(active, tooltip)
				last = active
				lastLang = lang
			}
		}
	}()

	err = wails.Run(&options.App{
		Title:             "NetWatch CookieGuard",
		Width:             1320,
		Height:            860,
		MinWidth:          960,
		MinHeight:         600,
		StartHidden:       *startHidden,
		HideWindowOnClose: true, // closing the window (X) just hides it; monitoring keeps running in the tray
		BackgroundColour:  options.NewRGB(249, 249, 247),
		AssetServer:       &assetserver.Options{Assets: assets},
		OnStartup: func(ctx context.Context) {
			app.startup(ctx)
			go forwardStoreEvents(ctx, st)
		},
		Bind: []any{app},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: singleInstanceID,
			OnSecondInstanceLaunch: func(_ options.SecondInstanceData) {
				if ctx, ok := app.Context(); ok {
					wailsRuntime.WindowShow(ctx)
					wailsRuntime.WindowUnminimise(ctx)
				}
			},
		},
	})
	if err != nil {
		fatalWithBox(i18n.T("log.window_start_failed"), err)
	}
}

// forwardStoreEvents relays every event the store publishes into the
// frontend via Wails' event bridge (window.runtime.EventsOn on the JS
// side), replacing the WebSocket broadcast the old HTTP-based dashboard
// used. Store itself stays framework-agnostic — it doesn't know Wails
// exists — this is just a subscriber like any other.
func forwardStoreEvents(ctx context.Context, st *store.Store) {
	ch := st.Subscribe()
	defer st.Unsubscribe(ch)
	for env := range ch {
		wailsRuntime.EventsEmit(ctx, env.Type, env.Data)
	}
}

func defaultDataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserHomeDir()
	}
	return filepath.Join(base, "NetWatchCookieGuard", "data")
}

// logFileBaseNames lists every file store.New / this file's netwatch.log
// setup can create in the data directory — kept in one place so
// cleanLogFiles doesn't silently miss one if a new log type is added later.
var logFileBaseNames = []string{
	"netwatch.log",
	"connections.jsonl",
	"dns.jsonl",
	"file_access.jsonl",
	"alerts.jsonl",
	"certchecks.jsonl",
}

// cleanLogFiles removes every log file and rotated backup (base,
// base.1 .. base.N) in dataDir, returning how many bytes were freed. It's
// deliberately a plain delete rather than a truncate: these files are only
// ever opened in append mode, so removing them and letting the next
// New()/NewRotatingFile() call recreate them from scratch is simpler and
// avoids leaving a process's open append handle pointing at a truncated
// file with a stale offset.
//
// If the monitor is currently running, the active files are locked
// (Windows won't let another process delete/rename a file that process has
// open without FILE_SHARE_DELETE, which this tool doesn't request) and
// os.Remove fails — that failure is surfaced to the caller rather than
// silently skipped, so the user gets a clear "close it first" message
// instead of a cleanup that quietly did nothing.
func cleanLogFiles(dataDir string) (freedBytes int64, err error) {
	var firstErr error
	for _, base := range logFileBaseNames {
		// "" is the active file itself; .1.. cover rotated-out backups.
		// One extra slot beyond store.LogMaxBackups is swept too, in case
		// a smaller backup count is configured later than what created
		// these files.
		suffixes := []string{""}
		for i := 1; i <= store.LogMaxBackups+1; i++ {
			suffixes = append(suffixes, fmt.Sprintf(".%d", i))
		}
		for _, suffix := range suffixes {
			p := filepath.Join(dataDir, base+suffix)
			info, statErr := os.Stat(p)
			if statErr != nil {
				continue // doesn't exist, nothing to do
			}
			if rmErr := os.Remove(p); rmErr != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s: %w", p, rmErr)
				}
				continue
			}
			freedBytes += info.Size()
		}
	}
	return freedBytes, firstErr
}

// fatalWithBox reports a startup failure and exits. The release build has
// no console (windowsgui subsystem), so log output alone would make a
// startup failure look exactly like nothing happened when double-clicked —
// this also pops a message box so the user always sees why it didn't
// start, not just silence.
func fatalWithBox(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	showErrorBox(i18n.T("log.startup_failed_title"), msg)
	os.Exit(1)
}
