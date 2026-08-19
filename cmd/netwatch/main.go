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

	"netwatch/internal/correlate"
	"netwatch/internal/etwmon"
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
	dataDir := flag.String("data-dir", defaultDataDir(), "日志/数据保存目录")
	debugETW := flag.String("debug-etw", "", "可选:把所有原始 ETW 事件的 JSON 写入此文件,用于排查字段映射问题")
	skipElevate := flag.Bool("skip-elevate", false, "跳过管理员自提权(仅用于调试界面本身;跳过后将看不到任何文件/网络事件)")
	startHidden := flag.Bool("start-hidden", false, "启动时不显示窗口,只驻留在系统托盘(用于开机自启动场景,避免每次登录都弹窗)")
	installAuto := flag.Bool("install-autostart", false, "注册开机/登录自启动计划任务,然后退出(不会立刻开始监控)")
	uninstallAuto := flag.Bool("uninstall-autostart", false, "移除开机自启动计划任务,然后退出")
	cleanLogs := flag.Bool("clean-logs", false, "清空历史日志文件(含所有 .jsonl 和已轮转的备份),释放磁盘空间,然后退出。若监控正在运行,请先在托盘图标里「退出监控」再执行")
	// Accepted for backward compatibility with scheduled tasks registered by
	// older builds (pre-native-window); no longer meaningful, silently ignored.
	flag.Bool("no-browser", false, "(已废弃,不再生效)")
	flag.Int("port", 0, "(已废弃,不再生效——现在是原生窗口,不再监听端口)")
	flag.Parse()

	// Doesn't touch anything that needs Administrator rights (it's just
	// deleting the user's own files under %LOCALAPPDATA%), so this is
	// handled before the elevation gate below — no reason to make the user
	// click through a UAC prompt just to free up disk space.
	if *cleanLogs {
		freed, err := cleanLogFiles(*dataDir)
		if err != nil {
			fatalWithBox("清理日志失败: %v\n(如果监控正在运行,请先在托盘图标里点「退出监控」,再重新执行清理)", err)
		}
		msg := fmt.Sprintf("已清空日志历史,释放约 %.1f MB 磁盘空间。", float64(freed)/(1<<20))
		fmt.Println(msg)
		showInfoBox("NetWatch CookieGuard", msg)
		return
	}

	if !*skipElevate && !isElevated() {
		log.Println("当前不是管理员权限,正在请求 UAC 提权重启…")
		if err := relaunchElevated(); err != nil {
			fatalWithBox("提权失败: %v\n请手动以管理员身份运行本程序,或者你在 UAC 弹窗里点了「否」。", err)
		}
		return
	}

	if *installAuto {
		exe, err := os.Executable()
		if err != nil {
			fatalWithBox("获取自身路径失败: %v", err)
		}
		if err := installAutostart(exe); err != nil {
			fatalWithBox("注册自启动失败: %v", err)
		}
		msg := "已注册开机自启动(登录时以管理员权限自动运行,不再弹 UAC;窗口默认隐藏,只在系统托盘)。可随时用 -uninstall-autostart 移除。"
		fmt.Println(msg)
		showInfoBox("NetWatch CookieGuard", msg)
		return
	}
	if *uninstallAuto {
		if err := uninstallAutostart(); err != nil {
			fatalWithBox("移除自启动失败: %v", err)
		}
		msg := "已移除开机自启动计划任务。"
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
		fatalWithBox("无法创建数据目录 %s: %v", *dataDir, err)
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
	// startup fatalWithBox, or the tray "退出监控" handler below, which does
	// its own explicit cleanup before exiting. Neither path returns
	// normally, so `defer`s placed here would never actually run; cleanup
	// is done explicitly instead of relying on them.
	st, err := store.New(*dataDir)
	if err != nil {
		fatalWithBox("初始化存储失败: %v", err)
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

	collector, err := etwmon.New(etwmon.Handlers{
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
	if err != nil {
		fatalWithBox("初始化 ETW 采集器失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := collector.Start(ctx); err != nil {
		if *skipElevate {
			// -skip-elevate is a UI-debugging escape hatch: keep the
			// dashboard usable even though no events will ever arrive,
			// instead of refusing to start.
			log.Printf("警告: ETW 采集未启动 (%v) — 因为传入了 -skip-elevate,窗口仍会打开但不会有任何事件。", err)
		} else {
			fatalWithBox("启动 ETW 采集失败: %v\n(需要以管理员身份运行;如果你确实是管理员还看到这个,请把 -debug-etw 的输出发给我排查)", err)
		}
	}

	assets, err := web.Assets()
	if err != nil {
		fatalWithBox("加载界面资源失败: %v", err)
	}

	app := NewApp(st)

	log.Printf("NetWatch CookieGuard 正在启动原生窗口界面…")
	log.Printf("数据目录: %s", *dataDir)
	if *debugETW != "" {
		log.Printf("调试模式:原始 ETW 事件将写入 %s", *debugETW)
	}

	go func() {
		tray.Run(
			func() {
				if ctx, ok := app.Context(); ok {
					wailsRuntime.WindowShow(ctx)
					wailsRuntime.WindowUnminimise(ctx)
				}
			},
			func() {
				log.Println("正在停止监控…")
				cancel()
				collector.Stop()
				st.Close()
				if ctx, ok := app.Context(); ok {
					wailsRuntime.Quit(ctx)
				}
				tray.Quit()
				os.Exit(0)
			},
		)
	}()

	// Poll the store's unacknowledged critical/high count to drive the
	// tray icon color; simple and avoids threading another callback
	// through the whole pipeline for a purely cosmetic signal.
	go func() {
		last := false
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			count := st.UnacknowledgedCriticalCount()
			active := count > 0
			if active != last {
				tooltip := "NetWatch CookieGuard - 正常监控中"
				if active {
					tooltip = fmt.Sprintf("NetWatch CookieGuard - ⚠ %d 条高危/严重告警待处理", count)
				}
				tray.SetAlert(active, tooltip)
				last = active
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
		fatalWithBox("启动窗口失败: %v\n(WebView2 运行时可能缺失,下载: https://developer.microsoft.com/microsoft-edge/webview2/)", err)
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
	showErrorBox("NetWatch CookieGuard - 启动失败", msg)
	os.Exit(1)
}
