# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

NetWatch CookieGuard — a Windows-only Go background monitor that watches, per-process, which
process touches browser/app cookie and password stores (Chrome/Edge/Brave/Vivaldi/Opera/Firefox
cookies & saved passwords, Discord/Steam/EA/Slack/Teams session tokens) and correlates that with
outbound network connections from the same process shortly after, to catch infostealer-style
credential theft. Detection is via Windows ETW kernel providers (no packet capture, no Npcap, no
cgo). The UI is a native window rendered via Wails v2 + WebView2 (HTML/CSS/JS embedded in the exe,
not a browser tab, no HTTP server/port). See [README.md](README.md) (Chinese) for the full
detection rationale and threat model this was built against.

## Build, test, run

```powershell
.\build.ps1
```

This runs `go vet ./...` → `go test ./...` → builds both exes into `build\`. Do this rather than a
bare `go build` — see the build-tag gotcha below.

Manual equivalents:

```powershell
# release: no console window, stripped
go build -tags production -ldflags "-H=windowsgui -s -w" -o build\netwatch.exe .\cmd\netwatch

# debug: console + verbose logging (use this while developing)
go build -tags "production debug" -o build\netwatch-debug.exe .\cmd\netwatch

go test ./...                          # full suite
go test ./internal/correlate/...       # single package
go test ./internal/correlate/ -run TestName -v
go vet ./...
```

- **`-tags production` is mandatory**, not an optimization. Wails' own Windows fallback path (no
  build tags) compiles fine but pops a "Wails applications will not build without the correct
  build tags" error box at runtime instead of the real app. `debug` is additive on top of it (just
  raises Wails' log verbosity) — never a substitute for `production`.
- `CGO_ENABLED=0` throughout; nothing here needs a C compiler (ETW via `golang.org/x/sys/windows`
  syscalls, WebView2 via Wails' pure-Go `go-webview2` binding, tray via `energye/systray`).
- Windows/amd64 only — most non-`cmd`/`config`/`model`/`store`/`i18n` source files carry `//go:build
  windows` deliberately; don't try to make this cross-platform.
- Running the actual monitor requires Administrator (UAC self-elevation happens in `main()`); ETW
  session creation fails without it. Most local dev/test iteration doesn't need elevation — only
  `internal/etwmon` and the actual collector `Start()` do.
- **Dependency upgrades**: never `go get -u` (or pin) `github.com/wailsapp/go-webview2` on its
  own — its version must match what `wails/v2`'s own `go.mod` expects (currently `v1.0.19`); a
  mismatch breaks a callback signature in Wails' internals. Upgrade `wails/v2` itself and let it
  pull its matching `go-webview2`.
- Tray icons (`internal/tray/assets/*.ico`) are checked-in pre-generated artifacts, not built by
  `build.ps1`. Regenerate via `go run tools\genicon\main.go` only if you change the RGBA values in
  [tools/genicon/main.go](tools/genicon/main.go).
- The exe's own icon (Explorer/taskbar/Alt-Tab/window titlebar, as opposed to the tray icon above)
  comes from [cmd/netwatch/rsrc_windows_amd64.syso](cmd/netwatch/rsrc_windows_amd64.syso), a
  checked-in Windows resource object that plain `go build` links in automatically — no
  `build.ps1` changes needed, no new go.mod dependency. Its source is
  [assets/appicon/icon.ico](assets/appicon/icon.ico) (a multi-size 16–256px rendering of the same
  shield mark used for the "shield" icon in the web dashboard's SVG sprite —
  [tools/genappicon/main.go](tools/genappicon/main.go) reproduces that exact path) plus
  [assets/appicon/winres.json](assets/appicon/winres.json), which controls how `go-winres`
  packs it. Only regenerate if you change the mark itself:
  ```powershell
  go run tools\genappicon\main.go
  go install github.com/tc-hib/go-winres@latest
  go-winres make --in assets\appicon\winres.json --arch amd64 --out cmd\netwatch\rsrc
  ```
  Two non-obvious things `winres.json` encodes, both required — don't "simplify" this back to
  `go-winres simply`:
  - **The icon must be resource ID 3, not 1.** Wails' own window/taskbar icon loader
    (`winc.NewIconFromResource(instance, winc.AppIconID)`, `AppIconID = 3`, internal to
    `wailsapp/wails/v2` so it can't be overridden from `cmd/netwatch`) looks up the icon by that
    exact numeric ID; `go-winres simply` puts it at ID 1 instead, which Wails silently fails to
    find and falls back to a generic default icon — the window/taskbar icon looks unset even
    though the exe file's own icon (Explorer, e.g.) is fine. `winres.json`'s
    `"RT_GROUP_ICON": {"#3": ...}` pins it to the ID Wails actually looks for.
  - **The manifest must stay `asInvoker`** (`"execution-level": ""`) — the app does its own
    on-demand UAC elevation (see `elevate_windows.go`'s `relaunchElevated`). A
    `requireAdministrator` manifest would force a UAC prompt on every launch, including
    flag-only invocations like `-clean-logs` that don't need it.

### What the test suite actually covers

ETW and WebView2 rendering can't be exercised without an elevated, real Windows run, so the tests
instead cover everything around them:
- [internal/correlate/engine_test.go](internal/correlate/engine_test.go) — the core scoring logic:
  file-then-network → critical alert, a browser reading its own cookies → no alert (including the
  "Chrome sandboxed child inherits parent identity" case), unresolved identity degrades gracefully
  rather than over- or under-claiming, AI-service domain hits escalate severity, regular-interval
  beaconing, known browsers/fast polling don't trigger.
- [internal/store/rotate_test.go](internal/store/rotate_test.go) — file rotation crossing the size
  threshold, backup count capping, byte-count continuity across restarts, JSONL validity.
- [internal/store/store_test.go](internal/store/store_test.go) — pub/sub, slow subscribers don't
  block publishers.
- [internal/procinfo/procinfo_test.go](internal/procinfo/procinfo_test.go) — OS-query fallback path
  using the test process's own real PID.
- [internal/web/assets_test.go](internal/web/assets_test.go) — embedded dashboard assets present
  (`index.html`, `app.js`, `i18n.js`, `style.css`).
- [internal/certcheck/certcheck_test.go](internal/certcheck/certcheck_test.go) — the pure
  decision logic (`toAlert` severity tiers, baseline drift tracking) with synthetic
  `model.CertCheckEvent`s; the actual TLS dial/verify (`probe`) needs real network access so isn't
  covered here — it was validated manually against real domains during development instead.
- [internal/i18n/i18n_test.go](internal/i18n/i18n_test.go) — every catalog key has all three
  languages, and multi-argument templates' `%[n]` indices match across languages (catches a
  translation that silently drops or duplicates a placeholder); also statically rejects any
  `%[n]` combined with a flag/width/precision before the verb (`%[4].0f` and the like) — Go's fmt
  package doesn't error on that combination anywhere at build/vet/test time, it just renders
  garbage (`%!f(BADINDEX)`) into the string at runtime, which is exactly what shipped in
  `alert.beacon.detail` before this test existed (see that catalog entry's comment, and
  `correlate.trackBeacon`'s call site, which does the rounding in Go and passes a plain string
  instead). Plus `T`/`ParseLang`/`SetSession` behavior. The dashboard-side catalog
  ([internal/web/static/i18n.js](internal/web/static/i18n.js))
  has no Go test coverage since it's plain JS — it was cross-checked ad hoc for the same
  invariants (key parity across languages, every `data-i18n`/`i18n.T()` reference resolving to a
  real key) during development instead.

## Architecture: the event pipeline

Everything flows one direction, wired together in [cmd/netwatch/main.go](cmd/netwatch/main.go):

```
internal/etwmon (ETW kernel events)
    → internal/procinfo (PID → name/path/signature/hash cache)
    → internal/correlate (scoring + alert synthesis)          ─┐
                                                                 ├→ internal/store (ring buffers + JSONL + pub/sub)
internal/certcheck (periodic active TLS probes) ────────────────┘      → Wails event bridge → internal/web dashboard (WebView2)
```

- **`internal/etwmon`** ([collector.go](internal/etwmon/collector.go)) opens one real-time ETW
  session against four kernel providers by hardcoded GUID (Kernel-Process, Kernel-File,
  Kernel-Network, DNS-Client) via `github.com/0xrawsec/golang-etw`. Field names for each event were
  reverse-engineered from public docs and can drift across Windows builds — every extraction goes
  through a `prop` helper that tries known aliases and falls back to a raw dump. `-debug-etw
  <file>` dumps raw JSON of every event for fixing field mappings against real samples.
- **`internal/procinfo`** ([procinfo.go](internal/procinfo/procinfo.go)) caches per-PID identity.
  `Observe()` runs synchronously on the ETW dispatch goroutine and does only cheap fallback (parent
  PID inheritance — a child of an already-identified process, e.g. a Chrome sandbox helper, is
  presumed the same app); the expensive path (`OpenProcess` + Toolhelp32 snapshot walk, Authenticode
  signature check, SHA-256) runs on a background worker pool and updates the cache asynchronously.
  `ProcessInfo.IdentityUnknown()` is the explicit "we don't know" state — callers must never treat
  it as "so it must be a stranger" or "so it must be fine."
- **`internal/correlate`** ([engine.go](internal/correlate/engine.go)) is the detection core, all
  scoring-based (`scoreToSeverity`: ≥80 critical, ≥55 high, ≥30 medium, else low) rather than
  binary rules:
  - **Headline rule**: a non-owner process touches a `Critical` sensitive target (cookie/password
    store), then the *same PID* opens an outbound connection within `CorrelationWindowSeconds`
    (15s) → critical "read credentials then phoned home" alert (`file_then_network_exfil`).
  - Beacon detection (`trackBeacon`): same (PID, remote addr) reconnecting on a regular interval
    (≥5 samples, jitter <15%, mean interval ≥8s to skip legitimate fast polling) → alert.
  - DNS correlation: `HandleDNS` populates an IP→domain cache consumed by `HandleNet` to annotate
    connections and flag raw-IP connects with no matching resolution (possible hardcoded C2).
  - Alerts to AI-service domains (`config.WatchedAIServiceDomains`) get a score bump — this
    project's threat model specifically prioritizes Claude/ChatGPT/Gemini session theft.
  - Internal maps (`recentTouch`, `dnsByIP`, `connHistory`) are periodically swept
    (`maybeSweepLocked`, every 200 net events) since a long-running monitor would otherwise
    accumulate unbounded per-key history for entries that simply stop being visited.
- **`internal/config`** ([config.go](internal/config/config.go)) is the tunable knowledge base:
  `SensitiveTargets()` (watched file patterns + owning process + critical/non-critical), owner
  allowlists, suspicious-path fragments, AI-service domains, and every threshold used by
  `correlate` (`CorrelationWindowSeconds`, beacon params, DNS cache window). **Change detection
  scope/sensitivity here, not in engine.go.** Patterns are deliberately drive-letter-agnostic
  (`\users\...` not `C:\Users\...`) because ETW sometimes reports NT device paths.
- **`internal/certcheck`** ([certcheck.go](internal/certcheck/certcheck.go)) is the one part of
  this tool that initiates its own outbound connections rather than passively observing everyone
  else's via ETW — a periodic ticker (`config.CertCheckIntervalSeconds`, default 10min) TLS-dials
  a handful of domains (`config.CertCheckTargets()`) and verifies the presented certificate chain
  against **two independent pools**: the OS trust store, and a bundled, fixed snapshot of the
  public Mozilla/curl CA list ([assets/cacert.pem](internal/certcheck/assets/cacert.pem)). This
  exists because a MITM proxy that has gotten its root CA silently trusted by the OS is a total
  blind spot for everything else in this pipeline — the browser shows no warning, no process
  reads a credential file it shouldn't, nothing "beacons". OS-trusted-but-not-in-the-public-list is
  the actual signal. Issuer strings are also matched against `config.KnownInterceptionVendors`
  (Zscaler/Netskope/Palo Alto/... → high severity, names the product) and
  `config.KnownConsumerAVRoots` (Kaspersky/Avast/... → informational, not the same threat as a
  network-level interceptor) separately, plus a per-domain baseline
  (`certcheck_baseline.json` in the data dir) flags drift even against vendors neither list knows
  about — but only a chain that itself verified against the public-CA pool is ever allowed to
  become the new baseline, so an active MITM can't "bless itself" as the new normal. Alerts flow
  through the same `model.Alert`/`Store.AddAlert` pipeline as `correlate`'s (see the Seq note on
  `Store.AddAlert` below), carrying no PID — this finding isn't process-scoped, and the frontend
  skips the process chip when `pid` is absent for exactly that reason. Turn it off with
  `-disable-cert-check`. `assets/cacert.pem` is a frozen snapshot (not re-fetched at runtime, so a
  compromised network can't hand it a fake update) — refresh it occasionally via
  `curl -sS https://curl.se/ca/cacert.pem -o internal/certcheck/assets/cacert.pem`.
- **`internal/store`** ([store.go](internal/store/store.go)) holds bounded in-memory ring buffers
  per event type (5000 events, 2000 alerts, 1000 cert checks) for fast dashboard reloads, appends
  everything to rotating JSONL files on disk (`internal/store/rotate.go`, 20MB × 3 backups per
  file, shared with `netwatch.log`) so history survives restarts/ring wraparound, and runs a plain
  channel-based pub/sub hub. Store has no knowledge of Wails; `cmd/netwatch/main.go`'s
  `forwardStoreEvents` relays its `Envelope`s into `wailsRuntime.EventsEmit`. `AddAlert` is the
  single authority for `Alert.Seq` — it overwrites whatever the caller set, from one counter
  shared across every alert producer. That's deliberate now that there are two (`correlate` and
  `certcheck`): the frontend's ack/dedup logic keys everything off `Seq` being unique across the
  *whole* alert stream, so two producers each keeping their own counter would eventually collide.
  Producers should just leave `Seq` unset and let `AddAlert` assign it.
- **`cmd/netwatch`**: `main.go` wires the whole pipeline and owns the Wails `options.App` config;
  `app.go` is the Wails-bound object (`App.GetSnapshot`, `App.AckAlert`, `App.GetLanguage`,
  `App.SetLanguage` — exported methods become `window.go.main.App.<Method>()` promises on the JS
  side); `app_settings.go` adds the dashboard's settings-modal methods
  (`App.GetDataDir`/`OpenDataDir`, `App.CleanLogs`, `App.GetAutostartEnabled`/`SetAutostart`,
  `App.GetMonitoring`/`StopMonitoring`/`StartMonitoring`) — kept in their own file since `app.go`
  is the core snapshot/alert/language surface and this is a distinct, later-added concern;
  `elevate_windows.go` /
  `privilege_windows.go` handle UAC self-relaunch and enabling `SeDebugPrivilege` (needed to open
  handles to browser sandboxed subprocesses — without it they show up as unidentifiable processes
  touching the browser's own cookie file, a false positive this fixes at the source);
  `autostart_windows.go` manages the scheduled-task-based autostart, including `autostartEnabled()`
  (queries Task Scheduler directly via `schtasks /Query` rather than tracking state of our own, so
  it's correct even if the task was touched outside the dashboard).

  There are two distinct, deliberately non-overlapping "stop" actions, both reachable from the
  dashboard's Settings modal (previously only the tray's right-click menu could stop anything at
  all, which is why both buttons exist now):
  - **Stop Monitoring** (`App.StopMonitoring`/`StartMonitoring`) pauses/resumes the ETW
    collector and cert-check prober, via [monitor.go](cmd/netwatch/monitor.go)'s
    `monitorController` — the window, tray, store, and process all stay up, so e.g. Clean Logs
    stays reachable. `Start` always *rebuilds* a fresh `etwmon.Collector`/`certcheck.Checker`
    rather than reusing the stopped ones — `certcheck.Checker.Stop` closes its own `stopCh`
    exactly once, so calling `Start` again on that same instance would find it already
    permanently closed and exit its loop immediately, silently monitoring nothing.
    `Stop`/`Start` also close/reopen the on-disk log file handles (the store's five JSONL logs
    plus `netwatch.log`, via `Store.CloseLogFiles`/`ReopenLogFiles` and
    `RotatingFile.Close`/`Reopen`) — not just the collector/checker that feed them, since those
    files are opened `O_APPEND` without `FILE_SHARE_DELETE` and Windows refuses to delete a file
    for as long as any handle to it is open, independent of whether anything is actively being
    written. The store's in-memory ring buffers/subscribers/alert history are untouched by this —
    only the on-disk file handles are cycled.

    The settings panel's **Clean Logs** button (`App.CleanLogs`, in
    [app_settings.go](cmd/netwatch/app_settings.go)) is what actually relies on this, and it does
    so itself rather than requiring the user to click Stop Monitoring first: if monitoring is
    running when Clean Logs is clicked, `CleanLogs` calls `mon.Stop()`, deletes, then `mon.Start()`
    to resume — so *one click always fully cleans* regardless of monitoring state, at the cost of
    a brief collection gap while the ETW session gets torn down and rebuilt (same gap a manual
    Stop/Start would cause; this just automates it). Before this, only exiting the whole process
    (`st.Close()` in `doQuit`) ever released those handles, which made Clean Logs silently fail on
    the active files while the app was merely running — the dashboard's copy for that case
    (`settings.clean_logs_partial` in [i18n.js](internal/web/static/i18n.js)) now describes the
    genuinely-remaining case (some *other* process, e.g. antivirus, has one of these files locked),
    not "go stop monitoring first".
  - **Exit Program** (`App.Quit`) actually ends the process. `main()` builds this shutdown
    sequence once, as a `doQuit` closure, and both the tray's "Exit Program" menu item and the
    dashboard's button call the exact same one (`App.SetQuitFunc(doQuit)`) — sharing it rather
    than giving the dashboard its own copy means there's exactly one place the shutdown order can
    be defined, not two that can drift apart. `doQuit` deliberately calls
    `wailsRuntime.WindowHide`/`tray.Quit()` *before* the slower `mon.Stop()`/`st.Close()` cleanup,
    not after — a real-time ETW session's `ProcessTrace` only returns on its own buffer-flush
    cadence (can be a second or more, an OS characteristic, not something fixable in `etwmon`),
    and without this reordering the window stuck around looking hung for that whole window
    instead of disappearing the instant "quit" was clicked.
- **`internal/i18n`** ([i18n.go](internal/i18n/i18n.go), [catalog.go](internal/i18n/catalog.go)) is
  the backend's translation layer — Chinese/English/German (`ZH`/`EN`/`DE`), one active `Lang` for
  the whole process, read by every `T(key, args...)` call. Covers everything the Go side produces
  in a human-facing string: CLI flag help (built in `main()`, so `i18n.Init()` must run before any
  `flag.String`/`flag.Bool` call), startup/log messages and message boxes, the tray menu
  (`internal/tray`'s `Relabel()`), and every `correlate`/`certcheck` alert's `Title`/`Detail`
  (`config.SensitiveTarget.AppKey`+`AppArgs` resolves a target's display name lazily via
  `config.TargetAppName` at alert time, not baked in at `SensitiveTargets()` call time, so a
  live language switch is reflected in the very next alert rather than only after a restart).
  `Init()` resolves the starting language from a persisted preference
  (`%LOCALAPPDATA%\NetWatchCookieGuard\language.json`, independent of `-data-dir` since flag
  descriptions need a language before `flag.Parse()` has even run) or else the detected Windows UI
  language (`detect_windows.go`, raw `GetUserDefaultUILanguage` via `syscall` — not wrapped by
  `x/sys/windows`); `Set()` changes it and persists, `SetSession()` changes it for this run only
  (used by the `-lang` override flag). **Deliberately does not support retroactively
  re-translating already-generated text**: an alert's `Title`/`Detail` (and each `netwatch.log`
  line) is plain text rendered once, in whatever language was active at that moment — matching how
  every other piece of this tool's history already behaves (an append-only audit trail, not a
  live view) — so switching languages only changes what gets generated *from that point on*.
  Multi-argument catalog templates use explicit argument indices (`%[1]s`, `%[2]d`...) rather than
  positional order, since a natural translation often reorders words relative to the source
  Chinese. The dashboard's own static/dynamic DOM text is a *separate*, parallel catalog —
  [internal/web/static/i18n.js](internal/web/static/i18n.js) — deliberately not derived from this
  Go one: it covers different content (UI chrome: labels, table headers, chip text) and translates
  instantly client-side with zero round-trip, rather than waiting on a Wails call. `App.SetLanguage`
  is what keeps the two in sync going forward (see `internal/web/static/app.js`'s "language
  switching" section for the full flow).
- **`internal/web`**: static HTML/CSS/JS embedded via `go:embed` ([embed.go](internal/web/embed.go)),
  served to WebView2 through Wails' `assetserver` — zero external deps/CDN by design.
- **`internal/tray`**: systray icon (blue = normal, red = unacknowledged critical/high alert);
  color driven by a 2s poller in `main.go` reading `Store.UnacknowledgedCriticalCount()`. Left
  click opens the dashboard directly; right click shows the menu (labels come from
  `internal/i18n`'s `tray.open`/`tray.quit` keys, not hardcoded strings) — via `energye/systray`'s
  `SetOnClick`/`SetOnRClick`, a fork of the original `getlantern/systray`
  chosen specifically because it exposes those two separately (`getlantern/systray` shows the same
  native menu on either click with no way to tell them apart). Both onOpen/onQuit are bounced onto
  their own goroutine in `tray.onReady` — menu-item clicks and `SetOnClick`/`SetOnRClick` callbacks
  run synchronously on the tray's own message-loop thread (called directly from `wndProc`), and
  neither should ever block on the real work those callbacks do (Wails window calls, stopping the
  ETW collector, closing log files...).
  `tray.Run` calls `runtime.LockOSThread()` itself before `systray.Run` — required because
  `cmd/netwatch/main.go` launches it on its own spawned goroutine (the main goroutine is Wails'),
  and systray's own `runtime.LockOSThread()` (in its package `init()`) only pins whichever
  goroutine happens to run package initialization, not a goroutine spawned later by our code.
  Without this, the Go scheduler can migrate the tray's message-loop goroutine to a different OS
  thread at any preemption point, orphaning the native window's message queue on the old thread —
  this was the cause of the tray sometimes becoming unresponsive (right-click doing nothing) that
  this now fixes. Don't remove it, and don't call `tray.Run` from anywhere except its own
  dedicated goroutine.

Single-instance behavior is enforced twice: an OS-level check
(`acquireSingleInstance`/`focusExistingWindow` in `cmd/netwatch`) before any fallible startup work
runs, and Wails' own `SingleInstanceLock` as a second layer once the window exists.

## Shared data model

[internal/model/types.go](internal/model/types.go) defines every struct that crosses package
boundaries (`ProcessInfo`, `SensitiveFileEvent`, `NetEvent`, `DNSEvent`, `Alert`,
`Severity`/`FileAccessKind` enums) — check here first when tracing a field through the pipeline,
since these are what `etwmon` produces, `correlate`/`store` consume, and the JSON the frontend and
JSONL logs both serialize.
