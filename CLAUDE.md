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
  syscalls, WebView2 via Wails' pure-Go `go-webview2` binding, tray via `getlantern/systray`).
- Windows/amd64 only — most non-`cmd`/`config`/`model`/`store` source files carry `//go:build
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
- [internal/web/assets_test.go](internal/web/assets_test.go) — embedded dashboard assets present.

## Architecture: the event pipeline

Everything flows one direction, wired together in [cmd/netwatch/main.go](cmd/netwatch/main.go):

```
internal/etwmon (ETW kernel events)
    → internal/procinfo (PID → name/path/signature/hash cache)
    → internal/correlate (scoring + alert synthesis)
    → internal/store (ring buffers + JSONL + pub/sub)
    → Wails event bridge → internal/web dashboard (WebView2)
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
- **`internal/store`** ([store.go](internal/store/store.go)) holds bounded in-memory ring buffers
  per event type (5000 events, 2000 alerts) for fast dashboard reloads, appends everything to
  rotating JSONL files on disk (`internal/store/rotate.go`, 20MB × 3 backups per file, shared with
  `netwatch.log`) so history survives restarts/ring wraparound, and runs a plain channel-based
  pub/sub hub. Store has no knowledge of Wails; `cmd/netwatch/main.go`'s `forwardStoreEvents`
  relays its `Envelope`s into `wailsRuntime.EventsEmit`.
- **`cmd/netwatch`**: `main.go` wires the whole pipeline and owns the Wails `options.App` config;
  `app.go` is the Wails-bound object (`App.GetSnapshot`, `App.AckAlert` — exported methods become
  `window.go.main.App.<Method>()` promises on the JS side); `elevate_windows.go` /
  `privilege_windows.go` handle UAC self-relaunch and enabling `SeDebugPrivilege` (needed to open
  handles to browser sandboxed subprocesses — without it they show up as unidentifiable processes
  touching the browser's own cookie file, a false positive this fixes at the source);
  `autostart_windows.go` manages the scheduled-task-based autostart.
- **`internal/web`**: static HTML/CSS/JS embedded via `go:embed` ([embed.go](internal/web/embed.go)),
  served to WebView2 through Wails' `assetserver` — zero external deps/CDN by design.
- **`internal/tray`**: systray icon (blue = normal, red = unacknowledged critical/high alert);
  color driven by a 2s poller in `main.go` reading `Store.UnacknowledgedCriticalCount()`.

Single-instance behavior is enforced twice: an OS-level check
(`acquireSingleInstance`/`focusExistingWindow` in `cmd/netwatch`) before any fallible startup work
runs, and Wails' own `SingleInstanceLock` as a second layer once the window exists.

## Shared data model

[internal/model/types.go](internal/model/types.go) defines every struct that crosses package
boundaries (`ProcessInfo`, `SensitiveFileEvent`, `NetEvent`, `DNSEvent`, `Alert`,
`Severity`/`FileAccessKind` enums) — check here first when tracing a field through the pipeline,
since these are what `etwmon` produces, `correlate`/`store` consume, and the JSON the frontend and
JSONL logs both serialize.
