// Package i18n is the single translation layer for every user-facing string
// this tool produces outside the web dashboard's own static UI chrome
// (which ships its own mirrored JS catalog, see internal/web/static/i18n.js,
// for zero-latency language switching without a Go round-trip): CLI flag
// help, startup/log messages and message boxes, the system-tray menu, and
// every alert/certcheck finding's Title/Detail.
//
// There is exactly one active language for the whole process at a time
// (current), read by every T() call. It starts out as whatever Init()
// resolves (persisted preference, else the Windows UI language, else
// English) and can change at runtime via Set() — called from the
// dashboard's language switcher through App.SetLanguage in cmd/netwatch.
// Changing it only affects text generated *after* the change: alerts
// already raised, and lines already written to netwatch.log or the JSONL
// history, keep whatever language they were generated in. That matches how
// every other piece of history in this tool already behaves (an
// append-only audit trail, not a live-translated view) and avoids having to
// thread every backend format string through the frontend as a key+args
// pair just to support retroactive re-translation of old entries.
package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// Lang is one of the three languages this tool ships translations for.
type Lang string

const (
	ZH Lang = "zh" // Simplified Chinese — this project's original/primary language
	EN Lang = "en"
	DE Lang = "de"
)

// current holds the active Lang, read by every T() call. Stored as an
// atomic.Value (rather than a plain var behind a mutex) since it's read far
// more often — every single formatted string, backend-wide — than it's
// written (only on an explicit language switch).
var current atomic.Value

func init() {
	// A safe, deterministic default for the brief window before Init() runs
	// (or in any test that never calls it). Init() itself always overwrites
	// this before main() does any real work.
	current.Store(EN)
}

// Init resolves the language to start this process in — a previously
// persisted preference if one exists, otherwise the Windows UI language —
// and must be called once, first thing in main(), before anything (flag
// descriptions included) calls T(). It deliberately doesn't depend on any
// command-line flag: flag *descriptions* themselves need to already be in
// the right language by the time flag.String/flag.Bool build them.
func Init() {
	if l, ok := loadPersisted(); ok {
		current.Store(l)
		return
	}
	current.Store(DetectSystemLang())
}

// Current returns the active language.
func Current() Lang {
	return current.Load().(Lang)
}

// SetSession changes the active language for the remainder of this process
// only — it does not persist, so the next launch reverts to whatever is
// saved (or system-detected). Meant for a one-off override (the -lang CLI
// flag); contrast with Set, which the dashboard's language switcher uses
// and which does persist. An unrecognized value falls back to English.
func SetSession(l Lang) {
	switch l {
	case ZH, EN, DE:
	default:
		l = EN
	}
	current.Store(l)
}

// Set changes the active language for the remainder of this process and
// persists it so the next launch starts there too — this is what the
// dashboard's language switcher calls. An unrecognized value falls back to
// English rather than silently leaving the previous language in place, so a
// caller passing bad input finds out from the return value having actually
// taken effect, not from nothing happening.
func Set(l Lang) error {
	SetSession(l)
	return savePersisted(l)
}

// ParseLang validates a user/flag-supplied language code (case-insensitive).
func ParseLang(s string) (Lang, bool) {
	switch Lang(strings.ToLower(strings.TrimSpace(s))) {
	case ZH:
		return ZH, true
	case EN:
		return EN, true
	case DE:
		return DE, true
	default:
		return "", false
	}
}

// T formats the message registered under key for the current language via
// fmt.Sprintf (so translated templates can — and often do, to allow
// reordering words across languages — use explicit argument indices like
// %[1]s rather than relying on positional order matching args). A key
// missing the current language falls back to English, then to the bare key
// itself, so a gap in the catalog degrades to *something* legible instead of
// panicking or going blank.
func T(key string, args ...any) string {
	return render(Current(), key, args...)
}

func render(l Lang, key string, args ...any) string {
	variants, ok := catalog[key]
	if !ok {
		return key
	}
	tmpl, ok := variants[l]
	if !ok {
		if tmpl, ok = variants[EN]; !ok {
			return key
		}
	}
	if len(args) == 0 {
		return tmpl
	}
	return fmt.Sprintf(tmpl, args...)
}

// ---------- persistence ----------
//
// Deliberately stored at a fixed location independent of the -data-dir flag
// (which flag.Parse hasn't even run yet when Init() needs this — flag
// *descriptions* need to already be localized) rather than inside the data
// directory itself.

type prefsFile struct {
	Lang string `json:"lang"`
}

func prefsPath() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserHomeDir()
	}
	return filepath.Join(base, "NetWatchCookieGuard", "language.json")
}

func loadPersisted() (Lang, bool) {
	b, err := os.ReadFile(prefsPath())
	if err != nil {
		return "", false
	}
	var p prefsFile
	if json.Unmarshal(b, &p) != nil {
		return "", false
	}
	return ParseLang(p.Lang)
}

func savePersisted(l Lang) error {
	p := prefsPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(prefsFile{Lang: string(l)})
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}
