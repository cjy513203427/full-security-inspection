// Package config centralizes everything that is "knowledge" rather than
// "mechanism": which files count as sensitive, which processes are expected
// to touch them, and the tunable knobs for the correlation engine.
package config

import "strings"

// SensitiveTarget is one watched file/folder pattern belonging to an app.
type SensitiveTarget struct {
	App      string   // display name, e.g. "Chrome Cookies", "Google 账号密码"
	Category string   // "cookie" | "password" | "token" | "config"
	Pattern  string   // lower-cased, drive/device-agnostic substring to match against the reported file path
	BasePath string   // optional second required substring, also lower-cased/drive-agnostic (see below)
	Critical bool     // true = this is a session/credential store (cookie theft target)
	Owners   []string // process image names (lower-case, no path) that are expected/normal to touch this file
}

// SensitiveTargets returns the list of file patterns we watch for via the
// Kernel-File ETW provider. Matching is a case-insensitive substring test
// against the path ETW reports for the file, which is sometimes an NT
// device path (\Device\HarddiskVolume3\Users\...) rather than a drive
// letter one (C:\Users\...) — so patterns here deliberately start from
// "\users\..." / "\appdata\..." rather than a drive letter, matching
// either form and being independent of which drive Windows/the user
// profile happens to live on.
//
// Coverage rationale (see README for the full writeup):
//   - Any Chromium browser's "Network\Cookies" and "Login Data" covers the
//     vast majority of "web login" accounts (Google, LinkedIn, Instagram,
//     GitHub, etc.) since those all sit behind browser session cookies /
//     saved passwords, regardless of the site.
//   - Firefox equivalents (cookies.sqlite / logins.json / key4.db).
//   - Native desktop clients that keep their own session tokens outside the
//     browser: Discord (Electron leveldb store), Steam (loginusers.vdf +
//     ssfn* auth files), and EA app / Origin.
func SensitiveTargets() []SensitiveTarget {
	chromiumBrowsers := []struct {
		app   string
		base  string // path fragment under the profile dir, drive-agnostic
		owner string
	}{
		{"Chrome", `\appdata\local\google\chrome\user data\`, "chrome.exe"},
		{"Edge", `\appdata\local\microsoft\edge\user data\`, "msedge.exe"},
		{"Brave", `\appdata\local\bravesoftware\brave-browser\user data\`, "brave.exe"},
		{"Vivaldi", `\appdata\local\vivaldi\user data\`, "vivaldi.exe"},
		{"Opera", `\appdata\roaming\opera software\opera stable\`, "opera.exe"},
	}

	var targets []SensitiveTarget

	// "Network\Cookies" and "Login Data" are the same relative filename
	// across every Chromium-based browser AND every app that embeds the
	// Chromium/Edge WebView2 runtime (VS Code, and countless other desktop
	// apps) for its own unrelated, isolated cookie jar — WebView2's on-disk
	// layout mirrors a real browser profile's. Without BasePath scoping,
	// Pattern alone would match any of those against whichever browser
	// happens to be first in this slice (Chrome), mislabeling e.g. a signed
	// msedgewebview2.exe reading its own local cookies as "a non-owner
	// process reading Chrome's credentials" — a real false positive
	// observed in production. BasePath requires the match to actually sit
	// inside that specific browser's own profile folder, so an embedded
	// WebView2 instance with its own isolated user-data folder elsewhere on
	// disk doesn't match any browser here at all (correctly: it isn't
	// touching Chrome's or Edge's data), while a process that touches a
	// real browser's actual profile folder is still caught exactly as
	// before.
	for _, b := range chromiumBrowsers {
		targets = append(targets,
			SensitiveTarget{App: b.app + " Cookies 数据库", Category: "cookie", Pattern: "network\\cookies", BasePath: b.base, Critical: true, Owners: []string{b.owner}},
			SensitiveTarget{App: b.app + " 保存的密码", Category: "password", Pattern: "login data", BasePath: b.base, Critical: true, Owners: []string{b.owner}},
			SensitiveTarget{App: b.app + " Local Storage(可能含网页 token)", Category: "token", Pattern: b.base + `default\local storage`, Critical: false, Owners: []string{b.owner}},
		)
	}

	// Firefox
	targets = append(targets,
		SensitiveTarget{App: "Firefox Cookies", Category: "cookie", Pattern: "cookies.sqlite", Critical: true, Owners: []string{"firefox.exe"}},
		SensitiveTarget{App: "Firefox 保存的密码", Category: "password", Pattern: "logins.json", Critical: true, Owners: []string{"firefox.exe"}},
		SensitiveTarget{App: "Firefox 密码主密钥", Category: "password", Pattern: "key4.db", Critical: true, Owners: []string{"firefox.exe"}},
	)

	// Discord family (and clones) - Electron apps keep the session token in
	// their leveldb-backed Local Storage.
	for _, d := range []string{"discord", "discordcanary", "discordptb", "discorddevelopment", "lightcord"} {
		targets = append(targets, SensitiveTarget{
			App: "Discord(" + d + ")", Category: "token",
			Pattern:  `\appdata\roaming\` + d + `\local storage\leveldb`,
			Critical: true,
			Owners:   []string{d + ".exe", "update.exe"},
		})
	}

	// Steam - pattern intentionally omits the install directory (users can
	// install Steam on any drive/path) and matches on the well-known
	// relative file names instead.
	targets = append(targets,
		SensitiveTarget{App: "Steam 登录信息", Category: "token", Pattern: `steam\config\loginusers.vdf`, Critical: true, Owners: []string{"steam.exe"}},
		SensitiveTarget{App: "Steam 免二次验证凭据(ssfn)", Category: "token", Pattern: `steam\ssfn`, Critical: true, Owners: []string{"steam.exe"}},
	)

	// EA app / Origin - exact file names are not well documented publicly,
	// so we watch the whole config/cache directory as a coarser net.
	targets = append(targets,
		SensitiveTarget{App: "EA App", Category: "token", Pattern: `\electronic arts\ea desktop`, Critical: false, Owners: []string{"eadesktop.exe", "eabackgroundservice.exe"}},
		SensitiveTarget{App: "Origin", Category: "token", Pattern: `\appdata\roaming\origin`, Critical: false, Owners: []string{"origin.exe", "originwebhelperservice.exe"}},
	)

	// Generic Electron apps (Slack, Teams, WhatsApp, etc.) - same leveldb
	// pattern as Discord, kept as a lower-confidence catch-all category.
	for _, e := range []struct{ app, dir, owner string }{
		{"Slack", "slack", "slack.exe"},
		{"Microsoft Teams", "microsoft\\teams", "teams.exe"},
		{"WhatsApp", "whatsapp", "whatsapp.exe"},
	} {
		targets = append(targets, SensitiveTarget{
			App: e.app + " Local Storage", Category: "token",
			Pattern:  `\appdata\roaming\` + e.dir + `\local storage\leveldb`,
			Critical: false,
			Owners:   []string{e.owner},
		})
	}

	return targets
}

// KnownBrowsers lists process image names that are expected to legitimately
// perform network activity and touch cookie stores. Anything NOT in this
// list that touches a sensitive file, or that opens a raw network
// connection while having recently touched one, is scored as far more
// suspicious.
func KnownBrowsers() map[string]bool {
	return map[string]bool{
		"chrome.exe": true, "msedge.exe": true, "brave.exe": true,
		"vivaldi.exe": true, "opera.exe": true, "firefox.exe": true,
		"iexplore.exe": true,
	}
}

// SuspiciousPathFragments flags process images launched from locations
// malware commonly drops itself into.
func SuspiciousPathFragments() []string {
	return []string{
		`\appdata\local\temp\`,
		`\appdata\roaming\`, // broad but common; combined with "unsigned" this is a strong signal, alone it's just "low"
		`\windows\temp\`,
		`\programdata\`,
		`\users\public\`,
		`\downloads\`,
		`\recycle.bin\`,
	}
}

// WatchedAIServiceDomains maps a lower-cased domain fragment to a display
// label. Any DNS resolution or DNS-enriched connection touching one of
// these gets tagged distinctly in the dashboard and, if it's also part of
// a file-then-network correlation, bumps that alert's visibility — per
// your explicit priority on Claude/ChatGPT/Gemini session theft. Matching
// is substring-based on the resolved hostname, so subdomains (e.g.
// "api.anthropic.com", "chat.openai.com") are covered by the parent
// domain entry without listing every one individually.
func WatchedAIServiceDomains() map[string]string {
	return map[string]string{
		"claude.ai":             "Claude",
		"anthropic.com":         "Claude/Anthropic",
		"chatgpt.com":           "ChatGPT",
		"openai.com":            "ChatGPT/OpenAI",
		"gemini.google.com":     "Gemini",
		"aistudio.google.com":   "Gemini/AI Studio",
		"bard.google.com":       "Gemini",
		"makersuite.google.com": "Gemini",
	}
}

// MatchAIService returns the display label for domain if it matches a
// watched AI service, or "" if it doesn't.
func MatchAIService(domain string) string {
	if domain == "" {
		return ""
	}
	d := strings.ToLower(domain)
	for frag, label := range WatchedAIServiceDomains() {
		if strings.Contains(d, frag) {
			return label
		}
	}
	return ""
}

// CorrelationWindowSeconds is how long after a sensitive-file touch we keep
// looking for an outbound network connection from the same process before
// we stop treating it as "related" to that file touch.
const CorrelationWindowSeconds = 15

// DNSCacheWindowSeconds is how long we remember a resolved IP->domain
// mapping observed via the DNS-Client provider, used to enrich connection
// events with a domain name and to flag raw-IP connects that were never
// preceded by an OS-level DNS lookup.
const DNSCacheWindowSeconds = 1800

// Beacon detection thresholds for periodic-connection ("beaconing") alerts.
const (
	BeaconMinSamples = 5
	// intervals within +/-15% of the mean count as "regular"
	BeaconJitterFraction = 0.15
	// only consider connects within the last 10 minutes
	BeaconWindowSeconds = 600
	// connections faster than this are ignored for beacon purposes.
	// Observed in practice: legitimate background software (e.g. vendor
	// monitor/telemetry utilities) routinely polls every 1-3 seconds,
	// which is fast enough to look "suspiciously regular" but is not what
	// real C2 beaconing looks like (that's usually 30s+, specifically
	// because anything faster is conspicuous). 8s cuts most of that
	// legitimate-software noise while still catching slower beacons.
	BeaconMinIntervalSeconds = 8
)
