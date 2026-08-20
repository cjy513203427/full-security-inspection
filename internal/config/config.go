// Package config centralizes everything that is "knowledge" rather than
// "mechanism": which files count as sensitive, which processes are expected
// to touch them, and the tunable knobs for the correlation engine.
package config

import (
	"strings"

	"netwatch/internal/i18n"
)

// SensitiveTarget is one watched file/folder pattern belonging to an app.
type SensitiveTarget struct {
	// AppKey (+ AppArgs) is an internal/i18n catalog key for the target's
	// display name, e.g. "target.browser_cookies" with AppArgs{"Chrome"} —
	// resolved lazily via TargetAppName() at the point an alert actually
	// fires, not baked into a plain string here at startup, so a live
	// language switch (internal/i18n.Set) is reflected in the very next
	// alert this target raises rather than only after a restart.
	AppKey   string
	AppArgs  []any
	Category string   // "cookie" | "password" | "token" | "config"
	Pattern  string   // lower-cased, drive/device-agnostic substring to match against the reported file path
	BasePath string   // optional second required substring, also lower-cased/drive-agnostic (see below)
	Critical bool     // true = this is a session/credential store (cookie theft target)
	Owners   []string // process image names (lower-case, no path) that are expected/normal to touch this file
}

// TargetAppName resolves a SensitiveTarget's display name in the
// currently active language.
func TargetAppName(t SensitiveTarget) string {
	return i18n.T(t.AppKey, t.AppArgs...)
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
			SensitiveTarget{AppKey: "target.browser_cookies", AppArgs: []any{b.app}, Category: "cookie", Pattern: "network\\cookies", BasePath: b.base, Critical: true, Owners: []string{b.owner}},
			SensitiveTarget{AppKey: "target.browser_password", AppArgs: []any{b.app}, Category: "password", Pattern: "login data", BasePath: b.base, Critical: true, Owners: []string{b.owner}},
			SensitiveTarget{AppKey: "target.browser_local_storage", AppArgs: []any{b.app}, Category: "token", Pattern: b.base + `default\local storage`, Critical: false, Owners: []string{b.owner}},
		)
	}

	// Firefox
	targets = append(targets,
		SensitiveTarget{AppKey: "target.firefox_cookies", Category: "cookie", Pattern: "cookies.sqlite", Critical: true, Owners: []string{"firefox.exe"}},
		SensitiveTarget{AppKey: "target.firefox_password", Category: "password", Pattern: "logins.json", Critical: true, Owners: []string{"firefox.exe"}},
		SensitiveTarget{AppKey: "target.firefox_master_key", Category: "password", Pattern: "key4.db", Critical: true, Owners: []string{"firefox.exe"}},
	)

	// Discord family (and clones) - Electron apps keep the session token in
	// their leveldb-backed Local Storage.
	for _, d := range []string{"discord", "discordcanary", "discordptb", "discorddevelopment", "lightcord"} {
		targets = append(targets, SensitiveTarget{
			AppKey: "target.discord_variant", AppArgs: []any{d}, Category: "token",
			Pattern:  `\appdata\roaming\` + d + `\local storage\leveldb`,
			Critical: true,
			Owners:   []string{d + ".exe", "update.exe"},
		})
	}

	// Steam - pattern intentionally omits the install directory (users can
	// install Steam on any drive/path) and matches on the well-known
	// relative file names instead.
	targets = append(targets,
		SensitiveTarget{AppKey: "target.steam_login", Category: "token", Pattern: `steam\config\loginusers.vdf`, Critical: true, Owners: []string{"steam.exe"}},
		SensitiveTarget{AppKey: "target.steam_ssfn", Category: "token", Pattern: `steam\ssfn`, Critical: true, Owners: []string{"steam.exe"}},
	)

	// EA app / Origin - exact file names are not well documented publicly,
	// so we watch the whole config/cache directory as a coarser net.
	targets = append(targets,
		SensitiveTarget{AppKey: "target.ea_app", Category: "token", Pattern: `\electronic arts\ea desktop`, Critical: false, Owners: []string{"eadesktop.exe", "eabackgroundservice.exe"}},
		SensitiveTarget{AppKey: "target.origin", Category: "token", Pattern: `\appdata\roaming\origin`, Critical: false, Owners: []string{"origin.exe", "originwebhelperservice.exe"}},
	)

	// Generic Electron apps (Slack, Teams, WhatsApp, etc.) - same leveldb
	// pattern as Discord, kept as a lower-confidence catch-all category.
	for _, e := range []struct{ app, dir, owner string }{
		{"Slack", "slack", "slack.exe"},
		{"Microsoft Teams", "microsoft\\teams", "teams.exe"},
		{"WhatsApp", "whatsapp", "whatsapp.exe"},
	} {
		targets = append(targets, SensitiveTarget{
			AppKey: "target.electron_local_storage", AppArgs: []any{e.app}, Category: "token",
			Pattern:  `\appdata\roaming\` + e.dir + `\local storage\leveldb`,
			Critical: false,
			Owners:   []string{e.owner},
		})
	}

	return targets
}

// CategoryLabel returns the currently active language's display name for a
// SensitiveTarget.Category value ("cookie" | "password" | "token" |
// "config"), used by internal/correlate to name what kind of store a
// non-owner process touched.
func CategoryLabel(category string) string {
	switch category {
	case "cookie":
		return i18n.T("category.cookie")
	case "password":
		return i18n.T("category.password")
	case "token":
		return i18n.T("category.token")
	default:
		return i18n.T("category.config")
	}
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

// CertCheckTargets is the small set of domains internal/certcheck
// periodically probes for TLS interception (a MITM proxy re-signing certs
// with a root the OS was made to trust silently) — the one blind spot nothing
// else in this tool can see, since a network-level interception produces no
// suspicious file/process/network behavior at all. The first three are the
// AI-service domains this whole project prioritizes protecting the session
// cookies of (see WatchedAIServiceDomains); github.com/cloudflare.com are
// generic, high-uptime anchors kept as a baseline independent of any one
// AI vendor's own CDN/cert rotation quirks.
func CertCheckTargets() []string {
	return []string{
		"claude.ai",
		"chatgpt.com",
		"gemini.google.com",
		"github.com",
		"cloudflare.com",
	}
}

// CertCheckIntervalSeconds is how often each target in CertCheckTargets is
// re-probed. Frequent enough to notice a MITM proxy toggled on mid-session
// within one work session; infrequent enough that the tool's one piece of
// self-initiated network traffic stays unobtrusive.
const CertCheckIntervalSeconds = 600

// KnownInterceptionVendors maps a lower-cased substring of a certificate's
// Issuer CommonName/Organization to a display label for enterprise
// SSL-inspection products. A match here is the highest-confidence signal
// certcheck can raise: these products exist specifically to decrypt and
// re-encrypt HTTPS traffic on corporate/school networks, so seeing one
// mid-chain on an otherwise-ordinary domain is a direct, nameable finding
// rather than an inference.
func KnownInterceptionVendors() map[string]string {
	return map[string]string{
		"zscaler":                      "Zscaler",
		"netskope":                     "Netskope",
		"palo alto":                    "Palo Alto Networks",
		"paloalto":                     "Palo Alto Networks",
		"fortinet":                     "Fortinet FortiGate",
		"fortigate":                    "Fortinet FortiGate",
		"cisco umbrella":               "Cisco Umbrella",
		"ironport":                     "Cisco IronPort",
		"blue coat":                    "Blue Coat / Symantec ProxySG",
		"bluecoat":                     "Blue Coat / Symantec ProxySG",
		"forcepoint":                   "Forcepoint",
		"websense":                     "Forcepoint (Websense)",
		"skyhigh":                      "Skyhigh Security",
		"mcafee web gateway":           "McAfee Web Gateway",
		"check point":                  "Check Point",
		"checkpoint":                   "Check Point",
		"sophos":                       "Sophos",
		"barracuda":                    "Barracuda",
		"menlo security":               "Menlo Security",
		"iboss":                        "iboss",
		"sonicwall":                    "SonicWall",
		"trustwave secure web gateway": "Trustwave",
		"squid":                        i18n.T("vendor.squid"),
		"mitmproxy":                    "mitmproxy",
		"charles proxy":                "Charles Proxy",
		"fiddler":                      "Fiddler",
	}
}

// KnownConsumerAVRoots maps a lower-cased Issuer substring for common
// consumer-antivirus local HTTPS-scanning root certificates, kept separate
// from KnownInterceptionVendors: these also intercept your TLS traffic, but
// for local anti-malware content scanning on a machine you presumably
// control yourself — not third-party network surveillance. A match here
// should read as "expected, low concern", not "someone is watching you".
func KnownConsumerAVRoots() map[string]string {
	return map[string]string{
		"kaspersky":       "Kaspersky",
		"avast":           "Avast",
		"avg":             "AVG",
		"eset":            "ESET",
		"bitdefender":     "Bitdefender",
		"norton":          "Norton/NortonLifeLock",
		"mcafee livesafe": "McAfee LiveSafe",
		"malwarebytes":    "Malwarebytes",
		"360":             i18n.T("vendor.qihoo360"),
		"qihoo":           "360 (Qihoo)",
	}
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
