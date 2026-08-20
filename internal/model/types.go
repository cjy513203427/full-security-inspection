// Package model holds the shared data structures passed between the ETW
// collectors, the correlation engine, the store and the web dashboard.
package model

import "time"

// Severity levels used for alerts and for color-coding rows in the UI.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// ProcessInfo describes everything we know about a running (or recently
// exited) process. It is looked up / cached by PID and enriched lazily
// (signature check is somewhat expensive so it is done once and cached).
type ProcessInfo struct {
	PID           uint32    `json:"pid"`
	PPID          uint32    `json:"ppid"`
	Name          string    `json:"name"`
	ImagePath     string    `json:"imagePath"`
	CommandLine   string    `json:"commandLine"`
	StartTime     time.Time `json:"startTime"`
	ExitTime      time.Time `json:"exitTime,omitempty"`
	Exited        bool      `json:"exited"`
	Signed        bool      `json:"signed"`
	SignerName    string    `json:"signerName,omitempty"`
	SigChecked    bool      `json:"sigChecked"`
	SuspiciousLoc bool      `json:"suspiciousLoc"` // running from Temp/AppData/Downloads/Public etc.
	SHA256        string    `json:"sha256,omitempty"`
	Known         bool      `json:"known"`                   // matched our allowlist of common browsers/apps
	NameInherited bool      `json:"nameInherited,omitempty"` // Name/ImagePath borrowed from the parent process because direct lookup failed (see procinfo.Cache.Observe)
}

// IdentityUnknown is true when we were never able to attach any name to
// this PID at all — direct lookup failed and no parent identity was
// available to inherit either. Callers should treat this as "unconfirmed",
// not "confirmed hostile": an unnamed process is not evidence by itself.
func (p ProcessInfo) IdentityUnknown() bool {
	return p.Name == ""
}

// FileAccessKind enumerates the kind of touch we observed on a sensitive file.
type FileAccessKind string

const (
	FileOpen   FileAccessKind = "open"
	FileCreate FileAccessKind = "create"
	FileWrite  FileAccessKind = "write"
	FileDelete FileAccessKind = "delete"
)

// SensitiveFileEvent records a process touching a file that matched our
// watch-list of browser/app cookie & credential stores.
type SensitiveFileEvent struct {
	Seq      uint64         `json:"seq"`
	Time     time.Time      `json:"time"`
	PID      uint32         `json:"pid"`
	ProcName string         `json:"procName"`
	Path     string         `json:"path"`
	App      string         `json:"app"` // "Chrome", "Discord", "Steam", ...
	Kind     FileAccessKind `json:"kind"`
	OwnFile  bool           `json:"ownFile"` // true if the touching process is the app that owns the file (e.g. chrome.exe reading its own cookies)
}

// NetEvent records a network connect/send observed via ETW Kernel-Network.
type NetEvent struct {
	Seq        uint64    `json:"seq"`
	Time       time.Time `json:"time"`
	PID        uint32    `json:"pid"`
	ProcName   string    `json:"procName"`
	Proto      string    `json:"proto"`     // TCP / UDP
	Direction  string    `json:"direction"` // connect / accept / send / recv / disconnect
	LocalAddr  string    `json:"localAddr"`
	LocalPort  uint16    `json:"localPort"`
	RemoteAddr string    `json:"remoteAddr"`
	RemotePort uint16    `json:"remotePort"`
	Size       uint32    `json:"size"`
	Domain     string    `json:"domain,omitempty"`    // filled in from correlated DNS-Client events
	AIService  string    `json:"aiService,omitempty"` // "Claude" / "ChatGPT" / "Gemini" ... when Domain matches config.WatchedAIServices
}

// DNSEvent records a domain resolution observed via ETW DNS-Client.
type DNSEvent struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	PID       uint32    `json:"pid"`
	ProcName  string    `json:"procName"`
	Query     string    `json:"query"`
	Results   []string  `json:"results"`
	AIService string    `json:"aiService,omitempty"`
}

// CertCheckEvent records one periodic TLS probe against a watched domain
// (internal/certcheck), evidence for the "is my HTTPS traffic being
// intercepted" check — the one thing this tool observes actively rather
// than passively via ETW, and the one blind spot process-behavior
// correlation alone can never see (a MITM proxy re-signing certificates
// with a root the OS already trusts produces no suspicious file/process/
// network behavior at all).
type CertCheckEvent struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	Domain string    `json:"domain"`

	// OK is false when the probe itself failed (network down, firewall,
	// DNS failure, timeout...) rather than reporting on a certificate —
	// Error holds why. Not a security signal by itself.
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	IssuerCN    string `json:"issuerCN,omitempty"`
	IssuerO     string `json:"issuerO,omitempty"`
	RootSubject string `json:"rootSubject,omitempty"`

	// TrustedPublicRoot is true when the presented chain verifies against
	// our own bundled public-CA pool (independent of the OS trust store).
	// False is the actual signal: the OS/WebView accepted a chain our own
	// bundle does not — something added a root CA to this machine's trust
	// store that isn't a standard public one.
	TrustedPublicRoot bool `json:"trustedPublicRoot"`

	// SuspectedVendor is set when IssuerCN/IssuerO matched a known
	// enterprise SSL-inspection product's fingerprint (config.
	// KnownInterceptionVendors) — high-confidence, names the product.
	SuspectedVendor string `json:"suspectedVendor,omitempty"`

	// SuspectedConsumerAV is set when the issuer instead matched a known
	// consumer antivirus's local HTTPS-scanning root (config.
	// KnownConsumerAVRoots) — same mechanism, far lower concern, kept
	// separate so it isn't scored the same as an enterprise proxy.
	SuspectedConsumerAV string `json:"suspectedConsumerAV,omitempty"`

	// Changed is true when this domain's (issuer, root) pair differs from
	// the last time it was seen trusted — catches novel interception setups
	// that match neither fingerprint list, at the cost of one unavoidable
	// false positive the very first time a domain legitimately rotates CAs.
	Changed bool `json:"changed"`
}

// Alert is a synthesized, human readable warning produced by the
// correlation engine from raw events.
type Alert struct {
	Seq       uint64       `json:"seq"`
	Time      time.Time    `json:"time"`
	Severity  Severity     `json:"severity"`
	Rule      string       `json:"rule"`
	Title     string       `json:"title"`
	Detail    string       `json:"detail"`
	PID       uint32       `json:"pid"`
	ProcName  string       `json:"procName"`
	ImagePath string       `json:"imagePath,omitempty"`
	AIService string       `json:"aiService,omitempty"` // set when the correlated connection targeted a watched AI-service domain
	Process   *ProcessInfo `json:"process,omitempty"`   // full evidence snapshot of the implicated process at alert time (command line, hash, signature, parent...)
	Related   []uint64     `json:"related,omitempty"`   // seq numbers of related file/net events, for the timeline view
	Ack       bool         `json:"ack"`
}
