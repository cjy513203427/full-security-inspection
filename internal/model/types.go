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
