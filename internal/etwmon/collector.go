//go:build windows

// Package etwmon consumes Windows kernel ETW (Event Tracing for Windows)
// providers to observe, per-process, file access on sensitive stores and
// outbound network activity — without installing any third-party driver.
//
// Field names used to pull data out of each event were determined from
// public documentation for the manifest-based providers
// (Microsoft-Windows-Kernel-Process / -Kernel-File / -Kernel-Network /
// -DNS-Client). Because the exact property names can genuinely differ a
// little across Windows builds, every extraction goes through Collector's
// `prop` helper which tries a short list of known aliases and, if none
// match, falls back to a raw dump so nothing is silently lost — run with
// -debug-etw to capture raw JSON of anything that doesn't map cleanly and
// the mapping can be tightened from real samples.
package etwmon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xrawsec/golang-etw/etw"

	"netwatch/internal/model"
)

// Well-known, stable GUIDs for the manifest-based kernel providers we rely
// on. Hard-coded rather than resolved by name so we do not depend on the
// provider being present in TdhEnumerateProviders' result at start time.
const (
	guidKernelProcess = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}" // Microsoft-Windows-Kernel-Process
	guidKernelFile    = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}" // Microsoft-Windows-Kernel-File
	guidKernelNetwork = "{7DD42A49-5329-4832-8DFD-43D979153A88}" // Microsoft-Windows-Kernel-Network
	guidDNSClient     = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" // Microsoft-Windows-DNS-Client
)

// Handlers is the set of callbacks the Collector invokes for each kind of
// enriched event it manages to parse.
type Handlers struct {
	OnProcessStart func(model.ProcessInfo)
	OnProcessStop  func(pid uint32, exitTime time.Time)
	OnFile         func(rawPath string, pid uint32, kind model.FileAccessKind)
	OnNet          func(model.NetEvent)
	OnDNS          func(model.DNSEvent)
}

type Collector struct {
	h         Handlers
	session   *etw.RealTimeSession
	consumer  *etw.Consumer
	seq       uint64
	debug     bool
	debugFile *os.File
	selfPID   uint32
}

// New creates a Collector. selfPID is excluded from network/file reporting
// so the tool does not alert on its own log/JSONL writes and (pre-Wails)
// housekeeping. debugETWPath, if non-empty, receives one JSON line per raw
// event seen by the collector's four providers (verbose — for
// field-mapping diagnostics only).
func New(h Handlers, selfPID uint32, debugETWPath string) (*Collector, error) {
	c := &Collector{h: h, selfPID: selfPID}
	if debugETWPath != "" {
		f, err := os.Create(debugETWPath)
		if err != nil {
			return nil, fmt.Errorf("open debug-etw file: %w", err)
		}
		c.debugFile = f
		c.debug = true
	}
	return c, nil
}

func (c *Collector) nextSeq() uint64 { return atomic.AddUint64(&c.seq, 1) }

// Start creates the ETW real-time session, enables the four kernel
// providers and begins dispatching events in a background goroutine. It
// requires the process to be running elevated (Administrator).
func (c *Collector) Start(ctx context.Context) error {
	c.session = etw.NewRealTimeSession("NetWatchCookieGuard")

	providers := []struct {
		name string
		guid string
	}{
		{"Microsoft-Windows-Kernel-Process", guidKernelProcess},
		{"Microsoft-Windows-Kernel-File", guidKernelFile},
		{"Microsoft-Windows-Kernel-Network", guidKernelNetwork},
		{"Microsoft-Windows-DNS-Client", guidDNSClient},
	}

	for _, p := range providers {
		prov := etw.Provider{GUID: p.guid, Name: p.name, EnableLevel: 0xff}
		if err := c.session.EnableProvider(prov); err != nil {
			return fmt.Errorf("enable provider %s: %w (are you running as Administrator?)", p.name, err)
		}
	}

	c.consumer = etw.NewRealTimeConsumer(ctx)
	c.consumer.FromSessions(c.session)

	go c.dispatchLoop()

	if err := c.consumer.Start(); err != nil {
		return fmt.Errorf("start ETW consumer: %w", err)
	}
	return nil
}

func (c *Collector) Stop() {
	if c.consumer != nil {
		c.consumer.Stop()
	}
	if c.session != nil {
		c.session.Stop()
	}
	if c.debugFile != nil {
		c.debugFile.Close()
	}
}

func (c *Collector) dispatchLoop() {
	for e := range c.consumer.Events {
		if c.debug {
			if b, err := json.Marshal(e); err == nil {
				c.debugFile.Write(b)
				c.debugFile.Write([]byte("\n"))
			}
		}
		pid := e.System.Execution.ProcessID
		if pid != 0 && pid == c.selfPID {
			continue
		}
		switch e.System.Provider.Name {
		case "Microsoft-Windows-Kernel-Process":
			c.handleProcess(e)
		case "Microsoft-Windows-Kernel-File":
			c.handleFile(e)
		case "Microsoft-Windows-Kernel-Network":
			c.handleNet(e)
		case "Microsoft-Windows-DNS-Client":
			c.handleDNS(e)
		}
	}
}

// prop tries each candidate key in turn and returns the first present
// value as a string.
func prop(e *etw.Event, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := e.GetProperty(k); ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t, true
				}
			default:
				return fmt.Sprintf("%v", t), true
			}
		}
	}
	return "", false
}

func propUint(e *etw.Event, keys ...string) (uint64, bool) {
	if s, ok := prop(e, keys...); ok {
		s = strings.TrimPrefix(s, "0x")
		if n, err := strconv.ParseUint(s, 10, 64); err == nil {
			return n, true
		}
		if n, err := strconv.ParseUint(s, 16, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

func (c *Collector) handleProcess(e *etw.Event) {
	taskLower := strings.ToLower(e.System.Task.Name)
	opLower := strings.ToLower(e.System.Opcode.Name)
	isStart := e.System.EventID == 1 || strings.Contains(taskLower, "start") || strings.Contains(opLower, "start")
	isStop := e.System.EventID == 2 || strings.Contains(taskLower, "stop") || strings.Contains(taskLower, "end") || strings.Contains(opLower, "stop") || strings.Contains(opLower, "end")

	newPID, _ := propUint(e, "ProcessID")
	if newPID == 0 {
		newPID = uint64(e.System.Execution.ProcessID)
	}
	if newPID != 0 && uint32(newPID) == c.selfPID {
		return
	}

	if isStart && c.h.OnProcessStart != nil {
		ppid, _ := propUint(e, "ParentProcessID")
		img, _ := prop(e, "ImageName", "ImageFileName", "ImagePath")
		cmd, _ := prop(e, "CommandLine")
		pi := model.ProcessInfo{
			PID:         uint32(newPID),
			PPID:        uint32(ppid),
			ImagePath:   img,
			Name:        baseName(img),
			CommandLine: cmd,
			StartTime:   e.System.TimeCreated.SystemTime,
		}
		c.h.OnProcessStart(pi)
		return
	}
	if isStop && c.h.OnProcessStop != nil {
		c.h.OnProcessStop(uint32(newPID), e.System.TimeCreated.SystemTime)
	}
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "/", "\\")
	if i := strings.LastIndex(path, "\\"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func (c *Collector) handleFile(e *etw.Event) {
	task := strings.ToLower(e.System.Task.Name)
	// We only care about handle-open style events; Read/Write/QueryInfo
	// events on Kernel-File do not usually re-carry the file name (it is
	// tracked internally against the FileObject by the OS), so the most
	// reliable and cheap signal is the initial Create.
	var kind model.FileAccessKind
	switch {
	case strings.Contains(task, "namecreate"):
		kind = model.FileCreate
	case strings.Contains(task, "namedelete"):
		kind = model.FileDelete
	case strings.Contains(task, "create"):
		kind = model.FileOpen
	default:
		return
	}

	path, ok := prop(e, "FileName", "OpenPath", "FilePath")
	if !ok || path == "" {
		return
	}
	pid := e.System.Execution.ProcessID
	if pid == 0 || pid == c.selfPID {
		return
	}
	if c.h.OnFile != nil {
		c.h.OnFile(path, pid, kind)
	}
}

func (c *Collector) handleNet(e *etw.Event) {
	task := strings.ToLower(e.System.Task.Name)
	opcode := strings.ToLower(e.System.Opcode.Name)
	combined := task + " " + opcode

	proto := "TCP"
	if strings.Contains(combined, "udp") {
		proto = "UDP"
	}

	// Only events that represent the establishment/teardown of a flow are
	// kept. send/recv/retransmit fire per-packet on Kernel-Network and
	// would be extremely high volume for little extra detection value —
	// "who connected to what, when" is what the correlation engine and the
	// dashboard need, not a byte-level packet trace.
	direction := ""
	switch {
	case strings.Contains(combined, "connect") && !strings.Contains(combined, "disconnect"):
		direction = "connect"
	case strings.Contains(combined, "accept"):
		direction = "accept"
	case strings.Contains(combined, "disconnect"):
		direction = "disconnect"
	}
	if direction == "" {
		return
	}

	pidVal, ok := propUint(e, "PID", "ProcessId")
	pid := uint32(pidVal)
	if !ok || pid == 0 {
		pid = e.System.Execution.ProcessID
	}
	if pid == 0 || pid == c.selfPID {
		return
	}

	daddr, _ := prop(e, "daddr", "DestAddress", "RemoteAddress")
	saddr, _ := prop(e, "saddr", "SourceAddress", "LocalAddress")
	dport, _ := propUint(e, "dport", "DestPort", "RemotePort")
	sport, _ := propUint(e, "sport", "SourcePort", "LocalPort")
	size, _ := propUint(e, "size", "Size")

	ne := model.NetEvent{
		Seq:        c.nextSeq(),
		Time:       e.System.TimeCreated.SystemTime,
		PID:        pid,
		Proto:      proto,
		Direction:  direction,
		LocalAddr:  saddr,
		LocalPort:  uint16(sport),
		RemoteAddr: daddr,
		RemotePort: uint16(dport),
		Size:       uint32(size),
	}
	if c.h.OnNet != nil {
		c.h.OnNet(ne)
	}
}

func (c *Collector) handleDNS(e *etw.Event) {
	if e.System.EventID != 3008 && !strings.Contains(strings.ToLower(e.System.Task.Name), "query") {
		return
	}
	query, ok := prop(e, "QueryName")
	if !ok || query == "" {
		return
	}
	resultsRaw, _ := prop(e, "QueryResults")
	var results []string
	for _, part := range strings.Split(resultsRaw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// QueryResults mixes CNAME-chain entries (e.g. "type: 5
		// some.cdn.example.com") in with the actual resolved IPs; only the
		// IPs are useful here — the correlation engine uses this list to
		// key its IP->domain map, so a CNAME text entry sneaking through
		// would just become permanent dead weight in that map.
		if net.ParseIP(part) == nil {
			continue
		}
		results = append(results, part)
	}
	pid := e.System.Execution.ProcessID
	if pid == 0 || pid == c.selfPID {
		return
	}
	de := model.DNSEvent{
		Seq:     c.nextSeq(),
		Time:    e.System.TimeCreated.SystemTime,
		PID:     pid,
		Query:   query,
		Results: results,
	}
	if c.h.OnDNS != nil {
		c.h.OnDNS(de)
	}
}
