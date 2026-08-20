// Package certcheck periodically probes a small set of watched domains for
// TLS interception: a MITM proxy (corporate SSL-inspection appliance, or
// just about anything else) that re-signs HTTPS certificates with a root CA
// it has gotten this machine to trust. That's the one blind spot nothing
// else in this tool can see — internal/correlate only ever looks at
// process/file/network *behavior*, and a network-level interception produces
// none: the browser shows no warning (the injected root is trusted), no
// process reads a credential file it shouldn't, nothing "beacons". It's also
// the only thing in this tool that initiates its own outbound connections,
// rather than passively observing everyone else's via ETW — see the
// "-disable-cert-check" flag in cmd/netwatch for turning it off.
//
// Detection principle: a plain TLS handshake succeeding proves nothing here,
// because it would succeed just as well against an interception proxy (that
// is the whole point of installing the root). Instead, the certificate chain
// the peer actually presents is verified independently against TWO pools:
// the OS trust store (what this Windows install currently accepts) and a
// bundled, fixed snapshot of the public Mozilla/curl CA list (assets/cacert.pem,
// what a real public CA should look like, deliberately NOT re-fetched at
// runtime so a compromised network can't hand us a fake update). OS-trusted
// but absent from the public list is the actual signal: something added a
// root to this machine's trust store that isn't a standard public CA.
package certcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netwatch/internal/config"
	"netwatch/internal/i18n"
	"netwatch/internal/model"
)

//go:embed assets/cacert.pem
var caBundlePEM []byte

var (
	trustedPoolOnce sync.Once
	trustedPool     *x509.CertPool
)

// trustedPublicRoots is the bundled public-CA pool, parsed once and reused
// for every probe — deliberately independent of x509.SystemCertPool() (see
// package doc).
func trustedPublicRoots() *x509.CertPool {
	trustedPoolOnce.Do(func() {
		trustedPool = x509.NewCertPool()
		trustedPool.AppendCertsFromPEM(caBundlePEM)
	})
	return trustedPool
}

// Handlers is the set of callbacks the Checker invokes for each probe.
type Handlers struct {
	OnCheck func(model.CertCheckEvent) // every probe, evidence for the "证书检测" tab
	OnAlert func(model.Alert)          // only probes that found something worth surfacing
}

// baselineEntry is the last-seen (issuer, root) pair for one domain, used to
// detect drift across restarts/checks — see Checker.probe.
type baselineEntry struct {
	Fingerprint string `json:"fingerprint"`
}

type Checker struct {
	h            Handlers
	targets      []string
	interval     time.Duration
	dialTimeout  time.Duration
	baselinePath string

	seq uint64

	mu       sync.Mutex
	baseline map[string]baselineEntry

	stopCh chan struct{}
	doneCh chan struct{}
}

// New creates a Checker. baselinePath, if non-empty, is where the
// last-known-good (issuer, root) fingerprint per domain is persisted across
// restarts (best-effort — a missing/corrupt file just starts clean rather
// than failing startup).
func New(h Handlers, baselinePath string) *Checker {
	return &Checker{
		h:            h,
		targets:      config.CertCheckTargets(),
		interval:     time.Duration(config.CertCheckIntervalSeconds) * time.Second,
		dialTimeout:  8 * time.Second,
		baselinePath: baselinePath,
		baseline:     make(map[string]baselineEntry),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
	}
}

// Start runs one probe pass immediately (so the dashboard's "证书检测" tab
// doesn't sit empty for a full interval after every launch) and then a
// ticker loop, in a background goroutine. It always returns nil — probing
// is best-effort, so there is nothing fallible to report at startup.
func (c *Checker) Start(ctx context.Context) error {
	c.loadBaseline()
	go c.loop(ctx)
	return nil
}

// Stop signals the loop to exit and blocks until it has (any in-flight
// probe still gets to finish or hit its own timeout first).
func (c *Checker) Stop() {
	close(c.stopCh)
	<-c.doneCh
}

func (c *Checker) loop(ctx context.Context) {
	defer close(c.doneCh)
	c.runOnce(ctx)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		case <-t.C:
			c.runOnce(ctx)
		}
	}
}

func (c *Checker) runOnce(ctx context.Context) {
	for _, domain := range c.targets {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		ev := c.probe(ctx, domain)
		ev.Seq = atomic.AddUint64(&c.seq, 1)
		ev.Time = time.Now()
		if c.h.OnCheck != nil {
			c.h.OnCheck(ev)
		}
		if a, ok := c.toAlert(ev); ok && c.h.OnAlert != nil {
			c.h.OnAlert(a)
		}
	}
	c.saveBaseline()
}

// probe connects to domain:443, and independently verifies whatever
// certificate chain it presents against both this machine's OS trust store
// and our own bundled public-CA pool. See the package doc for why both.
func (c *Checker) probe(ctx context.Context, domain string) model.CertCheckEvent {
	ev := model.CertCheckEvent{Domain: domain}

	dialCtx, cancel := context.WithTimeout(ctx, c.dialTimeout)
	defer cancel()

	rawConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		ev.Error = err.Error()
		return ev
	}
	defer rawConn.Close()

	// InsecureSkipVerify: verification happens explicitly below, twice,
	// against two different pools — accepting whatever the peer sends here
	// is what lets a probe against an actively-intercepted domain still
	// return real data instead of just a generic handshake error.
	tlsConn := tls.Client(rawConn, &tls.Config{ServerName: domain, InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		ev.Error = err.Error()
		return ev
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		ev.Error = i18n.T("certcheck.no_certificate")
		return ev
	}
	ev.OK = true

	leaf := state.PeerCertificates[0]
	ev.IssuerCN = leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		ev.IssuerO = leaf.Issuer.Organization[0]
	}

	var intermediates *x509.CertPool
	if len(state.PeerCertificates) > 1 {
		intermediates = x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:] {
			intermediates.AddCert(cert)
		}
	}

	// Independent check #1: does our own bundled public-CA snapshot trust
	// this chain? This is the actual MITM signal (combined with OS trust
	// below) — see package doc.
	if chains, err := leaf.Verify(x509.VerifyOptions{DNSName: domain, Roots: trustedPublicRoots(), Intermediates: intermediates}); err == nil {
		ev.TrustedPublicRoot = true
		setRootSubject(&ev, chains)
	}

	// Independent check #2: does the OS itself (Windows' own certificate
	// store / CertGetCertificateChain) trust it? A MITM proxy is only a
	// problem in practice once THIS check passes — that's what makes the
	// browser show no warning at all.
	if osPool, err := x509.SystemCertPool(); err == nil {
		if chains, err := leaf.Verify(x509.VerifyOptions{DNSName: domain, Roots: osPool, Intermediates: intermediates}); err == nil && ev.RootSubject == "" {
			setRootSubject(&ev, chains)
		}
	}

	issuerHay := strings.ToLower(ev.IssuerCN + " " + ev.IssuerO)
	for frag, vendor := range config.KnownInterceptionVendors() {
		if strings.Contains(issuerHay, frag) {
			ev.SuspectedVendor = vendor
			break
		}
	}
	if ev.SuspectedVendor == "" {
		for frag, vendor := range config.KnownConsumerAVRoots() {
			if strings.Contains(issuerHay, frag) {
				ev.SuspectedConsumerAV = vendor
				break
			}
		}
	}

	c.trackBaseline(&ev)
	return ev
}

func setRootSubject(ev *model.CertCheckEvent, chains [][]*x509.Certificate) {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return
	}
	root := chains[0][len(chains[0])-1]
	if root.Subject.CommonName != "" {
		ev.RootSubject = root.Subject.CommonName
	} else if len(root.Subject.Organization) > 0 {
		ev.RootSubject = root.Subject.Organization[0]
	}
}

// trackBaseline compares this probe against the last known-trusted
// (issuer, root) fingerprint for the domain and records Changed if it
// drifted — a generic tripwire that doesn't depend on either fingerprint
// list already knowing about whatever's intercepting the connection. Only a
// chain that verified against our own public-CA pool is allowed to become
// (or update) the baseline: an interception cert should never get to bless
// itself as the new normal for a domain.
func (c *Checker) trackBaseline(ev *model.CertCheckEvent) {
	if !ev.TrustedPublicRoot {
		return
	}
	fp := ev.IssuerCN + "|" + ev.RootSubject

	c.mu.Lock()
	defer c.mu.Unlock()
	prev, had := c.baseline[ev.Domain]
	if had && prev.Fingerprint != fp {
		ev.Changed = true
	}
	c.baseline[ev.Domain] = baselineEntry{Fingerprint: fp}
}

// toAlert decides whether a probe result is worth surfacing as a
// model.Alert, in increasing order of confidence: a matched enterprise
// interception vendor is the strongest, most specific claim, so it takes
// priority over the more generic "not a public root" finding even though
// both are usually true at once for the same probe. Alerts here
// deliberately carry no PID/process (nothing about this finding is
// process-scoped) — the frontend skips the process chip for that reason.
func (c *Checker) toAlert(ev model.CertCheckEvent) (model.Alert, bool) {
	if !ev.OK {
		return model.Alert{}, false // probe failure (network down, DNS, timeout...), not a finding
	}

	var severity model.Severity
	var title, detail string

	switch {
	case ev.SuspectedVendor != "":
		severity = model.SevHigh
		title = i18n.T("certcheck.vendor.title", ev.Domain, ev.SuspectedVendor)
		detail = i18n.T("certcheck.vendor.detail", ev.Domain, ev.IssuerCN, ev.IssuerO)

	case !ev.TrustedPublicRoot:
		severity = model.SevMedium
		title = i18n.T("certcheck.untrusted.title", ev.Domain)
		detail = i18n.T("certcheck.untrusted.detail", ev.Domain, ev.IssuerCN, ev.IssuerO, ev.RootSubject)

	case ev.Changed:
		severity = model.SevMedium
		title = i18n.T("certcheck.changed.title", ev.Domain)
		detail = i18n.T("certcheck.changed.detail", ev.Domain, ev.IssuerCN, ev.RootSubject)

	default:
		return model.Alert{}, false
	}

	return model.Alert{
		Time:     ev.Time,
		Severity: severity,
		Rule:     "tls_interception",
		Title:    title,
		Detail:   detail,
	}, true
}

func (c *Checker) loadBaseline() {
	if c.baselinePath == "" {
		return
	}
	b, err := os.ReadFile(c.baselinePath)
	if err != nil {
		return // first run, or unreadable — starting clean is fine, it just means one round of "changed" false positives at worst
	}
	var m map[string]baselineEntry
	if json.Unmarshal(b, &m) != nil {
		return
	}
	c.mu.Lock()
	c.baseline = m
	c.mu.Unlock()
}

func (c *Checker) saveBaseline() {
	if c.baselinePath == "" {
		return
	}
	c.mu.Lock()
	b, err := json.MarshalIndent(c.baseline, "", "  ")
	c.mu.Unlock()
	if err != nil {
		return
	}
	_ = os.WriteFile(c.baselinePath, b, 0o644) // best-effort; a failed write here shouldn't crash the monitor
}
