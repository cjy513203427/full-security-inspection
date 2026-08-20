package certcheck

import (
	"testing"

	"netwatch/internal/model"
)

// trustedPublicRoots must actually parse into a non-trivial pool — a
// truncated or corrupted assets/cacert.pem would silently make every
// domain look "not backed by a public CA", i.e. every single probe would
// misfire as a medium-severity alert. Subjects() isn't exposed by
// x509.CertPool, so cert count isn't directly inspectable; parsing without
// panicking plus a size sanity check on the embedded bytes is the
// practical guard here.
func TestTrustedPublicRootsParses(t *testing.T) {
	if len(caBundlePEM) < 50_000 {
		t.Fatalf("assets/cacert.pem looks truncated: only %d bytes", len(caBundlePEM))
	}
	pool := trustedPublicRoots()
	if pool == nil {
		t.Fatal("trustedPublicRoots() returned nil")
	}
	// Calling it again must return the exact same instance (sync.Once) —
	// parsing 100+ PEM blocks on every probe would be wasteful.
	if pool2 := trustedPublicRoots(); pool2 != pool {
		t.Fatal("trustedPublicRoots() did not memoize across calls")
	}
}

func newChecker() *Checker {
	return New(Handlers{}, "")
}

func TestToAlertVendorMatchIsHighAndTakesPriority(t *testing.T) {
	c := newChecker()
	ev := model.CertCheckEvent{
		Domain:            "claude.ai",
		OK:                true,
		IssuerCN:          "Zscaler Intermediate CA",
		TrustedPublicRoot: false, // realistic: a vendor cert also fails the public-CA check
		SuspectedVendor:   "Zscaler",
	}
	a, ok := c.toAlert(ev)
	if !ok {
		t.Fatal("expected an alert for a matched interception vendor")
	}
	if a.Severity != model.SevHigh {
		t.Errorf("severity = %s, want high", a.Severity)
	}
	if a.Rule != "tls_interception" {
		t.Errorf("rule = %q, want tls_interception", a.Rule)
	}
	if a.PID != 0 || a.ProcName != "" {
		t.Error("cert-check alerts must not claim a process — this finding isn't process-scoped")
	}
}

func TestToAlertUntrustedRootIsMedium(t *testing.T) {
	c := newChecker()
	ev := model.CertCheckEvent{
		Domain:            "github.com",
		OK:                true,
		IssuerCN:          "Some Corp Internal CA",
		TrustedPublicRoot: false,
	}
	a, ok := c.toAlert(ev)
	if !ok {
		t.Fatal("expected an alert for a non-public-CA-trusted chain")
	}
	if a.Severity != model.SevMedium {
		t.Errorf("severity = %s, want medium", a.Severity)
	}
}

func TestToAlertConsumerAVIsNotAlerted(t *testing.T) {
	c := newChecker()
	ev := model.CertCheckEvent{
		Domain:              "github.com",
		OK:                  true,
		IssuerCN:            "Kaspersky Anti-Virus Personal Root",
		TrustedPublicRoot:   false,
		SuspectedConsumerAV: "Kaspersky",
	}
	// A consumer-AV match alone (no vendor match, chain not publicly
	// trusted) still falls into the "!TrustedPublicRoot" case today — this
	// test documents that current behavior rather than asserting silence,
	// since consumer AV certs are, definitionally, not publicly trusted
	// either. What must NOT happen is it being scored as high/vendor.
	a, ok := c.toAlert(ev)
	if ok && a.Severity == model.SevHigh {
		t.Error("a consumer-AV-only match must never be scored as high as a real interception vendor")
	}
}

func TestToAlertCleanProbeIsSilent(t *testing.T) {
	c := newChecker()
	ev := model.CertCheckEvent{
		Domain:            "github.com",
		OK:                true,
		IssuerCN:          "DigiCert",
		TrustedPublicRoot: true,
	}
	if _, ok := c.toAlert(ev); ok {
		t.Error("a clean, publicly-trusted probe should not raise an alert")
	}
}

func TestToAlertFailedProbeIsSilent(t *testing.T) {
	c := newChecker()
	ev := model.CertCheckEvent{Domain: "github.com", OK: false, Error: "dial timeout"}
	if _, ok := c.toAlert(ev); ok {
		t.Error("a probe that failed to even connect should not raise a security alert")
	}
}

func TestTrackBaselineDetectsDrift(t *testing.T) {
	c := newChecker()

	first := model.CertCheckEvent{Domain: "github.com", IssuerCN: "DigiCert", RootSubject: "DigiCert Global Root", TrustedPublicRoot: true}
	c.trackBaseline(&first)
	if first.Changed {
		t.Error("first-ever sighting of a domain must not be flagged as a change")
	}

	same := model.CertCheckEvent{Domain: "github.com", IssuerCN: "DigiCert", RootSubject: "DigiCert Global Root", TrustedPublicRoot: true}
	c.trackBaseline(&same)
	if same.Changed {
		t.Error("an identical (issuer, root) on the next check must not be flagged as a change")
	}

	drifted := model.CertCheckEvent{Domain: "github.com", IssuerCN: "Some Corp Internal CA", RootSubject: "Some Corp Root", TrustedPublicRoot: true}
	c.trackBaseline(&drifted)
	if !drifted.Changed {
		t.Error("a different (issuer, root) for a previously-seen domain must be flagged as a change")
	}
}

func TestTrackBaselineIgnoresUntrustedChains(t *testing.T) {
	c := newChecker()

	good := model.CertCheckEvent{Domain: "github.com", IssuerCN: "DigiCert", RootSubject: "DigiCert Global Root", TrustedPublicRoot: true}
	c.trackBaseline(&good)

	// An untrusted (e.g. actively-intercepted) probe must never get to
	// overwrite the baseline — otherwise a MITM proxy that stays on
	// forever would "become the new normal" after one cycle and stop
	// being flagged as drift.
	mitm := model.CertCheckEvent{Domain: "github.com", IssuerCN: "Evil Corp CA", RootSubject: "Evil Corp Root", TrustedPublicRoot: false}
	c.trackBaseline(&mitm)
	if mitm.Changed {
		t.Error("Changed should only ever be computed for chains that themselves verified against the public-CA pool")
	}

	backToNormal := model.CertCheckEvent{Domain: "github.com", IssuerCN: "DigiCert", RootSubject: "DigiCert Global Root", TrustedPublicRoot: true}
	c.trackBaseline(&backToNormal)
	if backToNormal.Changed {
		t.Error("baseline must still be DigiCert (the MITM probe must not have overwritten it)")
	}
}
