//go:build windows

package procinfo

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// checkSignature reports whether path carries a valid Authenticode
// signature and, if so, the signer's certificate subject.
//
// This shells out to PowerShell's Get-AuthenticodeSignature instead of
// hand-rolling a WinVerifyTrust call: WinVerifyTrust needs a hand-built
// WINTRUST_DATA/WINTRUST_FILE_INFO struct whose field layout/padding is
// easy to get subtly wrong from Go and would fail silently or crash — for
// a security tool a slower-but-correct check beats a fast-but-unreliable
// one. Results are cached by the caller so this only runs once per unique
// image path.
func checkSignature(path string) (signed bool, signer string) {
	if path == "" {
		return false, ""
	}
	script := fmt.Sprintf(
		`try { $s = Get-AuthenticodeSignature -LiteralPath %s -ErrorAction Stop; `+
			`"$($s.Status)|$($s.SignerCertificate.Subject)" } catch { "Error|" }`,
		psSingleQuote(path))

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return false, ""
	}
	line := strings.TrimSpace(string(out))
	parts := strings.SplitN(line, "|", 2)
	status := parts[0]
	if len(parts) > 1 {
		signer = parts[1]
	}
	return status == "Valid", signer
}

func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
