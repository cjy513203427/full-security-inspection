//go:build !windows

package i18n

// DetectSystemLang has no non-Windows implementation (this tool is
// Windows-only, per CLAUDE.md) — this stub exists solely so the i18n
// package itself stays buildable/vettable with `go vet ./...` run from a
// non-Windows GOOS, same as internal/config and internal/model do.
func DetectSystemLang() Lang {
	return EN
}
