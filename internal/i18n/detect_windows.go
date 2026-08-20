//go:build windows

package i18n

import "syscall"

// GetUserDefaultUILanguage isn't wrapped by golang.org/x/sys/windows (the
// dependency already used elsewhere in this codebase for Win32 calls), so
// this reaches straight for kernel32 via syscall — the same pattern
// cmd/netwatch/elevate_windows.go and privilege_windows.go already use for
// APIs that package doesn't cover.
var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGetUserDefaultUILanguage = kernel32.NewProc("GetUserDefaultUILanguage")
)

// primaryLangID masks a LANGID down to its low-order PRIMARYLANGID bits, per
// the Win32 MAKELANGID layout (sublanguage in the high byte, primary
// language in the low 10 bits).
const primaryLangIDMask = 0x3ff

// Primary language IDs for the languages this tool supports translating
// into, from the Win32 winnt.h LANG_* constants.
const (
	langChinese = 0x04
	langGerman  = 0x07
)

// DetectSystemLang maps the current Windows user's UI language to one of
// this tool's supported languages, defaulting to English for anything else
// — including the call itself failing, which GetUserDefaultUILanguage never
// really does (it's documented to always return *some* LANGID), but a
// zero-value fallback costs nothing to be defensive about.
func DetectSystemLang() Lang {
	ret, _, _ := procGetUserDefaultUILanguage.Call()
	langID := uint16(ret)
	switch langID & primaryLangIDMask {
	case langChinese:
		return ZH
	case langGerman:
		return DE
	default:
		return EN
	}
}
