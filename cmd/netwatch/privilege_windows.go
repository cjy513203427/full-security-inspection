//go:build windows

package main

import (
	"log"

	"golang.org/x/sys/windows"

	"netwatch/internal/i18n"
)

// enableDebugPrivilege turns on SeDebugPrivilege for the current process
// token. An elevated (Administrator) token *has* this privilege available
// but Windows leaves it disabled by default; without explicitly enabling
// it, even an admin process gets Access Denied opening a handle to certain
// other processes — notably Chrome/Edge's sandboxed renderer and network-
// service child processes, which set a hardened DACL on their own process
// object as part of Chromium's sandbox. That single gap was making the
// tool unable to name Chrome's own subprocesses, which then looked
// identical to "unidentified process reading your cookies" — the false
// positive this exists to avoid. This is the same privilege Process
// Explorer / Task Manager / real EDR agents enable for the same reason.
func enableDebugPrivilege() {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		log.Printf(i18n.T("log.open_token_failed"), err)
		return
	}
	defer token.Close()

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		log.Printf(i18n.T("log.lookup_privilege_failed"), err)
		return
	}

	priv := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	priv.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}

	if err := windows.AdjustTokenPrivileges(token, false, &priv, 0, nil, nil); err != nil {
		log.Printf(i18n.T("log.enable_privilege_failed"), err)
	}
}
