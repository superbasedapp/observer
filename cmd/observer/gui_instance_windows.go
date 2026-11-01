//go:build windows

package main

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// platformGUIInstanceRunning walks a ToolHelp process snapshot for a process
// whose image name is bin's (Code.exe, idea64.exe) in this process's
// session: an instance in another user's session would not receive this
// launch. Opens no process handle.
func platformGUIInstanceRunning(bin string) bool {
	image := guiInstanceImage(bin)
	if image == "" {
		return false
	}
	var mySession uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &mySession); err != nil {
		return false
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snap) //nolint:errcheck // best-effort close of a read snapshot
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if !strings.EqualFold(windows.UTF16ToString(entry.ExeFile[:]), image) {
			continue
		}
		var session uint32
		if windows.ProcessIdToSessionId(entry.ProcessID, &session) == nil && session == mySession {
			return true
		}
	}
	return false
}
