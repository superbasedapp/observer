//go:build windows

package keystore

import (
	"strings"
	"syscall"
	"unsafe"
)

var procGetFinalPathNameByHandleW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

// resolveExisting is the final path of an existing file or folder: every
// symbolic link and junction resolved and every 8.3 short name expanded
// (GetFinalPathNameByHandle on a handle opened with backup semantics, which
// a folder needs), without the \\?\ prefix. ok is false when p cannot be
// opened.
func resolveExisting(p string) (string, bool) {
	pp, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return "", false
	}
	h, err := syscall.CreateFile(pp, 0, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", false
	}
	defer func() { _ = syscall.CloseHandle(h) }()
	buf := make([]uint16, 4096)
	// FILE_NAME_NORMALIZED | VOLUME_NAME_DOS is 0.
	n, _, _ := procGetFinalPathNameByHandleW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
	if n == 0 || n >= uintptr(len(buf)) {
		return "", false
	}
	s := syscall.UTF16ToString(buf[:n])
	switch {
	case strings.HasPrefix(s, `\\?\UNC\`):
		s = `\\` + s[len(`\\?\UNC\`):]
	case strings.HasPrefix(s, `\\?\`):
		s = s[len(`\\?\`):]
	}
	return s, true
}
