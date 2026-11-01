//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep && windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// codeFileID is the file's volume serial number and file index (the digest
// cache's identity), read from a handle opened with no access rights.
func codeFileID(path string, _ os.FileInfo) (string, bool) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var d windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &d); err != nil {
		return "", false
	}
	return fmt.Sprintf("%d:%d:%d", d.VolumeSerialNumber, d.FileIndexHigh, d.FileIndexLow), true
}
