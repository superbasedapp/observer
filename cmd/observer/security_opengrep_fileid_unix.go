//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep && unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// codeFileID is the file's device and inode (the digest cache's identity).
func codeFileID(_ string, fi os.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), true
}
