//go:build unix

package main

import (
	"io/fs"
	"os"
	"syscall"
)

// sdkHeldFileForeignOwner reports whether the SDK-held file belongs to a uid
// other than this process's, which the SDKs refuse (destination.md section
// 6a, unix read rules). An unknown stat shape reads as not foreign.
func sdkHeldFileForeignOwner(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	uid := os.Getuid()
	return uid >= 0 && int64(st.Uid) != int64(uid)
}
