package hook

import (
	"path/filepath"
	"runtime"
)

// rowAbs is p, a directory on this host, spelled so the path syntax of
// goos (the OS a test pins for the row) reads it as absolute while this host
// still opens the same directory. A relocation value is judged by the row
// OS's syntax (FU-143), so a Windows row refuses a POSIX temp path as
// relative; on a non-Windows host a Windows row gets "/"+p instead, a
// "//tmp/..." UNC path to Windows that POSIX resolves to p itself. Anything
// else is p unchanged.
func rowAbs(goos, p string) string {
	if goos == "windows" && runtime.GOOS != "windows" && filepath.IsAbs(p) {
		return "/" + p
	}
	return p
}
