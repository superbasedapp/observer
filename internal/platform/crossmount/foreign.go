package crossmount

import (
	"path/filepath"
	"strings"
)

// UnderForeignHome reports whether path lies under one of the non-native
// homes in homes (normally the result of AllHomes): both bridge
// directions, /mnt/c/Users/<u> on WSL2 and \\wsl.localhost\<distro>\home\<u>
// on Windows. The native home and a home with an empty Path are skipped.
//
// The match is a plain string prefix: the home path followed by either the
// OS-native separator or a forward slash, because a /mnt/c mount uses
// forward slashes whatever the foreign OS is. Nothing is cleaned or case
// folded, unlike PathUnder.
//
// It is the one foreign-mount predicate the SQLite-backed adapters share to
// decide whether a store must be read through a filtered local mirror
// (mirrorbase.StageIfForeign) instead of being opened in place.
func UnderForeignHome(path string, homes []HomeRoot) bool {
	sep := string(filepath.Separator)
	for _, h := range homes {
		if h.Origin == "native" || h.Path == "" {
			continue
		}
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}
