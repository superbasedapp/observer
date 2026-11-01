//go:build !unix && !windows

package hook

import "os"

// managedHooksOwnerUntrusted: no trust rule is known on this OS, so an
// administrator hooks file is never relied on here.
func managedHooksOwnerUntrusted(path string, _ os.FileInfo) string {
	return path + " ownership is not checked on this OS"
}
