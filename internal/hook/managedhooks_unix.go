//go:build unix

package hook

import "os"

// managedHooksOwnerUntrusted is the trust rule of an administrator hooks
// file (and its directory) on Linux and macOS: root-owned and not writable
// by group or others, the IBM Bob policy rule.
func managedHooksOwnerUntrusted(path string, fi os.FileInfo) string {
	return ibmBobOwnerUntrusted(path, fi)
}
