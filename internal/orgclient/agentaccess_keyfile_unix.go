//go:build unix

package orgclient

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// agentAccessKeyFileSupported: the unix build has the O_NOFOLLOW refusal and a
// POSIX owner check, so the hardened file fallback may hold the key.
const agentAccessKeyFileSupported = true

// agentAccessKeyOpenNoFollow makes the kernel refuse a symlinked key file even
// if it is swapped in after the Lstat check.
const agentAccessKeyOpenNoFollow = syscall.O_NOFOLLOW

// checkAgentAccessKeyOwner refuses a path owned by anyone other than this
// process user (root is accepted: a root-owned 0600 file is readable only by a
// process that is already root) - the internal/cloudcred checkOwner rule.
func checkAgentAccessKeyOwner(path string, fi fs.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // unknown stat shape: the mode check is the guarantee
	}
	uid := os.Getuid()
	if uid < 0 {
		return nil
	}
	if int(st.Uid) != uid && st.Uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, not this process's uid %d", path, st.Uid, uid)
	}
	return nil
}
