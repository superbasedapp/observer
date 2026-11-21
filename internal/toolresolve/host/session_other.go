//go:build !unix

package host

import "os/exec"

// detachSession is a no-op off unix: there is no POSIX login shell to
// capture on a Windows daemon (NewEnv leaves LoginPath nil there), and no
// terminal process group for a capture to take (tracker F-031).
func detachSession(*exec.Cmd) {}
