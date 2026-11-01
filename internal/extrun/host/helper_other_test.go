//go:build !unix

package host

import "syscall"

// newSessionAttr has no session to leave off Unix.
func newSessionAttr() *syscall.SysProcAttr { return nil }

// ownLimits has no rlimits to print off Unix.
func ownLimits() []string { return nil }

// dieAfterStarted has no trampoline off Unix.
func dieAfterStarted() {}
