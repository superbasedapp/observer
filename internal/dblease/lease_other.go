//go:build !unix && !windows

package dblease

// available is false off unix and windows (plan9, js, wasip1): there is
// no non-blocking advisory-lock syscall wired here. Mirrors the unix/other
// split in cmd/observer/prune_diskcheck_{unix,other}.go and
// internal/orgserver/policykey_open_{unix,other}.go.
const available = false

// tryAcquireFile always succeeds off unix and windows: there is no cross-process
// coordination on this platform, so every caller proceeds as if it held
// the lease (behavior is unchanged from before dblease existed there).
func tryAcquireFile(_ string) (release func(), acquired bool, err error) {
	return noop, true, nil
}
