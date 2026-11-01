//go:build (!unix && !windows) || sbo_omit_terminals

package main

// emitOOBLaunchHello is a no-op on non-unix platforms: the daemon's PTY
// launcher spine (and the inherited OOB FD) is unix-only (the native-Windows
// ConPTY path does not wire the trusted control channel). See oob_emit_unix.go.
func emitOOBLaunchHello() func(exitCode int) { return func(int) {} }

// announceOOBSession is a no-op on non-unix platforms (no OOB channel exists).
func announceOOBSession(string) {}

// announceDiscoveredOOBSession is a no-op on non-unix platforms (no OOB channel).
func announceDiscoveredOOBSession(string) {}

// oobChannelActive is always false on non-unix platforms (no OOB channel).
func oobChannelActive() bool { return false }

// oobChannelSpawnedByDaemon is always false here (no OOB channel).
func oobChannelSpawnedByDaemon() bool { return false }
