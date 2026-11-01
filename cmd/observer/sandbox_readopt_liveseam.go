//go:build !sbo_omit_terminals

package main

// sandbox_readopt_liveseam.go is the live-run gate's seam for local
// re-adoption (lane GATES-SBX): a run offered for re-adoption, or held
// while an update waits, counts as a live sandboxed run, so a restart or
// an update defers or asks for it as for any other. nil (no count) unless
// the re-adoption files are compiled.
var liveRunsReadoptCount func() int

// readoptLiveExtra is the count the seam adds.
func readoptLiveExtra() int {
	if f := liveRunsReadoptCount; f != nil {
		return f()
	}
	return 0
}

// sandboxDaemonExitMark runs in the daemon's stop just before its PTYs
// close (R-033): it marks the live re-adoptable container runs so their
// helpers keep the container through the hangup that follows. nil unless
// the re-adoption files are compiled.
var sandboxDaemonExitMark func()

// markSandboxRunsForDaemonExit calls the seam when it is set.
func markSandboxRunsForDaemonExit() {
	if f := sandboxDaemonExitMark; f != nil {
		f()
	}
}
