package main

import "sync"

// box_detect.go is the one seam through which a sandbox driver recognises,
// once per process, that this process runs inside one of its own boxes
// (the MXC row on Windows: terminal_sandbox_mxc_windows.go, audit finding
// F1 of the SBX-P6 merge). No other build registers anything, so every
// caller there sees exactly the state it had before the seam existed.

var (
	// boxDetect is set from init by a driver that can recognise its own
	// box; it runs at most once, from ensureBoxDetected.
	boxDetect func()
	// boxArgvRewrite, when a recognised box sets it, rewrites this
	// process's own argv in memory (never the command line the OS keeps).
	boxArgvRewrite func([]string) []string
	boxDetectOnce  sync.Once
	// boxStartRefusal, when a recognised box sets it, is why this process
	// must not go on (the MXC box's UI limits could not be put in force,
	// RERUN2 D2): main prints it and exits before any command runs.
	boxStartRefusal string
)

// ensureBoxDetected runs the driver's box detection once.
func ensureBoxDetected() {
	boxDetectOnce.Do(func() {
		if boxDetect != nil {
			boxDetect()
		}
	})
}

// boxArgs is args after a recognised box's in-memory rewrite (args itself
// everywhere else).
func boxArgs(args []string) []string {
	ensureBoxDetected()
	if boxArgvRewrite == nil {
		return args
	}
	return boxArgvRewrite(args)
}
