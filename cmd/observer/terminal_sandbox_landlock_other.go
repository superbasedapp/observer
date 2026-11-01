//go:build !linux && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/sandboxlandlock"
)

// terminal_sandbox_landlock_other.go: process_lite (Landlock) runs on Linux
// only. Off Linux the probe answers unsupported_platform without reading
// anything, and the exec step refuses.

// landlockProbeEnv is the probe's facts off Linux: no host the row runs on.
func landlockProbeEnv() sandboxlandlock.ProbeEnv {
	return sandboxlandlock.ProbeEnv{Host: sandboxlandlock.HostOther}
}

// runLandlockExec refuses off Linux.
func runLandlockExec(_ []string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (process_lite): Landlock runs on Linux only")
	return 1
}
