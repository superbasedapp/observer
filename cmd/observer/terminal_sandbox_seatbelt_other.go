//go:build !darwin && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
)

// terminal_sandbox_seatbelt_other.go: the Seatbelt row runs on macOS only.
// Here the probe ladder stops at its platform row (unsupported_platform)
// without reading anything, and the helper verbs refuse.

func seatbeltProbeEnv() sandboxsbpl.ProbeEnv { return sandboxsbpl.ProbeEnv{GOOS: runtime.GOOS} }

func runSeatbeltHost([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (seatbelt): runs on macOS only")
	return 125
}

func runSeatbeltSelfTest([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox-seatbelt-selftest: runs on macOS only")
	return 125
}
