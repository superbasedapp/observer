//go:build !darwin && !linux && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
)

// terminal_sandbox_applecontainer_other.go: the Apple container row runs on
// macOS only (its in-image init on Linux); here the probe stops at the
// platform row and both helper verbs refuse.

func appleProbeEnv(config.TerminalSandboxAppleContainerConfig) sandboxapple.ProbeEnv {
	return sandboxapple.ProbeEnv{GOOS: runtime.GOOS}
}

func appleSweep(string, string, string) {}

func runAppleHost([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (apple-container): runs on macOS only")
	return 125
}

func runAppleInit([]string) int {
	fmt.Fprintln(os.Stderr, "observer "+sandboxapple.InitVerb+": runs inside an Apple container's Linux VM only")
	return 127
}
