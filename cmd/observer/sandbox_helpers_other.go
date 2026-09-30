//go:build !linux

package main

import (
	"fmt"
	"os"
)

// The bwrap sandbox (and so its network tier) is Linux + WSL2 only. On any
// other OS the helpers refuse outright; the daemon never plans them there
// (sandbox.Probe reports unsupported_platform first).

func runSandboxHost(_ []string) int  { return sandboxHelperUnsupported() }
func runSandboxGuest(_ []string) int { return sandboxHelperUnsupported() }

func sandboxHelperUnsupported() int {
	fmt.Fprintln(os.Stderr, "observer sandbox: the sandbox network helpers are Linux-only")
	return 125
}
