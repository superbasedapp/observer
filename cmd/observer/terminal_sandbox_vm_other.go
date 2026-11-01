//go:build !linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_other.go: the microVM row runs on Linux and WSL2
// only; here the probe stops at its platform row without reading anything
// and every helper verb refuses.

func vmProbeEnv(*sandboxRuntime, config.TerminalSandboxVMConfig) sandboxvm.ProbeEnv {
	return sandboxvm.ProbeEnv{GOOS: runtime.GOOS}
}

// vmLookProgramFor finds nothing off Linux.
func vmLookProgramFor(string) (string, error) {
	return "", errors.New("the microVM row runs on Linux and WSL2 only")
}

// vmHelperVerbs lists the helper verbs.
var vmHelperVerbs = []string{vmHostVerb, vmInitVerb}

// registerVMHelpers registers the helper verbs as refusals.
func registerVMHelpers() {
	for _, verb := range vmHelperVerbs {
		sandboxHelperFuncs[verb] = func([]string) int {
			fmt.Fprintln(os.Stderr, "observer sandbox (cloud-hypervisor): runs on Linux and WSL2 only")
			return 125
		}
	}
}

// vmSweep has nothing to sweep off Linux.
func vmSweep(string) {}
