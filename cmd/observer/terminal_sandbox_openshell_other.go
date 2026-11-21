//go:build !linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_other.go: the openshell row runs on native
// Linux only. Off Linux the probe answers unsupported_platform at row P1
// before any program runs (the host facts below are never read), and the
// helper verbs refuse.

// openShellHostFacts is the host facts off Linux: none.
func openShellHostFacts() openShellHostFactsT { return openShellHostFactsT{} }

// openShellStatBinaryFacts reads nothing off Linux: the trust rule then
// refuses (row P1 refuses first anyway).
func openShellStatBinaryFacts(program, path string) sandboxopenshell.BinaryTrustFacts {
	return sandboxopenshell.BinaryTrustFacts{Program: program, Path: path, Detail: "the openshell row runs on Linux only"}
}

// openShellReadOwned refuses off Linux (the row keeps no state here).
func openShellReadOwned(string, int64) ([]byte, error) {
	return nil, errors.New("terminal_sandbox: the openshell row runs on Linux only")
}

// openShellRemoveSockDir: no socket dir is made off Linux.
func openShellRemoveSockDir(openShellPlanFile) error {
	return errors.New("terminal_sandbox: the openshell row runs on Linux only")
}

// openShellRunHeld: no helper runs off Linux.
func openShellRunHeld(string) bool { return false }

// runOpenShellHost refuses off Linux.
func runOpenShellHost([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (openshell): OpenShell runs on native Linux only")
	return 1
}

// runOpenShellCanary refuses off Linux (the canary runs in a Linux
// container, from a Linux build of this binary).
func runOpenShellCanary([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (openshell canary): OpenShell runs on native Linux only")
	return 1
}

// runOpenShellInit refuses off Linux.
func runOpenShellInit([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (openshell init): OpenShell runs on native Linux only")
	return 1
}
