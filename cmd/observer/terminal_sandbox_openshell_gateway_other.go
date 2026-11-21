//go:build !linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/rand"
	"errors"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_gateway_other.go: the managed gateway runs on
// native Linux only. Off Linux probe row P1 refuses before the managed
// step, so these facts are never read; they refuse, never accept.
func openShellGatewayHost() openShellGatewayHostT {
	return openShellGatewayHostT{
		RuntimeDir: func() string { return "" },
		StateFS:    func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriUnknown, "not Linux" },
		RuntimeFS:  func(string) (sandboxopenshell.Tri, string) { return sandboxopenshell.TriNo, "not Linux" },
		PortFree:   func(int) bool { return false },
		Lock:       func(string) (func(), error) { return nil, errors.New("the openshell row runs on Linux only") },
		Rand:       rand.Reader,
	}
}
