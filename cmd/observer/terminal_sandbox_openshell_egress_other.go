//go:build !linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
)

// terminal_sandbox_openshell_egress_other.go: the openshell row runs on
// Linux only, so off Linux there is no gateway config to read, no receiver
// and no host helper (lane O3).

// openShellOCSFExport is unknown off Linux.
func openShellOCSFExport(path string) sandboxopenshell.OCSFExport {
	return sandboxopenshell.OCSFExport{Path: path}
}

// openShellOCSFReceiverFacts finds no receiver off Linux.
func openShellOCSFReceiverFacts(string) sandboxopenshell.OCSFReceiverFacts {
	return sandboxopenshell.OCSFReceiverFacts{}
}

// openShellEnsureOCSF starts nothing off Linux.
func openShellEnsureOCSF(string, string, *slog.Logger) bool { return false }

// openShellReleaseOCSF stops nothing off Linux.
func openShellReleaseOCSF() {}
