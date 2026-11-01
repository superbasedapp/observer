//go:build sbo_omit_terminals_sandbox_seatbelt || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_seatbelt_omit.go stands in for the Seatbelt driver in a
// build without it (-tags sbo_omit_terminals_sandbox_seatbelt, or a build
// without the sandbox module): no driver registers, so the seatbelt row
// drops at S1 (not_in_build), and internal/sandboxsbpl is not linked.
func init() { components.MarkOmitted("terminals.sandbox.seatbelt") }
