//go:build sbo_omit_terminals_sandbox_landlock || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_landlock_omit.go stands in for the Landlock-only driver
// in a build without it (-tags sbo_omit_terminals_sandbox_landlock, or a
// build without the sandbox module): no driver registers, so the
// process_lite row drops at S1 (not_in_build), and internal/sandboxlandlock
// is not linked.
func init() { components.MarkOmitted("terminals.sandbox.landlock") }
