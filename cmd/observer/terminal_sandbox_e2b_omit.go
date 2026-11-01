//go:build sbo_omit_terminals_sandbox_e2b || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_e2b_omit.go is the E2B driver's twin in a build without
// it (-tags sbo_omit_terminals_sandbox_e2b, or a build without the sandbox
// module): no row registers, so the e2b backend reads not_in_build, and the
// vendor's wire client is not linked.
func init() { components.MarkOmitted("terminals.sandbox.e2b") }
