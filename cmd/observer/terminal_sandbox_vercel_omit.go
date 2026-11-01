//go:build sbo_omit_terminals_sandbox_vercel || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_vercel_omit.go is the Vercel Sandbox driver's twin in a
// build without it (-tags sbo_omit_terminals_sandbox_vercel, or a build
// without the sandbox module): no row registers, so the vercel-sandbox
// backend reads not_in_build, and the vendor's wire client is not linked.
func init() { components.MarkOmitted("terminals.sandbox.vercel") }
