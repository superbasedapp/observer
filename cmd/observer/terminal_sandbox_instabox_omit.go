//go:build sbo_omit_terminals_sandbox_instabox || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_instabox_omit.go is the InstaBox driver's twin in a
// build without it (-tags sbo_omit_terminals_sandbox_instabox, or a build
// without the sandbox module): no row registers, so the instabox backend
// reads not_in_build, and the vendor's wire client is not linked.
func init() { components.MarkOmitted("terminals.sandbox.instabox") }
