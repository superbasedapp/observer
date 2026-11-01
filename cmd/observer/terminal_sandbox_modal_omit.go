//go:build sbo_omit_terminals_sandbox_modal || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_modal_omit.go is the Modal driver's twin in a build
// without it (-tags sbo_omit_terminals_sandbox_modal, or a build without the
// sandbox module): no row registers, so the modal backend reads
// not_in_build, and neither the wire client nor Modal's Go SDK is linked.
func init() { components.MarkOmitted("terminals.sandbox.modal") }
