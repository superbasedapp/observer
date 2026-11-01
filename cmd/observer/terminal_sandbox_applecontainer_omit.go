//go:build sbo_omit_terminals_sandbox_apple_container || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_applecontainer_omit.go stands in for the Apple container
// driver in a build without it (-tags
// sbo_omit_terminals_sandbox_apple_container, or a build without the
// sandbox module): no driver registers, so the apple-container row drops at
// S1 (not_in_build), and internal/sandboxapple is not linked.
func init() { components.MarkOmitted("terminals.sandbox.apple-container") }
