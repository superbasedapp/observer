//go:build sbo_omit_terminals_sandbox_openshell || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_openshell_omit.go stands in for the OpenShell driver in a
// build without it (-tags sbo_omit_terminals_sandbox_openshell, or a build
// without the sandbox module): no driver registers, so the openshell row
// drops at S1 (not_in_build), and internal/sandboxopenshell is not linked.
func init() { components.MarkOmitted(openShellComponentID) }

// openShellComponentID is the OpenShell driver's component id.
const openShellComponentID = "terminals.sandbox.openshell"
