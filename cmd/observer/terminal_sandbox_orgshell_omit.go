//go:build sbo_omit_terminals_sandbox_openshell_org || sbo_omit_terminals_sandbox_openshell || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_orgshell_omit.go is the org-hosted OpenShell driver's
// twin in a build without it (-tags sbo_omit_terminals_sandbox_openshell_org,
// or a build without the sandbox module): no row registers, so the
// openshell-org backend reads not_in_build, and neither the OpenShell SDK
// nor the wire client is linked.
func init() { components.MarkOmitted("terminals.sandbox.openshell-org") }
