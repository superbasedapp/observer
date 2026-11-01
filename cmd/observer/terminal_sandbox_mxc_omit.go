//go:build sbo_omit_terminals_sandbox_mxc || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_mxc_omit.go stands in for the mxc-process driver in a
// build without it (-tags sbo_omit_terminals_sandbox_mxc, or a build
// without the sandbox module): no driver registers, so the mxc-process row
// drops at S1 (not_in_build), internal/sandboxmxc and
// internal/sandboxmxcdll are not linked, and the release jobs bundle no MXC
// file for such a distro.
func init() { components.MarkOmitted("terminals.sandbox.mxc") }
