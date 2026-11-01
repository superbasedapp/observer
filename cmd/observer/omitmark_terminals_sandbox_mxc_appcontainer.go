//go:build sbo_omit_terminals_sandbox_mxc_appcontainer || sbo_omit_terminals_sandbox_mxc || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// The build reports terminals.sandbox.mxc.appcontainer as compiled out (L1) wherever its own omit tag or
// an ancestor's removes it, as every other L1 component's omit file does, so
// `observer components status` and the distro proof (sbo-components proof)
// list it as omitted rather than as left out by the distro's defaults
// (RB1 gate: the minimal and developer distro proofs failed without it).
func init() { components.MarkOmitted("terminals.sandbox.mxc.appcontainer") }
