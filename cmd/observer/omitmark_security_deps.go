//go:build sbo_omit_security_deps || sbo_omit_security

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// The build reports security.deps as compiled out (L1) wherever its own omit tag or
// an ancestor's removes it, as every other L1 component's omit file does, so
// `observer components status` and the distro proof (sbo-components proof)
// list it as omitted rather than as left out by the distro's defaults
// (RB1 gate: the minimal and developer distro proofs failed without it).
func init() { components.MarkOmitted("security.deps") }
