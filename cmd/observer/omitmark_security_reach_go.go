//go:build sbo_omit_security_reach_go || sbo_omit_security

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// The build reports security.reach.go as compiled out (L1) wherever its own
// omit tag or the security module's removes it, as every other L1
// component's omit file does, so `observer components status` and the
// distro proof (sbo-components proof) list it as omitted rather than as
// left out by the distro's defaults.
func init() { components.MarkOmitted("security.reach.go") }
