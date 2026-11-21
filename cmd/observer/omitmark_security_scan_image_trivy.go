//go:build sbo_omit_security_scan_image_trivy || sbo_omit_security_scan_trivy || sbo_omit_security_deps || sbo_omit_security

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// The build reports security.scan.image.trivy as compiled out (L1) wherever
// its own omit tag or one that removes what it needs (the Trivy binary's
// row, security.deps, the security module) removes it, as every other L1
// component's omit file does, so `observer components status` and the
// distro proof list it as omitted rather than as left out by the distro's
// defaults.
func init() { components.MarkOmitted("security.scan.image.trivy") }
