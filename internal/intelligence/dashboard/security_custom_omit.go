//go:build sbo_omit_security || sbo_omit_security_scan_custom

package dashboard

import "net/http"

// security_custom_omit.go is the off side of security_custom.go: in a build
// without the security module or its security.scan.custom component the
// routes stay registered and answer 404 component_not_installed, and this
// package does not link the custom scanner packages.

// handleSecurityCustom refuses: security.scan.custom is not in this build.
func (s *Server) handleSecurityCustom(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.scan.custom")
}

// handleSecurityCustomSub refuses the same way.
func (s *Server) handleSecurityCustomSub(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.scan.custom")
}
