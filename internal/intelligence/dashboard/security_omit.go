//go:build sbo_omit_security

package dashboard

import "net/http"

// security_omit.go is the off side of security.go: in a `-tags
// sbo_omit_security` build (component security compiled out) the Code
// security routes stay registered and answer 404 component_not_installed,
// reason not_compiled, and this package imports none of the pillar's
// packages.

// handleSecurityStatus refuses: security is not in this build.
func (s *Server) handleSecurityStatus(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityFindings refuses: security is not in this build.
func (s *Server) handleSecurityFindings(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}
