//go:build sbo_omit_security || sbo_omit_security_trust

package dashboard

import "net/http"

// security_trust_omit.go is the off side of security_trust.go: in a build
// without the security module or its security.trust component the route
// stays registered and answers 404 component_not_installed, and this
// package does not link internal/sectrust.

// handleSecurityTrust refuses: security.trust is not in this build.
func (s *Server) handleSecurityTrust(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.trust")
}
