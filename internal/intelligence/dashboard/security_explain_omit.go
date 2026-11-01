//go:build sbo_omit_security

package dashboard

import "net/http"

// security_explain_omit.go: without the security module the explain route
// answers 404 component_not_installed.
func (s *Server) handleSecurityExplain(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.feedback")
}
