//go:build sbo_omit_security

package dashboard

import "net/http"

// security_fix_omit.go: without the security module the "Fix with an agent"
// routes answer 404 component_not_installed.

func (s *Server) handleSecurityFixPlan(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityFixLaunch(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityFixAttempts(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}
