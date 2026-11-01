//go:build sbo_omit_security

package dashboard

import "net/http"

// security_exceptions_omit.go is the off side of security_exceptions.go:
// with sbo_omit_security the exception and baseline routes answer 404
// component_not_installed.

// handleSecurityExceptions refuses: security is not in this build.
func (s *Server) handleSecurityExceptions(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityExceptionRevoke refuses: security is not in this build.
func (s *Server) handleSecurityExceptionRevoke(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityBaseline refuses: security is not in this build.
func (s *Server) handleSecurityBaseline(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityEditor refuses: security is not in this build.
func (s *Server) handleSecurityEditor(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityScanHistory refuses: security is not in this build.
func (s *Server) handleSecurityScanHistory(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityGithooks refuses: security is not in this build.
func (s *Server) handleSecurityGithooks(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}
