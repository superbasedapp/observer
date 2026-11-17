//go:build sbo_omit_security || sbo_omit_security_dast

package dashboard

import "net/http"

// The DAST card's routes refuse: security.dast is not in this build.

func (s *Server) handleSecurityDAST(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.dast")
}

func (s *Server) handleSecurityDASTAccept(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.dast")
}

func (s *Server) handleSecurityDASTRun(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.dast")
}
