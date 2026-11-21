//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecuritySBOM refuses: the project inventory belongs to
// security.deps, which is not in this build.
func (s *Server) handleSecuritySBOM(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
