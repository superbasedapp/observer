//go:build sbo_omit_security

package dashboard

import "net/http"

// handleSecurityProvenance refuses: the AI change records require the
// security module, which is not in this build.
func (s *Server) handleSecurityProvenance(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.provenance")
}
