//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecurityScannersDB refuses: the dependency scanners require
// security.deps, which is not in this build.
func (s *Server) handleSecurityScannersDB(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
