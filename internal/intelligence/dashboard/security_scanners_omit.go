//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecurityScanners refuses: the dependency scanners require
// security.deps, which is not in this build.
func (s *Server) handleSecurityScanners(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
