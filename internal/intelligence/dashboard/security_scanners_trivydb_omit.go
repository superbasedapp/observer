//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecurityScannersTrivyDB refuses: the Trivy image driver needs
// security.deps, which is not in this build.
func (s *Server) handleSecurityScannersTrivyDB(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
