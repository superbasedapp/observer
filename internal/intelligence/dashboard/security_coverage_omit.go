//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecurityCoverage refuses: the dependency coverage reads the
// dependency scanners' tables, which require security.deps, not in this
// build.
func (s *Server) handleSecurityCoverage(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
