//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecurityLookup refuses: the package lookup posture belongs to the
// dependency scanners, which require security.deps, not in this build.
func (s *Server) handleSecurityLookup(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
