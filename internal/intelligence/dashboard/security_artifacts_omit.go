//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// handleSecurityArtifacts refuses: the artifact folders belong to the
// dependency scanners, which require security.deps, not in this build.
func (s *Server) handleSecurityArtifacts(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}

// handleSecurityReachSource and handleSecurityReachSourceRun refuse: the
// Go source check rides the dependency scanners' seam.
func (s *Server) handleSecurityReachSource(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}

func (s *Server) handleSecurityReachSourceRun(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
