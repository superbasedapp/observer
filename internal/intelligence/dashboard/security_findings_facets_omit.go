//go:build sbo_omit_security

package dashboard

import "net/http"

// security_findings_facets_omit.go is the off side of
// security_findings_facets.go: without the security module the findings
// facets and groups answer 404 component_not_installed, reason
// not_compiled.

// handleSecurityFindingsFacets refuses: security is not in this build.
func (s *Server) handleSecurityFindingsFacets(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// handleSecurityFindingsGroups refuses: security is not in this build.
func (s *Server) handleSecurityFindingsGroups(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}
