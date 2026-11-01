//go:build sbo_omit_security

package dashboard

import "net/http"

// security_orgnotice_omit.go: without the security module nothing is shared
// about code security; the route answers 404 component_not_installed like
// every other security route, and the notice renders nothing.
func (s *Server) handleSecurityOrgNotice(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}
