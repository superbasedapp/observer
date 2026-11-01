//go:build sbo_omit_security || sbo_omit_security_deps

package dashboard

import "net/http"

// security_deps_omit.go is the off side of security_deps.go: in a build
// without the security module or its security.deps component the route
// stays registered and answers 404 component_not_installed.

// handleSecurityDeps refuses: security.deps is not in this build.
func (s *Server) handleSecurityDeps(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.deps")
}
