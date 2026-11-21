//go:build sbo_omit_integration_shell_wrap

package dashboard

import "net/http"

// shellwrap_omit.go is the off side of shellwrap.go: in a `-tags
// sbo_omit_integration_shell_wrap` build (component integration.shell-wrap
// compiled out) the Settings > Session attach "Command wrapping" routes stay
// registered and answer 404 component_not_installed, reason not_compiled,
// and this package does not import internal/shellwrap or
// internal/shellwrapsvc (lane MP-L1E, T-715). The shim guard every launcher
// relies on is core (internal/shimguard).

// handleShellWrapStatus refuses: integration.shell-wrap is not in this build.
func (s *Server) handleShellWrapStatus(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "integration.shell-wrap")
}

// handleShellWrapApply refuses: integration.shell-wrap is not in this build.
func (s *Server) handleShellWrapApply(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "integration.shell-wrap")
}

// handleShellWrapDisable refuses: integration.shell-wrap is not in this build.
func (s *Server) handleShellWrapDisable(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "integration.shell-wrap")
}
