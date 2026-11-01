//go:build sbo_omit_security

package dashboard

import "net/http"

// handleSecurityImportSARIF refuses: the security module is not in this
// build.
func (s *Server) handleSecurityImportSARIF(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security.scan.sarif-import")
}
