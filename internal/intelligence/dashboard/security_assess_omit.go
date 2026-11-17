//go:build sbo_omit_security

package dashboard

import (
	"net/http"
)

// security_assess_omit.go: without the security module the "Security
// assessments" routes answer 404 component_not_installed.

func (s *Server) handleSecurityAssess(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessPlan(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessLaunch(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessReport(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessImport(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessRequest(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessCancel(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessStop(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessDeleteData(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessValidate(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessModel(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessFix(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

func (s *Server) handleSecurityAssessExport(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "security")
}

// securityAssessBodySandboxed says no assessment launch is sandboxed by its
// route: without the module the route answers 404 and no launch is ever held
// for it.
func securityAssessBodySandboxed(_ []byte) bool { return false }

// securityAssessFixHeld has nothing to add without the security module: the fix
// route answers 404 and no launch is ever held for it.
func (s *Server) securityAssessFixHeld(_ *http.Request, _ []byte) heldExtra {
	return heldExtra{}
}
