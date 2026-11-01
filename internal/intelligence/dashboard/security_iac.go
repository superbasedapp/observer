package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
)

// security_iac.go serves the IaC engines on the Code security page (lane
// GATES-SEC): their rows on the data-driven Scanners card and the guided
// install's dialog and POST (/api/security/iac/install). Both come from
// the cmd layer through dashapi.IaC; with no seam (the security module
// compiled out) the rows are absent and the route answers 404.

// iacInstallRequest is the dialog's POST body: the engine and the pin the
// developer saw.
type iacInstallRequest struct {
	Engine string `json:"engine"`
	SHA256 string `json:"sha256"`
}

// handleSecurityIaCInstall is GET (the rows with each install plan and a
// confirm token) and POST (the consent and the install).
func (s *Server) handleSecurityIaCInstall(w http.ResponseWriter, r *http.Request) {
	iac := s.opts.IaC
	if iac == nil || iac.Rows == nil || iac.Install == nil {
		writeCompiledOut(w, "security.scan.trivy")
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"engines": iac.Rows(r.Context()), "confirm_token": setConfirmCookie(w, r)})
	case http.MethodPost:
		if !requireConfirmToken(w, r) {
			return
		}
		var req iacInstallRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Engine == "" || req.SHA256 == "" {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "detail": "engine and sha256 are required"})
			return
		}
		if err := iac.Install(r.Context(), req.Engine, req.SHA256); err != nil {
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "install_refused", "detail": err.Error()})
			return
		}
		writeJSON(w, map[string]string{"status": "installed"})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
