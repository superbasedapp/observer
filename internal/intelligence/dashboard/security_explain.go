//go:build !sbo_omit_security

package dashboard

import (
	"errors"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_explain.go serves POST /api/security/findings/{id}/explain, the
// Findings tab's Explain button (component security.feedback, security
// pillar plan section 5.11 (b), lane sec-h): the configured judge's
// advisory explanation of one finding through the injected seam
// (Options.SecurityExplain). Owner-local with the confirm token: the call
// may leave the machine (through the judge client's secure egress), so it
// is never a remote viewer's action. It changes nothing on the finding.

// handleSecurityExplain serves POST /api/security/findings/{id}/explain.
func (s *Server) handleSecurityExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	explain := s.opts.SecurityExplain
	if explain == nil {
		writeCompiledOut(w, "security.feedback")
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	id := r.PathValue("id")
	if id == "" || len(id) > 64 {
		http.Error(w, "bad finding id", http.StatusBadRequest)
		return
	}
	ex, err := explain(r.Context(), id)
	switch {
	case errors.Is(err, dashapi.ErrExplainNotSelected):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, dashapi.ErrExplainUnknownFinding):
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	writeJSON(w, ex)
}
