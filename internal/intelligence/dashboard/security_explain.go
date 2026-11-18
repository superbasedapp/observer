//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
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
//
// A body of {"fix":true} asks for the suggest-a-fix variant (the drawer's
// "Suggest a fix", `observer security explain --fix`, OS and CI plan section
// 14.8) through Options.SecurityExplainFix: the same flow, caps, advisory
// label and judge routing, with the rule's fix hint and a dependency
// finding's versions added to the prompt (versions only, never advisory
// prose). Any other JSON body, or none, is the plain explanation; a body
// that is not JSON is refused rather than guessed.

// handleSecurityExplain serves POST /api/security/findings/{id}/explain.
func (s *Server) handleSecurityExplain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.SecurityExplain == nil {
		writeCompiledOut(w, "security.feedback")
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	fix, ok := explainWantsFix(r)
	if !ok {
		http.Error(w, "the body is not JSON", http.StatusBadRequest)
		return
	}
	explain := s.opts.SecurityExplain
	if fix {
		explain = s.opts.SecurityExplainFix
	}
	if explain == nil {
		writeCompiledOut(w, "security.feedback")
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
		writeSettingRefusal(w, err, http.StatusConflict)
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

// explainWantsFix reports whether a POST's JSON body sets "fix" true (read
// capped at 4 KB). An empty body is the plain explanation; a body that is not
// JSON is refused (ok false).
func explainWantsFix(r *http.Request) (fix, ok bool) {
	if r.Body == nil {
		return false, true
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(b) > 4096 {
		return false, false
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return false, true
	}
	var body struct {
		Fix bool `json:"fix"`
	}
	if json.Unmarshal(b, &body) != nil {
		return false, false
	}
	return body.Fix, true
}
