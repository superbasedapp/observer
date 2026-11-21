package dashboard

import (
	"fmt"
	"net/http"
)

// promptJudgeNotWiredReason is the Reason of the unavailable body
// GET /api/guard/prompt/judge answers when no PromptJudgeStatus seam is wired
// (a standalone `observer dashboard`, a test server).
const promptJudgeNotWiredReason = "the organization's prompt judge status is served by the observer daemon (observer start); this dashboard process cannot read it"

// handlePromptJudgeStatus serves GET /api/guard/prompt/judge, the Security
// page's "Organization prompt judge" card (lane adm-p2). Read-only: the seam
// composes the same facts `observer guard status` prints
// (cmd/observer/planeb_admission_dashboard.go). It makes no network call
// and writes nothing; nothing it returns is prompt text.
func (s *Server) handlePromptJudgeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.PromptJudgeStatus == nil {
		writeJSON(w, mcpAccessUnavailable{Available: false, Reason: promptJudgeNotWiredReason})
		return
	}
	v, err := s.opts.PromptJudgeStatus(r.Context())
	if err != nil {
		writeErr(w, fmt.Errorf("prompt judge status: %w", err))
		return
	}
	writeJSON(w, v)
}
