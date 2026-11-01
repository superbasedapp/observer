package dashboard

import (
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// handleTerminalProjectPolicy implements GET /api/terminal/project-policy
// ?dir=<path> (lane sec-p2b): whether the organization's project rules
// apply to the directory a New Terminal launch will run in. It reads only
// what the cmd-side seam reads (the daemon's match record and the signed
// mapping); it never runs git and never writes. With no seam, no directory,
// or a node that holds no project delivery, it answers shown=false and the
// dialog shows no line.
func (s *Server) handleTerminalProjectPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir := strings.TrimSpace(r.URL.Query().Get("dir"))
	if s.opts.ProjectPolicy == nil || dir == "" {
		writeJSON(w, dashapi.ProjectPolicyLine{})
		return
	}
	writeJSON(w, s.opts.ProjectPolicy(dir))
}
