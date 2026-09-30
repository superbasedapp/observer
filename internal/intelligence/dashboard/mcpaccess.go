package dashboard

import (
	"fmt"
	"net/http"
)

// mcpAccessUnavailable is the body GET /api/mcp-access/status answers when
// no MCPAccessStatus seam is wired (a standalone `observer dashboard`, a
// test server): an honest "this process cannot say", never a 404 that a
// client would misread as an older daemon.
type mcpAccessUnavailable struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
}

// mcpAccessNotWiredReason is the Reason of the unavailable body.
const mcpAccessNotWiredReason = "MCP access status is served by the observer daemon (observer start); this dashboard process has no relay"

// handleMCPAccessStatus serves GET /api/mcp-access/status - the node
// Security page's "MCP access" section and the VS Code "MCP access" status
// item (Agent Access P10, doc3 §15 / §12.7 / §12.8). Read-only: the seam
// composes the relay status, approved servers, the client x transport x
// method coverage matrix, the effective state and the org connect target
// (cmd/observer/mcp_access_dashboard.go). It makes no network call and
// writes nothing. ?verify=1 also walks the relay's decision-record chain
// (the page asks for it; the polled status item does not).
func (s *Server) handleMCPAccessStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.MCPAccessStatus == nil {
		writeJSON(w, mcpAccessUnavailable{Available: false, Reason: mcpAccessNotWiredReason})
		return
	}
	verify := r.URL.Query().Get("verify") == "1"
	v, err := s.opts.MCPAccessStatus(r.Context(), verify)
	if err != nil {
		writeErr(w, fmt.Errorf("mcp access status: %w", err))
		return
	}
	writeJSON(w, v)
}
