package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// handleSessionMCPCalls serves GET /api/session/<id>/mcp-calls - the node
// session-detail MCP panel (Agent Access P11(a), doc3 §11.12b (a), R10.7 /
// R11.8). One row per de-duplicated MCP call the node relay recorded for the
// session, each carrying its derived correlation:
//
//	correlation.confidence  exact | inferred   (none never attaches)
//	correlation.level       action | turn | session
//	correlation.method      the rules-table row that produced it
//	correlation.action_key  the matched action's source_event_id (tool-use id)
//	correlation.turn_index / message_id / prompt_key  where it sits in the timeline
//
// The derivation is internal/mcpintel/correlate - the SAME one the org
// drawer (GET /api/org/sessions/{id}/mcp-calls) runs over the pushed copies,
// so node and org never disagree on a call's link. Read-only; args / result
// payloads are what the relay captured at its capture level (node-local).
func (s *Server) handleSessionMCPCalls(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	res, err := store.New(s.opts.DB).LoadSessionMCPCalls(r.Context(), sessionID)
	if err != nil {
		writeErr(w, fmt.Errorf("session mcp calls: %w", err))
		return
	}
	writeJSON(w, res)
}
