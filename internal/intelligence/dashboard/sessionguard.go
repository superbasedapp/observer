package dashboard

import (
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// handleSessionGuardEvents serves GET /api/session/<id>/guard — the
// session-scoped guard-verdict feed the Messages tab interleaves into its
// timeline (LOC/guardmsg/APM followups plan,
// docs/plans/loc-guardmsg-apm-followups-2026-09-21.md, Item 2).
//
// Reuses store.LoadGuardEventsForSessionWithMessageAnchor — session-scoped,
// unbounded time window (guard verdicts are low-volume by design; allow
// verdicts never persist), plus a LEFT JOIN resolving each action-anchored
// event's upstream message_id/turn_index — and toGuardEventJSONAnchored
// (guard.go) so this feed and the Security page's global timeline can
// never drift on wire shape.
//
// DEFAULT-FILTERED TO BLOCKS, TOOL-CALL AND PROMPT-GUARD ALIKE. Operator
// decision 2026-09-21 (superseding the prior scoped-to-exclude-prompt-guard
// design): prompt-guard blocks (R-172 secrets / R-190 PII,
// event_kind=user_prompt) are now INCLUDED in this feed — the frontend
// renderers (web's MessagesTab.tsx, web2's Sessions.tsx) distinguish them
// from tool-call verdicts with a distinct "prompt guard" label, keyed off
// event_kind=="user_prompt" or rule_id R-172/R-190. isPolicyBlock is now a
// pure anti-flood gate: enforced OR decided deny/ask (observe-mode
// deny/ask still means the policy WOULD have blocked); informational
// flag/unenforced rows are still dropped so the strip doesn't drown in
// low-signal noise. Live-DB grounding (2026-09-21): on this observe-mode
// estate the rows that pass the gate are today mostly prompt-guard
// verdicts (tool-call policy is still in flag/observe mode) — that's
// expected, and now shown rather than hidden. Pass ?include_flags=1 to see
// the full unfiltered session history (matching what /api/guard/events
// shows globally).
func (s *Server) handleSessionGuardEvents(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	includeFlags := r.URL.Query().Get("include_flags") == "1"
	rows, err := store.New(s.opts.DB).LoadGuardEventsForSessionWithMessageAnchor(r.Context(), sessionID)
	if err != nil {
		writeErr(w, fmt.Errorf("session guard events: %w", err))
		return
	}
	// Same org-granted override posture the global /api/guard/events
	// timeline stamps on every row (one cached bundle read per request),
	// so the Messages-tab strip and the Security page never disagree on
	// whether a block can still be overridden.
	orgOverride := s.orgOverrides(r.Context())
	out := make([]guardEventJSON, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		if !includeFlags && !isPolicyBlock(row) {
			continue
		}
		ev := toGuardEventJSONAnchored(row)
		ev.Overridable, ev.OrgLocked = orgOverride.For(row.RuleID)
		out = append(out, ev)
	}
	writeJSON(w, map[string]any{"events": out, "count": len(out)})
}

// isPolicyBlock reports whether a guard verdict represents an actual
// policy block worth surfacing inline by default — tool-call and
// prompt-guard verdicts alike (operator decision 2026-09-21; the frontend
// labels the two distinctly, see the handler doc comment). The gate is
// purely anti-flood: enforced or decided deny/ask (observe-mode deny/ask
// still means the policy WOULD have blocked). Informational flag/unenforced
// rows are dropped by default; ?include_flags=1 on the handler bypasses
// this gate entirely.
func isPolicyBlock(row *store.GuardEventAnchoredRow) bool {
	return row.Enforced || row.Decision == "deny" || row.Decision == "ask"
}
