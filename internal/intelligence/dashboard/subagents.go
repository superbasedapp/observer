package dashboard

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// subagents.go — the session-detail sub-agents read model.
//
// The claude-code sub-agent model (migration 010, commit 54a51540) keeps
// every sub-agent's activity on the PARENT's session row flagged
// is_sidechain=1, bracketed by spawn_subagent / subagent_start /
// subagent_stop lifecycle actions. This file turns that flat material into
// per-sub-agent summaries for GET /api/session/<id>/subagents and the
// SessionDetailPanel's Sub-agents section.
//
// Since migration 087 token_usage rows carry the same flag, so the builder
// also accepts sidechain usage rows and folds their tokens + cost into the
// windows — closing commit ad46b05b's honest omission (activity without
// attribution of what it cost).
//
// Grouping rule (pure): a window OPENS on each spawn/start bracket and
// CLOSES on its stop bracket (or stays open — an unterminated sub-agent).
// Sidechain rows inside the open window belong to it.
//
// RETROSPECTIVE WINDOWS (C2 fix, operator-approved 2026-08-22): claude-code
// fires SubagentStop per sub-agent but has NO SubagentStart hook, so
// stop-without-open is the COMMON case, not an anomaly. Each such stop now
// claims the sidechain activity accumulated since the last bracket boundary
// as its own closed window, labeled by the stop's agent_id — instead of
// stranding ~2133/2996 actions of session 1e2f0aa0 in the unattributed
// bucket. A stop with no agent_id and no accumulated activity is still
// skipped (nothing to name, nothing to claim).
//
// Sidechain rows outside any window (before the first stop / after the last
// bracket of any kind) still land in ONE explicit unattributed bucket rather
// than being silently dropped. Label precedence: structured metadata agent_id
// → bracket Target (agent_type / persona name) → ordinal.
//
// Token rows never move the bracket state — only actions open/close windows.
// Each usage row is replayed against the same bracket timeline the action
// pass walked, applying every bracket at or before the row's timestamp;
// retroactive windows emit their open-mark at their computed onset so tokens
// in [onset, stop] bind to the labeled window. A row outside any window lands
// in the same unattributed bucket.

// SubagentSummary is one sub-agent's rolled-up window.
type SubagentSummary struct {
	// SessionID links to the full transcript when the agent has its own session.
	SessionID string `json:"session_id,omitempty"`
	// HookOnly marks lifecycle evidence with no captured transcript activity.
	HookOnly bool `json:"hook_only,omitempty"`
	// StopActionID opens the captured final output through the existing action API.
	StopActionID int64 `json:"stop_action_id,omitempty"`
	// ID is the structured agent identity when capture stamped one (hook
	// agent_id / transcript agentName); "" for time-window-only grouping.
	ID string `json:"id,omitempty"`
	// Label is what the UI shows: the best identity available, falling back
	// to an ordinal ("sub-agent 2").
	Label string `json:"label"`
	// Type is the categorical agent type when known ("Explore",
	// "general-purpose", persona names).
	Type string `json:"type,omitempty"`
	// Start bounds the window; End is zero while still open.
	Start time.Time `json:"start"`
	End   time.Time `json:"end,omitempty"`
	// Open marks a window with no stop bracket yet — the sub-agent may
	// still be running (or its stop event was suppressed as empty-shell).
	Open bool `json:"open"`
	// ActionCount is the sidechain actions attributed to this window,
	// EXCLUDING the bracket rows themselves.
	ActionCount int `json:"action_count"`
	// ErrorCount is the attributed actions with success=false.
	ErrorCount int `json:"error_count"`
	// InputTokens / OutputTokens / CacheReadTokens sum the sidechain
	// token_usage rows attributed to this window (migration 087). Zero for
	// installs whose transcripts predate the flag until a re-ingest heals
	// them (`observer scan --force`).
	InputTokens         int64 `json:"input_tokens,omitempty"`
	OutputTokens        int64 `json:"output_tokens,omitempty"`
	CacheReadTokens     int64 `json:"cache_read_tokens,omitempty"`
	CacheCreationTokens int64 `json:"cache_creation_tokens,omitempty"`
	// CostUSD sums estimated_cost_usd over the same attributed rows. The
	// JSON omits zero so pre-heal installs render exactly as before.
	CostUSD float64 `json:"cost_usd,omitempty"`
}

// SessionSubagentsResponse is the /api/session/<id>/subagents payload.
//
// Since migration 087 each summary also carries the token/cost rollup of
// the sidechain token_usage rows inside its window (input_tokens /
// output_tokens / cache_read_tokens / cost_usd, all omitempty — zero until
// a post-087 ingest or a `observer scan --force` re-parse heals the rows).
type SessionSubagentsResponse struct {
	SessionID string            `json:"session_id"`
	Total     int               `json:"total"`
	Subagents []SubagentSummary `json:"subagents"`
}

// bracketMark records one mutation of the open-window state during the
// action pass, so the token pass can replay the SAME timeline without
// re-walking the actions: open != nil means "window w opened at ts";
// open == nil means "the then-current window closed at ts".
type bracketMark struct {
	ts   time.Time
	open *subagentWindow
}

// subagentWindow is one accumulator: its summary plus the ordinal that
// labels time-window-only groupings ("sub-agent 2").
type subagentWindow struct {
	summary SubagentSummary
	ordinal int
}

// buildSubagentSummaries groups chronological sidechain material into
// per-sub-agent windows. Exported for tests; the handler is a thin wrapper.
// refs drive the window structure (brackets + activity counts); tokens are
// pure payload folded into whichever window is open at their timestamp.
func buildSubagentSummaries(refs []models.SubagentActionRef, tokens []models.SubagentTokenRef) []SubagentSummary {
	b := &subagentBuilder{}
	b.foldActions(refs)
	b.foldTokens(tokens)
	return b.output()
}

// subagentBuilder holds the state the action pass, token pass, and output
// pass thread through together: the windows opened so far, the current one,
// the retrospective-claimable unattributed segment, and the bracket
// timeline the token pass replays. One builder is used per
// buildSubagentSummaries call.
type subagentBuilder struct {
	windows []*subagentWindow
	// unattributed is the current retrospective-claimable segment.
	unattributed          *subagentWindow
	unattributedAggregate *subagentWindow
	cur                   *subagentWindow
	marks                 []bracketMark
	lastBoundary          time.Time // ts of the last bracket of any kind
}

// openWindow starts a new bracketed window at ts and records its open mark
// on the timeline the token pass later replays.
func (b *subagentBuilder) openWindow(ts time.Time) *subagentWindow {
	w := &subagentWindow{summary: SubagentSummary{Start: ts, Open: true}, ordinal: len(b.windows) + 1}
	b.windows = append(b.windows, w)
	b.marks = append(b.marks, bracketMark{ts: ts, open: w})
	b.lastBoundary = ts
	return w
}

// labelFor assigns w's display label from the best identity already known
// (structured ID, then its ordinal fallback), leaving an existing label
// untouched.
func labelFor(w *subagentWindow) {
	if w.summary.Label != "" {
		return
	}
	if w.summary.ID != "" {
		w.summary.Label = w.summary.ID
		return
	}
	if w.ordinal > 0 {
		w.summary.Label = fmt.Sprintf("sub-agent %d", w.ordinal)
	}
}

// stashUnattributed folds the current unattributed segment into the single
// aggregate summary the output pass renders, merging counts and widening
// the aggregate's span. The superseded window is left empty (zero counts)
// so the final payload filter drops it — all unattributed segments render
// as one summary.
func (b *subagentBuilder) stashUnattributed() {
	if b.unattributed == nil {
		return
	}
	if b.unattributedAggregate == nil {
		b.unattributedAggregate = b.unattributed
	} else if b.unattributedAggregate != b.unattributed {
		dst, src := &b.unattributedAggregate.summary, &b.unattributed.summary
		if dst.Start.IsZero() || (!src.Start.IsZero() && src.Start.Before(dst.Start)) {
			dst.Start = src.Start
		}
		if dst.End.Before(src.End) {
			dst.End = src.End
		}
		dst.ActionCount += src.ActionCount
		dst.ErrorCount += src.ErrorCount
		src.ActionCount = 0
		src.ErrorCount = 0
	}
	b.unattributed = nil
}

// foldActions walks the chronological sidechain action refs, dispatching
// each to the handler for its bracket shape (spawn/start, stop, or plain
// activity), then folds any trailing unclaimed segment into the one visible
// unattributed summary. Keeping the claimable segment separate until now is
// what lets a trailing stop name it without reaching back across an earlier
// bracket boundary.
func (b *subagentBuilder) foldActions(refs []models.SubagentActionRef) {
	for _, ref := range refs {
		switch ref.ActionType {
		case models.ActionSpawnSubagent, models.ActionSubagentStart:
			b.handleStart(ref)
		case models.ActionSubagentStop:
			b.handleStop(ref)
		default:
			b.handleActivity(ref)
		}
	}
	b.stashUnattributed()
	b.unattributed = b.unattributedAggregate
}

// handleStart opens a new window for a spawn_subagent / subagent_start
// bracket and seeds its identity from whatever the ref carries.
func (b *subagentBuilder) handleStart(ref models.SubagentActionRef) {
	b.cur = b.openWindow(ref.Timestamp)
	if ref.Metadata != nil && ref.Metadata.AgentID != "" {
		b.cur.summary.ID = ref.Metadata.AgentID
	}
	if ref.Target != "" {
		b.cur.summary.Type = ref.Target
	}
	labelFor(b.cur)
}

// handleStop closes the currently open window when the stop matches a real
// start bracket (the forward path), or otherwise falls back to the
// retrospective claim (C2): claude-code fires SubagentStop with no
// SubagentStart hook, so stop-without-open is the common case, not an
// anomaly.
func (b *subagentBuilder) handleStop(ref models.SubagentActionRef) {
	if b.cur != nil && b.cur.summary.Open && b.cur != b.unattributed {
		b.handleStopForward(ref)
		return
	}
	b.handleStopRetrospective(ref)
}

// handleStopForward closes a window that was actually opened by a matching
// start/spawn bracket.
func (b *subagentBuilder) handleStopForward(ref models.SubagentActionRef) {
	cur := b.cur
	if cur.summary.ID == "" && ref.Metadata != nil && ref.Metadata.AgentID != "" {
		cur.summary.ID = ref.Metadata.AgentID
	}
	if cur.summary.Type == "" && ref.Target != "" {
		cur.summary.Type = ref.Target
	}
	labelFor(cur)
	cur.summary.End = ref.Timestamp
	cur.summary.Open = false
	b.marks = append(b.marks, bracketMark{ts: ref.Timestamp})
	b.lastBoundary = ref.Timestamp
	b.cur = nil
}

// handleStopRetrospective claims the sidechain activity accumulated since
// the last boundary as this stop's own closed window, when that pending
// unattributed bucket is claimable (holds only post-boundary rows).
// Otherwise it detaches a stale leftover, if any, and either names an empty
// window (an agent ID is known) or drops the stop (nothing to claim,
// nothing to name).
func (b *subagentBuilder) handleStopRetrospective(ref models.SubagentActionRef) {
	agentID := ""
	if ref.Metadata != nil {
		agentID = ref.Metadata.AgentID
	}
	// The bucket is only claimable when it holds POST-boundary rows; a
	// bucket predating the last boundary (e.g. activity before a real
	// start) stays an unattributed leftover and a fresh bucket forms for
	// whatever follows.
	claimable := b.unattributed != nil &&
		(b.lastBoundary.IsZero() || !b.unattributed.summary.Start.Before(b.lastBoundary))
	if !claimable {
		b.claimNothing(ref, agentID)
		return
	}
	b.claimUnattributed(ref, agentID)
}

// claimNothing handles a retrospective stop whose pending unattributed
// bucket can't be claimed (empty, or predating the last boundary): it
// detaches a stale leftover if present, then either creates a bare named
// window (an agent ID is known, even with no activity to attach) or drops
// the stop entirely.
func (b *subagentBuilder) claimNothing(ref models.SubagentActionRef, agentID string) {
	if b.unattributed != nil && !b.lastBoundary.IsZero() &&
		!b.unattributed.summary.Start.After(b.lastBoundary) {
		b.stashUnattributed() // detach the stale leftover
	}
	if agentID == "" {
		return // nothing to claim and nothing to name
	}
	w := &subagentWindow{
		summary: SubagentSummary{Start: ref.Timestamp},
		ordinal: len(b.windows) + 1,
	}
	b.windows = append(b.windows, w)
	w.summary.ID = agentID
	labelFor(w)
	w.summary.End = ref.Timestamp
	w.summary.Open = false
	b.marks = append(b.marks,
		bracketMark{ts: w.summary.Start, open: w},
		bracketMark{ts: ref.Timestamp})
	b.lastBoundary = ref.Timestamp
}

// claimUnattributed converts the pending unattributed bucket wholesale into
// this stop's named window, so the bucket's Start (first row after the
// boundary) becomes the window's onset.
func (b *subagentBuilder) claimUnattributed(ref models.SubagentActionRef, agentID string) {
	var w *subagentWindow
	if b.unattributed != nil {
		w = b.unattributed
		b.unattributed = nil // next activity starts a fresh bucket
	} else {
		w = &subagentWindow{
			summary: SubagentSummary{Start: ref.Timestamp},
			ordinal: len(b.windows) + 1,
		}
		b.windows = append(b.windows, w)
	}
	b.cur = nil
	w.summary.ID = agentID
	if w.summary.Type == "" && ref.Target != "" {
		w.summary.Type = ref.Target
	}
	if w.ordinal == 0 {
		w.ordinal = len(b.windows)
	}
	// The bucket's Label must not survive the conversion — and it must be
	// cleared BEFORE labelFor, which early-returns on any existing label.
	if strings.HasPrefix(w.summary.Label, "unattributed") {
		w.summary.Label = ""
	}
	labelFor(w)
	w.summary.End = ref.Timestamp
	w.summary.Open = false
	// Token replay: open at the claimed onset, close at the stop.
	b.marks = append(b.marks,
		bracketMark{ts: w.summary.Start, open: w},
		bracketMark{ts: ref.Timestamp})
	b.lastBoundary = ref.Timestamp
}

// handleActivity folds one non-bracket sidechain action into whichever
// window is currently open, or into the shared unattributed bucket when
// none is.
func (b *subagentBuilder) handleActivity(ref models.SubagentActionRef) {
	if !ref.IsSidechain {
		return
	}
	if b.cur == nil || !b.cur.summary.Open {
		// Outside any bracket: keep it visible in one explicit unattributed
		// bucket instead of dropping it. A bucket that began at or before
		// the most recent bracket belongs to the earlier segment and must
		// not absorb post-boundary activity. Refs are ordered, so an
		// activity row encountered after a same-timestamp bracket is
		// unambiguously on the new side.
		if b.unattributed != nil && !b.lastBoundary.IsZero() &&
			!b.unattributed.summary.Start.After(b.lastBoundary) {
			b.stashUnattributed()
		}
		if b.unattributed == nil {
			b.unattributed = &subagentWindow{summary: SubagentSummary{
				Label: "unattributed sub-agent activity",
				Start: ref.Timestamp,
				Open:  true,
			}}
			b.windows = append(b.windows, b.unattributed)
		}
		b.cur = b.unattributed
	}
	b.cur.summary.ActionCount++
	if !ref.Success {
		b.cur.summary.ErrorCount++
	}
	if b.cur.summary.End.Before(ref.Timestamp) {
		b.cur.summary.End = ref.Timestamp
	}
}

// foldTokens replays the bracket timeline foldActions recorded so each
// token_usage row lands in whichever window was open at its timestamp — the
// same open-window rule the action pass uses (a stop sharing the row's
// exact timestamp closes first, so such a row is outside; cross-table
// timestamp ties carry no sub-row ordering to recover).
func (b *subagentBuilder) foldTokens(tokens []models.SubagentTokenRef) {
	mi := 0
	b.cur = nil
	for _, tok := range tokens {
		for mi < len(b.marks) && !b.marks[mi].ts.After(tok.Timestamp) {
			if b.marks[mi].open != nil {
				b.cur = b.marks[mi].open
			} else {
				// A close nulls cur directly; do NOT consult
				// cur.summary.Open here — the action pass above has
				// already flipped every closed window's flag to false,
				// so that check would misattribute tokens inside an
				// already-closed window to the unattributed bucket.
				b.cur = nil
			}
			mi++
		}
		if b.cur == nil {
			if b.unattributed == nil {
				b.unattributed = &subagentWindow{summary: SubagentSummary{
					Label: "unattributed sub-agent activity",
					Start: tok.Timestamp,
					Open:  true,
				}}
				b.windows = append(b.windows, b.unattributed)
			} else if b.unattributed.summary.Start.After(tok.Timestamp) {
				b.unattributed.summary.Start = tok.Timestamp
			}
			b.cur = b.unattributed
		}
		b.cur.summary.InputTokens += tok.InputTokens
		b.cur.summary.OutputTokens += tok.OutputTokens
		b.cur.summary.CacheReadTokens += tok.CacheReadTokens
		b.cur.summary.CostUSD += tok.EstimatedCostUSD
	}
}

// output filters empty bracket pairs (no story to tell, unless tokens
// landed in them — a usage-only window, e.g. hook events suppressed but
// usage rows captured, must stay visible) and returns the remaining
// windows sorted by start time.
func (b *subagentBuilder) output() []SubagentSummary {
	out := make([]SubagentSummary, 0, len(b.windows))
	for _, w := range b.windows {
		s := w.summary
		if s.ActionCount == 0 && s.InputTokens == 0 && s.OutputTokens == 0 &&
			s.CacheReadTokens == 0 && s.CostUSD == 0 && s.ID == "" && s.Type == "" {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// handleSessionSubagents serves GET /api/session/<id>/subagents.
func (s *Server) handleSessionSubagents(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	st := store.New(s.db())
	refs, err := st.SidechainActionsForSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load sidechain actions: %v", err), http.StatusInternalServerError)
		return
	}
	tokens, err := st.SidechainTokenUsageForSession(r.Context(), sessionID)
	if err != nil {
		http.Error(w, fmt.Sprintf("load sidechain token usage: %v", err), http.StatusInternalServerError)
		return
	}
	children, err := st.ChildSubagentsForSession(r.Context(), sessionID)
	if err != nil {
		writeErr(w, err)
		return
	}
	subagents := mergeChildSubagents(children, refs, tokens)
	if subagents == nil {
		subagents = []SubagentSummary{}
	}
	writeJSON(w, SessionSubagentsResponse{SessionID: sessionID, Total: len(subagents), Subagents: subagents})
}

// mergeChildSubagents prefers exact runtime identity over legacy time windows.
// Lifecycle hooks enrich only the child with the same native agent ID.
func mergeChildSubagents(children []store.ChildSubagent, refs []models.SubagentActionRef, tokens []models.SubagentTokenRef) []SubagentSummary {
	out := make([]SubagentSummary, 0, len(children))
	byID := make(map[string]int)
	for _, c := range children {
		label := c.AgentID
		if label == "" {
			label = c.SessionID
		}
		out = append(out, SubagentSummary{
			SessionID: c.SessionID, ID: c.AgentID, Label: label,
			Start: parseSubagentStamp(c.StartedAt), End: parseSubagentStamp(c.LastSeenAt), Open: true,
			ActionCount: c.ActionCount, ErrorCount: c.ErrorCount, InputTokens: c.InputTokens, OutputTokens: c.OutputTokens,
			CacheReadTokens: c.CacheReadTokens, CacheCreationTokens: c.CacheCreationTokens, CostUSD: c.CostUSD,
		})
		if c.AgentID != "" {
			byID[c.AgentID] = len(out) - 1
		}
	}
	remaining := make([]models.SubagentActionRef, 0, len(refs))
	for _, ref := range refs {
		if ref.Metadata != nil {
			if idx, ok := byID[ref.Metadata.AgentID]; ok && (ref.ActionType == models.ActionSubagentStart || ref.ActionType == models.ActionSubagentStop) {
				r := &out[idx]
				if ref.Target != "" && ref.ActionType == models.ActionSubagentStart {
					r.Type = ref.Target
				}
				if ref.ActionType == models.ActionSubagentStop && !ref.Timestamp.Before(r.End) {
					r.Open = false
					r.End = ref.Timestamp
				}
				continue
			}
		}
		remaining = append(remaining, ref)
	}
	legacy := buildSubagentSummaries(remaining, tokens)
	if len(children) > 0 && len(tokens) == 0 {
		if hooks, ok := lifecycleOnlySubagents(remaining); ok {
			legacy = hooks
		}
	}
	out = append(out, legacy...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// lifecycleOnlySubagents keeps unmatched hooks separate after dedicated child
// activity has moved. Anonymous spawn calls cannot identify these runtimes;
// a stop's Target may be final prose, so only starts supply categorical types.
// Any remaining inline activity requires the legacy window view instead.
func lifecycleOnlySubagents(refs []models.SubagentActionRef) ([]SubagentSummary, bool) {
	var out []SubagentSummary
	byID := make(map[string]int)
	for _, ref := range refs {
		switch ref.ActionType {
		case models.ActionSpawnSubagent:
			continue
		case models.ActionSubagentStart, models.ActionSubagentStop:
		default:
			if ref.IsSidechain {
				return nil, false
			}
			continue
		}
		if ref.Metadata == nil || ref.Metadata.AgentID == "" {
			continue
		}
		id := ref.Metadata.AgentID
		idx, ok := byID[id]
		if !ok {
			idx = len(out)
			byID[id] = idx
			out = append(out, SubagentSummary{ID: id, Label: id, Start: ref.Timestamp, Open: true, HookOnly: true})
		}
		r := &out[idx]
		if ref.ActionType == models.ActionSubagentStart {
			r.Type = ref.Target
		} else {
			r.End, r.Open, r.StopActionID = ref.Timestamp, false, ref.ID
		}
	}
	return out, true
}

func parseSubagentStamp(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}
