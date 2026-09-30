package dashboard

// Test-only ORACLE for the session Messages endpoint: verbatim copies of
// handleSessionMessages, loadMessageActionRows and loadActionExcerpts as they
// stood BEFORE the page-window hydration + indexed excerpt lookup (node
// dashboard performance audit 2026-09-29). The equality tests in
// session_messages_hydrate_test.go assert the live handler is byte-identical
// to this oracle over every query shape. Only the three function names
// differ from the pre-change source.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/sessionmsg"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func loadActionExcerptsOracle(ctx context.Context, db *sql.DB, ids []int64, maxBytes int) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	var q string
	if maxBytes > 0 {
		q = fmt.Sprintf("SELECT action_id, substr(excerpt, 1, %d) FROM action_excerpts WHERE action_id IN (%s)", maxBytes, placeholders)
	} else {
		q = "SELECT action_id, excerpt FROM action_excerpts WHERE action_id IN (" + placeholders + ")"
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var excerpt string
		if err := rows.Scan(&id, &excerpt); err != nil {
			return nil, err
		}
		if _, ok := out[id]; !ok {
			out[id] = excerpt
		}
	}
	return out, rows.Err()
}

func (s *Server) handleSessionMessagesOracle(w http.ResponseWriter, r *http.Request, sessionID string) {
	if sessionID == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	var sessionModel, sessionTool string
	_ = s.db().QueryRowContext(
		r.Context(),
		`SELECT COALESCE(model, ''), COALESCE(tool, '') FROM sessions WHERE id = ?`, sessionID,
	).Scan(&sessionModel, &sessionTool)
	// browserSession gates the assistant_message inline-body behaviour to
	// browser-captured chat sessions (chatgpt-web / claude-web /
	// perplexity-web / gemini-web / copilot-web — every browserchat tool
	// ends in "-web"). For those sessions the response text lives in
	// actions.raw_tool_output and IS the user-facing content to render
	// inline; for coding-agent adapters assistant_message.raw_tool_output
	// is model narration already surfaced via target/excerpt, so their
	// rows stay byte-for-byte unchanged (no regression). This is a
	// capability distinction (browser chat = raw_tool_output is the
	// displayable answer), resolved once here at the boundary rather than
	// branched on tool name deeper in the scan loop.
	browserSession := strings.HasSuffix(sessionTool, "-web")
	// messageAttachment is the per-turn user-attachment metadata decoded
	// from actions.user_attachments (Issue 1). Metadata only: a coarse
	// kind + optional media_type, never a filename or bytes.
	type messageAttachment struct {
		Kind      string `json:"kind"`
		MediaType string `json:"media_type,omitempty"`
	}
	type toolCallRow struct {
		// ActionID is the actions.id primary key. Surfaced so the
		// frontend can call /api/action/<id>/full_text to fetch the
		// untruncated raw_tool_input + raw_tool_output on demand for
		// the copy and view-full-text buttons.
		ActionID    int64  `json:"action_id"`
		ActionType  string `json:"action_type"`
		RawToolName string `json:"raw_tool_name"`
		Target      string `json:"target"`
		FullText    string `json:"full_text,omitempty"`
		// FullTextElided marks rows whose raw_tool_input exceeded the
		// per-row inline cap (fullTextInlineMax) and was truncated for
		// the timeline payload. UI fetches the untruncated body via
		// /api/action/<id>/full_text when the operator clicks copy or
		// view-full-text.
		FullTextElided bool `json:"full_text_elided,omitempty"`
		// HasFullOutput is true when actions.raw_tool_output is
		// non-empty for this row — i.e. the adapter captured a
		// tool_result body that's available via the on-demand
		// /api/action/<id>/full_text endpoint. The inline Excerpt
		// stays 2 KiB (FTS5 cap) regardless; this flag tells the UI
		// there's a fuller version to offer.
		HasFullOutput bool   `json:"has_full_output,omitempty"`
		Excerpt       string `json:"excerpt,omitempty"`
		Success       bool   `json:"success"`
		ErrorMessage  string `json:"error_message,omitempty"`
		Timestamp     string `json:"timestamp"`
		// DurationMs is the per-tool-call wall-clock duration in ms
		// (sourced from actions.duration_ms). Adapters populate this
		// where the source data carries timing — codex via the
		// function_call→output timestamp gap, claude-code via
		// tool_use→tool_result gap, copilot via elapsedMs. Zero when
		// the source provided no timing signal or the row predates
		// the v1.4.28 capture work.
		DurationMs int64 `json:"duration_ms,omitempty"`
		// Per-event metadata extracted from actions.metadata JSON
		// (migration 017 + codex JSONL extension). Empty / false when
		// the source adapter didn't emit the field. omitempty keeps
		// the response payload lean.
		PermissionMode string `json:"permission_mode,omitempty"`
		EffortLevel    string `json:"effort_level,omitempty"`
		IsInterrupt    bool   `json:"is_interrupt,omitempty"`
		// StopReason — why the assistant turn ended; ServiceTier — served
		// capacity tier. Per-message metadata from the transcript.
		StopReason  string `json:"stop_reason,omitempty"`
		ServiceTier string `json:"service_tier,omitempty"`
		// Browser-capture API-call details, extracted from
		// actions.metadata JSON on browserchat assistant_message rows
		// (request_url / id_source / granularity / prompt_tokens_est /
		// response_tokens_est). Empty / zero for every non-browser
		// adapter — omitempty keeps the payload lean so only browser
		// rows carry them. See ActionMetadata (models) + the browserchat
		// buildMetadata seam.
		RequestURL        string `json:"request_url,omitempty"`
		IDSource          string `json:"id_source,omitempty"`
		Granularity       string `json:"granularity,omitempty"`
		PromptTokensEst   int64  `json:"prompt_tokens_est,omitempty"`
		ResponseTokensEst int64  `json:"response_tokens_est,omitempty"`
	}
	type messageRow struct {
		Account models.MessageAccount `json:"account"`
		// Seq is the row's 1..N ordinal in CHRONOLOGICAL order, assigned
		// once right after the authoritative merge sort and therefore
		// stable across pagination, ?tail and any ?sort_by reordering.
		// The dashboard's "#" column renders it (a page-relative index
		// would renumber under a non-default sort), and sort_by=seq is
		// the "restore chronological order" key.
		Seq               int    `json:"seq"`
		MessageID         string `json:"message_id"`
		Timestamp         string `json:"timestamp"`
		Role              string `json:"role"`
		Model             string `json:"model,omitempty"`
		Input             int64  `json:"input"`
		Output            int64  `json:"output"`
		CacheRead         int64  `json:"cache_read"`
		CacheCreation     int64  `json:"cache_creation"`
		CacheCw1h         int64  `json:"cache_creation_1h"`
		Reasoning         int64  `json:"reasoning,omitempty"`
		WebSearchRequests int64  `json:"web_search_requests,omitempty"`
		// CostUSD is the legacy total; AICostUSD + ToolCostUSD split
		// it so the Messages table can render API / Tool / Total in
		// separate columns. CostUSD == AICostUSD + ToolCostUSD always.
		CostUSD     float64 `json:"cost_usd"`
		AICostUSD   float64 `json:"ai_cost_usd"`
		ToolCostUSD float64 `json:"tool_cost_usd"`
		// ToolDurationMs is the sum of contained tool_calls'
		// duration_ms — the assistant's tool-execution time for
		// this turn. Differs from ElapsedMs (which spans the entire
		// gap to the next message, including the model's reasoning
		// time and the user's typing time). Zero when no contained
		// tool_call carries duration_ms.
		ToolDurationMs int64 `json:"tool_duration_ms,omitempty"`
		ToolCallCount  int   `json:"tool_call_count"`
		// EffortLevel is the per-turn reasoning effort the adapter
		// captured for this message — sourced from
		// actions.metadata.$.effort_level on any action in the turn.
		// All actions in one message share the same effort_level
		// (codex collaboration_mode.settings.reasoning_effort is
		// per-turn, antigravity's effort is encoded in the SKU
		// itself — gemini-pro-agent, gemini-3.1-pro-low/medium/high
		// per [[project_antigravity_skus]]). First non-empty wins —
		// resolved by sessionmsg.Derive (the SAME rule the org uses),
		// copied verbatim below rather than re-derived here.
		// Empty when the adapter didn't emit it (Anthropic via
		// claude-code/cowork, copilot, etc. — Anthropic doesn't
		// expose a reasoning-effort knob).
		EffortLevel string `json:"effort_level,omitempty"`
		// StopReason is the assistant turn's terminal reason (end_turn /
		// max_tokens / tool_use / refusal) and ServiceTier the served
		// capacity tier (standard / priority / batch) — both resolved by
		// Derive from the row's proxy contribution (api_turns.stop_reason)
		// first, else the first non-empty among the turn's actions.
		// Empty when neither source carried them.
		StopReason  string `json:"stop_reason,omitempty"`
		ServiceTier string `json:"service_tier,omitempty"`
		// Fast is true when any token/turn row in this message bucket was
		// served in the provider's low-latency "fast" tier (Anthropic
		// Opus 4.8 speed:"fast", captured by the proxy). The timeline
		// renders a FAST badge on the row; CostUSD already reflects the
		// FastMultiplier premium. Zero/false for every standard turn.
		Fast bool `json:"fast,omitempty"`
		// Attachments records the files/images/audio the USER attached to
		// this prompt turn (Issue 1, migration 126), decoded from
		// actions.user_attachments on the turn's user_prompt action.
		// Metadata only: each entry carries a coarse kind (image | file |
		// audio) and an optional media_type — NEVER a filename or bytes.
		// Empty/omitted when the turn had no attachments; renders as an
		// "Att" badge in the Messages table.
		Attachments []messageAttachment `json:"attachments,omitempty"`
		ToolCalls   []toolCallRow       `json:"tool_calls"`
		// TimingWire carries elapsed_ms (gap to the next row), response_ms
		// and every tps_* field, projected by sessionmsg.Row.Timing() - the
		// SAME projection the org drawer embeds, so the two cannot drift.
		sessionmsg.TimingWire
		// speed is the row's sessionmsg accumulator, kept for the server
		// sort. Never serialized.
		speed sessionmsg.Speed
	}

	// Group-key precedence: default (turn rollup) vs ?detail=inference —
	// see sessionmsg.GroupMode's doc comment for the exact semantics both
	// engines share.
	mode := sessionmsg.RollupTurn
	if r.URL.Query().Get("detail") == "inference" {
		mode = sessionmsg.RollupInference
	}

	caps := store.NodeSessionCaps(sessionTool)

	// S1: plain ordered SQL, no dedup/fold logic of its own — see this
	// function's doc comment.
	proxyRows, err := loadMessageProxyRows(r.Context(), s.db(), sessionID, sessionModel)
	if err != nil {
		writeErr(w, err)
		return
	}
	tokenRows, err := loadMessageTokenRows(r.Context(), s.db(), sessionID, sessionModel, sessionTool)
	if err != nil {
		writeErr(w, err)
		return
	}
	actionRows, err := loadMessageActionRowsOracle(r.Context(), s.db(), sessionID, browserSession)
	if err != nil {
		writeErr(w, err)
		return
	}

	derived := sessionmsg.Derive(sessionmsg.DeriveInput{
		ProxyRows:         proxyRows,
		TokenRows:         tokenRows,
		ActionRows:        actionRows,
		Mode:              mode,
		ShadowCapable:     caps.ShadowCapable,
		ReasoningDisjoint: caps.ReasoningDisjoint,
		SessionCumulative: caps.SessionCumulative,
		DefaultModel:      sessionModel,
	})

	out := make([]*messageRow, len(derived))
	// pendingExcerpt records each tool-call's location so we can fill
	// its Excerpt field after the batch FTS5 lookup below. Indices into
	// mr.ToolCalls are stable once the projection loop ends.
	type pendingExcerpt struct {
		actionID int64
		mr       *messageRow
		idx      int
	}
	var pendings []pendingExcerpt
	var actionIDs []int64

	for i, row := range derived {
		mr := &messageRow{
			Seq:               row.Seq,
			MessageID:         row.Key,
			Timestamp:         row.Timestamp,
			Role:              row.Role,
			Model:             row.Model,
			Input:             row.Bundle.Input,
			Output:            row.Bundle.Output,
			CacheRead:         row.Bundle.CacheRead,
			CacheCreation:     row.Bundle.CacheCreation,
			CacheCw1h:         row.Bundle.CacheCreation1h,
			Reasoning:         row.Bundle.Reasoning,
			WebSearchRequests: row.Bundle.WebSearchRequests,
			StopReason:        row.StopReason,
			EffortLevel:       row.EffortLevel,
			ServiceTier:       row.ServiceTier,
			ToolCalls:         []toolCallRow{},
			TimingWire:        row.Timing(),
			speed:             row.Speed,
		}

		// Cost: price EACH raw contribution separately, then sum —
		// pricing the already-merged Bundle once would falsely apply a
		// long-context-threshold rate to a message whose individual
		// underlying turns never crossed it
		// (TestAPISessionMessages_LongContextPerTurn's regression case:
		// two 150K-token turns summing to 300K must NOT be priced as one
		// 300K-token long-context call). See Row.Contributions' doc
		// comment.
		for _, c := range row.Contributions {
			cAt, perr := time.Parse(time.RFC3339Nano, c.Timestamp)
			if perr != nil {
				cAt, _ = time.Parse(time.RFC3339Nano, row.Timestamp)
			}
			bundle := sessionMsgCostBundle(c.Bundle)
			if cb, ok := proxyAwareCost(s.opts.CostEngine, c.Model, bundle, c.RecordedCostUSD, c.OwnFast, c.InheritedFast, cAt); ok {
				mr.CostUSD += cb.Total
				mr.AICostUSD += cb.AICost
				mr.ToolCostUSD += cb.ToolCost
			}
			// A turn shows the ⚡ premium badge only when it was served fast
			// AND the model actually carries a fast-mode premium
			// (Pricing.FastMultiplier > 0). Codex sends service_tier:
			// "priority" globally, but only gpt-5.5 / gpt-5.4 have a
			// documented Fast premium — so mini/codex priority turns keep
			// the service_tier pill without an ⚡ that implies a price bump
			// they don't incur.
			if bundle.Fast {
				if p, ok := s.opts.CostEngine.LookupAt(c.Model, cAt); ok && p.FastMultiplier > 0 {
					mr.Fast = true
				}
			}
		}

		// Tool calls: project each bucketed action (already rich-field-
		// resolved by loadMessageActionRows) into a toolCallRow, decode
		// attachments, and queue the excerpt batch lookup.
		for _, a := range row.Actions {
			var actionID int64
			if a.ActionID != "" {
				if n, perr := strconv.ParseInt(a.ActionID, 10, 64); perr == nil {
					actionID = n
				}
			}
			var durationMs int64
			if a.DurationMs != nil {
				durationMs = *a.DurationMs
			}
			success := true
			if a.Success != nil {
				success = *a.Success
			}
			tc := toolCallRow{
				ActionID:          actionID,
				ActionType:        a.ActionType,
				RawToolName:       a.Tool,
				Target:            a.Target,
				FullText:          a.FullText,
				FullTextElided:    a.FullTextElided,
				HasFullOutput:     a.HasFullOutput,
				Success:           success,
				ErrorMessage:      a.ErrorMessage,
				Timestamp:         a.Timestamp,
				DurationMs:        durationMs,
				PermissionMode:    a.PermissionMode,
				EffortLevel:       a.EffortLevel,
				IsInterrupt:       a.IsInterrupt,
				StopReason:        a.StopReason,
				ServiceTier:       a.ServiceTier,
				RequestURL:        a.RequestURL,
				IDSource:          a.IDSource,
				Granularity:       a.Granularity,
				PromptTokensEst:   a.PromptTokensEst,
				ResponseTokensEst: a.ResponseTokensEst,
			}
			mr.ToolCalls = append(mr.ToolCalls, tc)
			mr.ToolCallCount++
			mr.ToolDurationMs += tc.DurationMs
			// Decode this turn's user-attachment metadata (Issue 1) onto
			// the message row. Metadata only (kind + optional media_type);
			// a malformed blob is ignored rather than failing the
			// endpoint.
			if a.UserAttachmentsJSON != "" {
				var atts []messageAttachment
				if err := json.Unmarshal([]byte(a.UserAttachmentsJSON), &atts); err == nil && len(atts) > 0 {
					mr.Attachments = append(mr.Attachments, atts...)
				}
			}
			pendings = append(pendings, pendingExcerpt{actionID: actionID, mr: mr, idx: len(mr.ToolCalls) - 1})
			actionIDs = append(actionIDs, actionID)
		}
		out[i] = mr
	}

	// Batch-fetch excerpts for every tool call (single FTS5 scan instead
	// of N×M); see loadActionExcerpts. maxBytes=0 preserves the original
	// full-text semantics for the messages view.
	excerptByID, err := loadActionExcerptsOracle(r.Context(), s.db(), actionIDs, 0)
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, p := range pendings {
		if ex := excerptByID[p.actionID]; ex != "" {
			p.mr.ToolCalls[p.idx].Excerpt = ex
		}
	}

	// Orphan-token stub injection — for agentic sessions (gemini /
	// antigravity tool-call-loop turns) where the upstream API stores
	// no extractable content for most LLM calls, surface a synthetic
	// row carrying the per-turn token totals so the dashboard's
	// expand-row view has SOMETHING to display instead of an empty
	// Tools column. Gated on orphan ratio > 0.5 so claude sessions
	// (where every turn already has narrative or a tool call) don't
	// grow noise stubs that obscure real content.
	var assistantTotal, assistantOrphan int
	for _, mr := range out {
		if mr.Role != "assistant" {
			continue
		}
		assistantTotal++
		if len(mr.ToolCalls) == 0 {
			assistantOrphan++
		}
	}
	if assistantTotal > 0 && float64(assistantOrphan)/float64(assistantTotal) > 0.5 {
		for _, mr := range out {
			if mr.Role != "assistant" || len(mr.ToolCalls) > 0 {
				continue
			}
			target := fmt.Sprintf("API call (no recovered text): %d in + %d cache_read + %d cache_create + %d out tokens",
				mr.Input, mr.CacheRead, mr.CacheCreation, mr.Output)
			mr.ToolCalls = append(mr.ToolCalls, toolCallRow{
				ActionType:  "llm_call",
				RawToolName: "synthetic.api_call",
				Target:      target,
				Success:     true,
				Timestamp:   mr.Timestamp,
			})
			mr.ToolCallCount++
		}
	}

	accounts, accountErr := store.New(s.db()).LoadMessageAccounts(r.Context(), sessionID, sessionTool)
	if accountErr != nil {
		http.Error(w, "account evidence unavailable", http.StatusInternalServerError)
		return
	}
	accountSummary := struct {
		Accounts  []models.ToolAccountEvidence `json:"accounts"`
		Observed  int                          `json:"observed"`
		Unknown   int                          `json:"unknown"`
		Conflicts int                          `json:"conflicts"`
	}{Accounts: []models.ToolAccountEvidence{}}
	// S7 (2026-09-22 review round 3): index every alias a row answers to —
	// not just its own final MessageID — via the SAME sessionmsg.AliasIndex
	// helper the org's rollup.SessionMessageMetrics now calls, so a
	// turn-bound observation (binding_id = a contributing token row's
	// turn_id, or any other id that folded into a merged row) that only
	// the org used to resolve now resolves here too. `out` is index-aligned
	// with `derived` (built by direct one-pass projection above), so
	// AliasIndex's row indices apply unchanged.
	aliasIdx := sessionmsg.AliasIndex(derived)
	rowKeys := sessionmsg.RowKeysByIndex(aliasIdx, len(derived))
	seenAccounts := map[string]bool{}
	for i, mr := range out {
		mr.Account = models.MessageAccount{Status: "unknown", Label: "Unknown", Evidence: []models.ToolAccountEvidence{}}
		for _, k := range rowKeys[i] {
			if a, ok := accounts[mr.Role+":"+k]; ok {
				mr.Account = a
				break
			}
		}
		switch mr.Account.Status {
		case "observed":
			accountSummary.Observed++
		case "conflict":
			accountSummary.Conflicts++
		default:
			accountSummary.Unknown++
		}
		for _, e := range mr.Account.Evidence {
			if !seenAccounts[e.Key] {
				seenAccounts[e.Key] = true
				accountSummary.Accounts = append(accountSummary.Accounts, e)
			}
		}
	}
	// ?sort_by / ?sort_dir — display ordering, applied LAST: after the
	// authoritative chronological merge, after the Seq assignment, and after
	// the ElapsedMs / TpsMs derivations (which are defined over the
	// chronological timeline and would be corrupted by a reorder), but BEFORE
	// the offset/limit slice so a sort addresses the WHOLE timeline rather
	// than the current page. Absent / unrecognised params resolve to the
	// chronological default, whose permutation is the identity — the response
	// is then byte-identical to the pre-sort handler.
	sortBy, sortDesc := parseMessagesSortParams(r)
	applySort := func(rows []*messageRow) []*messageRow {
		if messageSortIsDefault(sortBy, sortDesc) || len(rows) < 2 {
			return rows
		}
		fields := make([]messageSortField, len(rows))
		for i, mr := range rows {
			f := messageSortField{
				Seq:            mr.Seq,
				Timestamp:      mr.Timestamp,
				MessageID:      mr.MessageID,
				Role:           mr.Role,
				Model:          mr.Model,
				EffortLevel:    mr.EffortLevel,
				Account:        mr.Account.Label,
				AccountUnknown: mr.Account.Status == "unknown",
				Input:          mr.Input,
				CacheRead:      mr.CacheRead,
				CacheWrite:     mr.CacheCreation,
				Output:         mr.Output,
				ElapsedMs:      mr.ElapsedMs,
				ResponseMs:     mr.ResponseMs,
				ToolCalls:      mr.ToolCallCount,
				Attachments:    len(mr.Attachments),
				AICostUSD:      mr.AICostUSD,
				ToolCostUSD:    mr.ToolCostUSD,
				CostUSD:        mr.CostUSD,
			}
			// Tok/s: sessionmsg.Speed.Rate() - the ONE owner the client's
			// shared/lib/speed.ts renders from - so the server sorts on
			// exactly the number the operator sees (absent when suppressed).
			if tps, _, ok := mr.speed.Rate(); ok {
				f.TokensPerSec = &tps
			}
			// Content: mirrors the Content cell, which is derived from the
			// first tool call. No tool calls → the cell renders "—" and the
			// key is the empty string.
			if len(mr.ToolCalls) > 0 {
				tc := mr.ToolCalls[0]
				f.Content = messageContentSortKey(tc.ActionType, tc.Target)
			}
			fields[i] = f
		}
		sorted := make([]*messageRow, len(rows))
		for i, p := range messageSortOrder(fields, sortBy, sortDesc) {
			sorted[i] = rows[p]
		}
		return sorted
	}

	// ?tail=N (FROZEN contract, v1.24): return the last N rows of the FULL
	// ordered timeline — NOT a re-slice of a paginated page. Because it
	// addresses the whole timeline, tail is mutually exclusive with the
	// pagination params: combined with offset/limit/locate it is an explicit
	// 400 (they would otherwise fight over which window wins, and the old
	// "tail-after-page" order silently returned the tail of page 0, not the
	// true last N). Standalone: response offset = index of the first returned
	// row (total−N, clamped ≥0); total stays the FULL count. Clamp N to 1..200
	// (>200 saturates); a <1 / non-numeric tail is ignored as absent and falls
	// through to the default pagination path below, so an absent-or-garbage
	// tail is byte-identical to the pre-tail behaviour.
	if tailStr := r.URL.Query().Get("tail"); tailStr != "" {
		if r.URL.Query().Get("offset") != "" ||
			r.URL.Query().Get("limit") != "" ||
			r.URL.Query().Get("locate") != "" {
			http.Error(w, "tail cannot be combined with offset, limit, or locate", http.StatusBadRequest)
			return
		}
		if n, err := strconv.Atoi(tailStr); err == nil && n >= 1 {
			if n > 200 {
				n = 200
			}
			total := len(out)
			offset := 0
			if total > n {
				offset = total - n
			}
			// tail keeps its frozen meaning — the last N rows
			// CHRONOLOGICALLY — and the sort then reorders just those N
			// for display. tail+sort is therefore NOT an error (unlike
			// tail+pagination, which would fight over the window).
			writeJSON(w, map[string]any{
				"session_id":      sessionID,
				"messages":        applySort(out[offset:]),
				"account_summary": accountSummary,
				"total":           total,
				"limit":           n,
				"offset":          offset,
			})
			return
		}
	}

	// Pagination — added v1.4.24 because rendering 5000+ messages in
	// one go was crashing the dashboard browser tab. Default limit is
	// 100; pass limit=0 explicitly to opt into the pre-v1.4.24 "all
	// messages" behaviour. Server-side paginates AFTER the chronological
	// sort so the page boundaries are stable across re-fetches.
	limit, offset := 100, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	// Reorder for display BEFORE locate/offset/limit so the page window is cut
	// out of the EFFECTIVE order the caller asked for.
	out = applySort(out)
	// ?locate=<message_id>: snap offset to the page containing that message so
	// the caller (the Processes panel "jump to the message that spawned this
	// process" link) lands on the right page. Reuses this handler's own
	// effective ordering — no fragile external ordinal — so it stays correct
	// under a non-default sort_by. No-op if not found.
	if mid := r.URL.Query().Get("locate"); mid != "" && limit > 0 {
		for i := range out {
			if out[i].MessageID == mid {
				offset = (i / limit) * limit
				break
			}
		}
	}
	total := len(out)
	if offset > total {
		offset = total
	}
	page := out[offset:]
	if limit > 0 && len(page) > limit {
		page = page[:limit]
	}
	writeJSON(w, map[string]any{
		"session_id":      sessionID,
		"messages":        page,
		"account_summary": accountSummary,
		"total":           total,
		"limit":           limit,
		"offset":          offset,
	})
}

func loadMessageActionRowsOracle(ctx context.Context, db *sql.DB, sessionID string, browserSession bool) ([]sessionmsg.ActionRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT a.id, COALESCE(a.source_event_id, ''), COALESCE(a.message_id, ''),
		        a.action_type, COALESCE(a.raw_tool_name, ''),
		        COALESCE(a.target, ''), COALESCE(a.raw_tool_input, ''),
		        LENGTH(COALESCE(a.raw_tool_output, '')) AS raw_output_len,
		        CASE WHEN a.action_type = 'assistant_message'
		             THEN substr(COALESCE(a.raw_tool_output, ''), 1, ?)
		             ELSE '' END AS asst_body,
		        COALESCE(a.success, 1),
		        COALESCE(a.error_message, ''), a.timestamp,
		        COALESCE(a.duration_ms, 0),
		        COALESCE(json_extract(a.metadata, '$.permission_mode'), '') AS permission_mode,
		        COALESCE(json_extract(a.metadata, '$.effort_level'), '') AS effort_level,
		        COALESCE(json_extract(a.metadata, '$.is_interrupt'), 0) AS is_interrupt,
		        COALESCE(json_extract(a.metadata, '$.stop_reason'), '') AS stop_reason,
		        COALESCE(json_extract(a.metadata, '$.service_tier'), '') AS service_tier,
		        COALESCE(json_extract(a.metadata, '$.request_url'), '') AS request_url,
		        COALESCE(json_extract(a.metadata, '$.id_source'), '') AS id_source,
		        COALESCE(json_extract(a.metadata, '$.granularity'), '') AS granularity,
		        COALESCE(json_extract(a.metadata, '$.prompt_tokens_est'), 0) AS prompt_tokens_est,
		        COALESCE(json_extract(a.metadata, '$.response_tokens_est'), 0) AS response_tokens_est,
		        COALESCE(a.user_attachments, '') AS user_attachments
		 FROM actions a
		 WHERE a.session_id = ?
		   AND a.action_type <> 'post_tool_batch'
		 ORDER BY a.timestamp ASC, COALESCE(a.source_event_id, '') ASC`,
		fullTextInlineMax, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sessionmsg.ActionRow
	for rows.Next() {
		var actionID int64
		var srcEventID, msgID, actionType, rawTool, target, rawInput, asstBody, errMsg, ts string
		var permMode, effortLevel, stopReason, serviceTier string
		var requestURL, idSource, granularity string
		var promptTokensEst, responseTokensEst int64
		var successInt, isInterrupt int
		var durationMs, rawOutputLen int64
		var userAttachmentsJSON string
		if err := rows.Scan(&actionID, &srcEventID, &msgID, &actionType, &rawTool, &target, &rawInput, &rawOutputLen, &asstBody,
			&successInt, &errMsg, &ts, &durationMs, &permMode, &effortLevel, &isInterrupt, &stopReason, &serviceTier,
			&requestURL, &idSource, &granularity, &promptTokensEst, &responseTokensEst, &userAttachmentsJSON); err != nil {
			return nil, err
		}
		fullText := target
		switch actionType {
		case "user_prompt", "system_prompt", "ask_user", "run_command":
			if rawInput != "" {
				fullText = rawInput
			}
		}
		if actionType == "run_command" {
			fullText = decodeCommandInput(fullText)
		}
		// Browser chat: the assistant's on-screen answer is stored in
		// raw_tool_output (target is only a one-line preview). Surface
		// the (SQL-capped) response body as the row's inline FullText so
		// the timeline shows the actual reply; the untruncated body
		// stays available via /api/action/<id>/full_text. Gated on
		// browserSession so coding-agent assistant_message rows (model
		// narration) render exactly as before.
		if browserSession && actionType == "assistant_message" && asstBody != "" {
			fullText = asstBody
		}
		fullTextElided := false
		if len(fullText) > fullTextInlineMax {
			fullText = fullText[:fullTextInlineMax]
			fullTextElided = true
		}
		// A capped assistant body whose source was longer than the inline
		// cap is elided too (the substr already trimmed it in SQL, so the
		// len check above can't see the original length — use raw_output_len).
		if browserSession && actionType == "assistant_message" && rawOutputLen > fullTextInlineMax {
			fullTextElided = true
		}
		success := successInt != 0
		out = append(out, sessionmsg.ActionRow{
			ActionID:            strconv.FormatInt(actionID, 10),
			SourceEventID:       srcEventID,
			MessageID:           msgID,
			ActionType:          actionType,
			Timestamp:           ts,
			EffortLevel:         effortLevel,
			StopReason:          stopReason,
			ServiceTier:         serviceTier,
			Tool:                rawTool,
			Target:              target,
			Success:             &success,
			DurationMs:          &durationMs,
			FullText:            fullText,
			FullTextElided:      fullTextElided,
			HasFullOutput:       rawOutputLen > 0,
			ErrorMessage:        errMsg,
			PermissionMode:      permMode,
			IsInterrupt:         isInterrupt != 0,
			RequestURL:          requestURL,
			IDSource:            idSource,
			Granularity:         granularity,
			PromptTokensEst:     promptTokensEst,
			ResponseTokensEst:   responseTokensEst,
			UserAttachmentsJSON: userAttachmentsJSON,
		})
	}
	return out, rows.Err()
}
