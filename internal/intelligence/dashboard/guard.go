package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Security-page endpoints (guard spec §11.2, G7): verdict summary +
// timeline + the §6.5 conformance matrix. Read paths go through the
// store's guard helpers rather than local SQL — the chain
// verification and the canonical row decoding MUST have exactly one
// implementation (store/guard.go), and the row reads are cheap enough
// that reusing them beats duplicating column lists here.

// guardSummaryResponse is GET /api/guard/summary.
type guardSummaryResponse struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	Strict  bool   `json:"strict"`

	Counts24h guardCounts `json:"counts_24h"`
	Counts7d  guardCounts `json:"counts_7d"`

	Chain guardChainStatus `json:"chain"`
}

// guardCounts mirrors store.GuardEventSummary for the wire.
type guardCounts struct {
	Total      int            `json:"total"`
	Enforced   int            `json:"enforced"`
	ByDecision map[string]int `json:"by_decision"`
	BySeverity map[string]int `json:"by_severity"`
	ByCategory map[string]int `json:"by_category"`
}

// guardChainStatus is the §10.4 verification result for the page
// header badge.
type guardChainStatus struct {
	OK           bool   `json:"ok"`
	Checked      int    `json:"checked"`
	DivergenceID int64  `json:"divergence_id,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

func toGuardCounts(s store.GuardEventSummary) guardCounts {
	return guardCounts{
		Total: s.Total, Enforced: s.Enforced,
		ByDecision: s.ByDecision, BySeverity: s.BySeverity, ByCategory: s.ByCategory,
	}
}

// handleGuardSummary serves GET /api/guard/summary.
func (s *Server) handleGuardSummary(w http.ResponseWriter, r *http.Request) {
	st := store.New(s.opts.DB)
	now := s.now()
	day, err := st.SummarizeGuardEvents(r.Context(), now.Add(-24*time.Hour))
	if err != nil {
		http.Error(w, fmt.Sprintf("guard summary 24h: %v", err), http.StatusInternalServerError)
		return
	}
	week, err := st.SummarizeGuardEvents(r.Context(), now.Add(-7*24*time.Hour))
	if err != nil {
		http.Error(w, fmt.Sprintf("guard summary 7d: %v", err), http.StatusInternalServerError)
		return
	}
	report, err := st.VerifyGuardChain(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("guard chain verify: %v", err), http.StatusInternalServerError)
		return
	}
	writeJSON(w, guardSummaryResponse{
		Enabled:   s.opts.GuardEnabled,
		Mode:      s.opts.GuardMode,
		Strict:    s.opts.GuardStrict,
		Counts24h: toGuardCounts(day),
		Counts7d:  toGuardCounts(week),
		Chain: guardChainStatus{
			OK: report.OK, Checked: report.Checked,
			DivergenceID: report.FirstDivergenceID, Detail: report.Detail,
		},
	})
}

// guardEventJSON is one verdict-timeline row. Reason/excerpt are
// node-local operator UI — the privacy gating applies to the ORG
// WIRE (SelectUnpushedSince), not to the operator's own dashboard.
type guardEventJSON struct {
	ID        int64  `json:"id"`
	Ts        string `json:"ts"`
	SessionID string `json:"session_id,omitempty"`
	ActionID  *int64 `json:"action_id,omitempty"`
	// APITurnID is the api_turns.id anchor a proxy-path guard verdict
	// carries (guard_events has three producers with different anchors —
	// see store.GuardEventRow). Added alongside the session-scoped
	// /api/session/<id>/guard endpoint (sessionguard.go) so the Messages
	// tab's merge can attempt exact placement; ActionID remains the only
	// anchor that resolves against a rendered message row today.
	APITurnID     *int64 `json:"api_turn_id,omitempty"`
	Tool          string `json:"tool,omitempty"`
	EventKind     string `json:"event_kind,omitempty"`
	RuleID        string `json:"rule_id"`
	Category      string `json:"category,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Decision      string `json:"decision,omitempty"`
	DegradedFrom  string `json:"degraded_from,omitempty"`
	Enforced      bool   `json:"enforced"`
	Source        string `json:"source,omitempty"`
	Reason        string `json:"reason,omitempty"`
	TargetExcerpt string `json:"target_excerpt,omitempty"`
	TaintOrigin   string `json:"taint_origin,omitempty"`
	// Overridable / OrgLocked are the ORG-GRANTED OVERRIDE posture of
	// this row's rule under the org policy bundle currently on disk
	// (Track B, guard_override.go). They describe the RULE now, not
	// the historical event: "can this still be overridden", which is
	// what the Security page's "Allow for this session" button needs.
	// Both false on an un-enrolled node, where the page renders
	// exactly as it did before the wave.
	Overridable bool `json:"overridable,omitempty"`
	OrgLocked   bool `json:"org_locked,omitempty"`
	// MessageID / TurnIndex resolve ActionID to the upstream
	// actions.message_id / turn_index (a LEFT JOIN — see
	// store.LoadGuardEventsForSessionWithMessageAnchor). Populated only by
	// /api/session/<id>/guard (sessionguard.go); the global
	// /api/guard/events timeline leaves these empty/nil (it doesn't pay the
	// join, and the Security page has no message row to anchor against).
	// This is what the Messages tab's merge (@shared/lib/guardMessages)
	// uses for exact placement instead of guessing from timestamps.
	MessageID string `json:"message_id,omitempty"`
	TurnIndex *int64 `json:"turn_index,omitempty"`
}

// toGuardEventJSON is the single row->wire mapper for guardEventJSON,
// shared by /api/guard/events (this file) and /api/session/<id>/guard
// (sessionguard.go) so the Security page's global timeline and the session
// drawer's interleaved feed can never drift on shape.
//
// Ts is full precision (RFC3339Nano, matching how store.timestamp() stamps
// the column at insert) rather than truncated to whole seconds
// (time.RFC3339) — the Messages tab's merge
// (@shared/lib/guardMessages::mergeGuardIntoTimeline) can fall back to
// nearest-timestamp ordering among several guard events or messages that
// land in the same second, and second-truncation would silently discard
// the sub-second ordering it needs to place them correctly.
func toGuardEventJSON(row *store.GuardEventRow) guardEventJSON {
	return guardEventJSON{
		ID: row.ID, Ts: row.TS.UTC().Format(time.RFC3339Nano),
		SessionID: row.SessionID, ActionID: row.ActionID, APITurnID: row.APITurnID,
		Tool: row.Tool, EventKind: row.EventKind,
		RuleID: row.RuleID, Category: row.Category,
		Severity: row.Severity, Decision: row.Decision,
		DegradedFrom: row.DegradedFrom, Enforced: row.Enforced,
		Source: row.Source, Reason: row.Reason,
		TargetExcerpt: row.TargetExcerpt, TaintOrigin: row.TaintOrigin,
	}
}

// toGuardEventJSONAnchored extends toGuardEventJSON with the
// message_id/turn_index a GuardEventAnchoredRow resolved via its LEFT JOIN.
func toGuardEventJSONAnchored(row *store.GuardEventAnchoredRow) guardEventJSON {
	j := toGuardEventJSON(&row.GuardEventRow)
	j.MessageID = row.MessageID
	j.TurnIndex = row.TurnIndex
	return j
}

// handleGuardEvents serves GET /api/guard/events — the verdict
// timeline. Query params: hours (window, default 168), limit (default
// 200), and the §11.2 filters severity / category / tool / decision
// (exact match, empty = all). Filtering happens in Go over the
// store-loaded window: guard verdicts are low-volume by design
// (allow verdicts never persist), so a filtered reload beats growing
// a bespoke SQL surface.
func (s *Server) handleGuardEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours := 168
	if v, err := strconv.Atoi(q.Get("hours")); err == nil && v > 0 {
		hours = v
	}
	limit := 200
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	wantSeverity := q.Get("severity")
	wantCategory := q.Get("category")
	wantTool := q.Get("tool")
	wantDecision := q.Get("decision")
	wantRule := q.Get("rule_id")
	wantSession := q.Get("session_id")

	st := store.New(s.opts.DB)
	// Over-fetch when filters are active so a filter-heavy view still
	// fills a page; the final slice respects limit.
	fetch := limit
	if wantSeverity != "" || wantCategory != "" || wantTool != "" || wantDecision != "" ||
		wantRule != "" || wantSession != "" {
		fetch = limit * 5
	}
	rows, err := st.LoadRecentGuardEvents(r.Context(), s.now().Add(-time.Duration(hours)*time.Hour), fetch)
	if err != nil {
		http.Error(w, fmt.Sprintf("guard events: %v", err), http.StatusInternalServerError)
		return
	}
	// One org-bundle read for the whole page (cached, TTL-bounded),
	// never one per row.
	orgOverride := s.orgOverrides(r.Context())
	out := make([]guardEventJSON, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		if (wantSeverity != "" && row.Severity != wantSeverity) ||
			(wantCategory != "" && row.Category != wantCategory) ||
			(wantTool != "" && row.Tool != wantTool) ||
			(wantDecision != "" && row.Decision != wantDecision) ||
			(wantRule != "" && row.RuleID != wantRule) ||
			(wantSession != "" && row.SessionID != wantSession) {
			continue
		}
		ev := toGuardEventJSON(row)
		ev.Overridable, ev.OrgLocked = orgOverride.For(row.RuleID)
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, map[string]any{"events": out, "count": len(out)})
}

// guardConformanceJSON is one §6.5 matrix row for the coverage panel.
type guardConformanceJSON struct {
	Client       string `json:"client"`
	Channel      string `json:"channel"`
	PreExecution bool   `json:"pre_execution"`
	CanBlock     bool   `json:"can_block"`
	CanAsk       bool   `json:"can_ask"`
	Notes        string `json:"notes"`
}

// handleGuardConformance serves GET /api/guard/conformance — the
// §6.5 matrix, hook channels first (the matrix order), so the page
// renders enforcement surfaces above the post-hoc tail.
func (s *Server) handleGuardConformance(w http.ResponseWriter, _ *http.Request) {
	matrix := guard.ConformanceMatrix()
	out := make([]guardConformanceJSON, 0, len(matrix))
	for _, e := range matrix {
		out = append(out, guardConformanceJSON{
			Client:       e.Client,
			Channel:      strings.TrimPrefix(e.Channel, "hook:"),
			PreExecution: e.Caps.PreExecution,
			CanBlock:     e.Caps.CanBlock,
			CanAsk:       e.Caps.CanAsk,
			Notes:        e.Notes,
		})
	}
	writeJSON(w, map[string]any{"entries": out})
}

// guardRuleJSON is one rule row on the wire. Multi-row IDs (e.g.
// R-152's write + read rows) appear once per row; the client groups
// by id. Source/Enforced ride only the effective view (G1.5).
type guardRuleJSON struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Observe  string `json:"observe"`
	Enforce  string `json:"enforce"`
	Doc      string `json:"doc"`
	Advice   string `json:"advice,omitempty"`
	Source   string `json:"source,omitempty"`
	Enforced bool   `json:"enforced,omitempty"`
}

// handleGuardRules serves GET /api/guard/rules — the rule catalog the
// Security page uses to resolve a verdict's bare rule_id into its
// human definition.
//
// Default: the built-in catalog (policy.Catalog). With ?effective=1
// (G1.5) it constructs a fresh guard from the ON-DISK config — the
// same layers the daemon binds at start — and serves EffectiveRules:
// built-ins with overrides applied, disabled rules removed, plus
// user/project/org layer rules with their source attributed, so a
// custom rule's verdict resolves in the UI instead of degrading to a
// bare mono ID. Any construction failure degrades to the built-in
// catalog (fail-open, like every guard surface).
func (s *Server) handleGuardRules(w http.ResponseWriter, r *http.Request) {
	infos := policy.Catalog()
	if v := r.URL.Query().Get("effective"); v == "1" || strings.EqualFold(v, "true") {
		if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
			home, _ := os.UserHomeDir()
			roots, _ := store.New(s.opts.DB).ProjectRoots(r.Context())
			if g, gerr := guard.New(guard.Options{Config: cfg.Guard, Home: home, KnownProjectRoots: roots}); gerr == nil {
				infos = g.EffectiveRules()
			}
		}
	}
	out := make([]guardRuleJSON, 0, len(infos))
	for _, r := range infos {
		out = append(out, guardRuleJSON{
			ID:       r.ID,
			Category: string(r.Category),
			Severity: r.Severity.String(),
			Observe:  r.Observe.String(),
			Enforce:  r.Enforce.String(),
			Doc:      r.Doc,
			Advice:   r.Advice,
			Source:   r.Source,
			Enforced: r.Enforced,
		})
	}
	writeJSON(w, map[string]any{"rules": out})
}

// handleGuardSimulate serves GET /api/guard/simulate?hours=&enforce= —
// the dashboard face of `observer guard simulate` (G1.2): replay
// captured history against the CURRENT on-disk policy with a fresh
// engine. Nothing persists; the live guard state is untouched. The
// mode-control consent dialog calls it with enforce=1 to show "what
// would last week have BLOCKED" before the operator promotes.
//
// Policy source: the config FILE (loadConfigForDashboard), not the
// running daemon's bound config — deliberately, so a saved-but-not-
// yet-restarted policy edit is what gets simulated (the dialog's
// evidence matches what enforce would do after the restart).
func (s *Server) handleGuardSimulate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	hours := 168
	if v, err := strconv.Atoi(q.Get("hours")); err == nil && v >= 1 && v <= 2160 {
		hours = v
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	mode := cfg.Guard.Mode
	if q.Get("enforce") == "1" || strings.EqualFold(q.Get("enforce"), "true") {
		mode = "enforce"
		cfg.Guard.Mode = "enforce"
	}
	st := store.New(s.opts.DB)
	home, _ := os.UserHomeDir()
	roots, _ := st.ProjectRoots(r.Context())
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home, KnownProjectRoots: roots})
	if err != nil {
		writeErr(w, fmt.Errorf("construct guard: %w", err))
		return
	}
	const replayCap = 50000
	inputs, err := st.LoadGuardReplayInputs(r.Context(), s.now().Add(-time.Duration(hours)*time.Hour), replayCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	verdicts := g.EvaluateActions(inputs)
	byRule := map[string]int{}
	byRuleBlocking := map[string]int{}
	byDecision := map[string]int{}
	wouldBlock := 0
	for _, v := range verdicts {
		byRule[v.Verdict.RuleID]++
		dec := v.Verdict.Decision.String()
		byDecision[dec]++
		if mode == "enforce" && (dec == "deny" || dec == "ask") {
			wouldBlock++
			byRuleBlocking[v.Verdict.RuleID]++
		}
	}
	writeJSON(w, map[string]any{
		"window_hours": hours,
		"mode":         mode,
		"scanned":      len(inputs),
		"verdicts":     len(verdicts),
		"would_block":  wouldBlock,
		"capped":       len(inputs) == replayCap,
		"by_rule":      byRule,
		// by_rule_blocking splits would_block per rule (G2.1): only
		// deny/ask-class verdicts under the enforce projection, so the
		// readiness review ranks rules by what would actually block —
		// by_rule alone conflates flag-only noise with blocking load.
		"by_rule_blocking": byRuleBlocking,
		"by_decision":      byDecision,
	})
}

// handleGuardBudget serves GET /api/guard/budget — the G2.4 budget
// guardrails basis: configured [guard.budget] thresholds from the
// ON-DISK config, today's spend on the exact substrate the §12.1
// enforcement compares against (GuardBudgetSpend), and the trailing
// 30-day observed-spend distribution (GuardBudgetObservedStats) the
// suggested values derive from. The suggestion math (headroom +
// rounding) lives in the UI — this endpoint reports observations.
func (s *Server) handleGuardBudget(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	st := store.New(s.opts.DB)
	now := s.now()
	weekStart := now.Add(-7 * 24 * time.Hour)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	spend, err := st.GuardBudgetSpend(r.Context(), "", now.Truncate(24*time.Hour), weekStart, monthStart)
	if err != nil {
		writeErr(w, err)
		return
	}
	obs, err := st.GuardBudgetObservedStats(r.Context(), now.Add(-30*24*time.Hour))
	if err != nil {
		writeErr(w, err)
		return
	}
	util5h, util7d, _, _ := st.LatestLimitWindows(r.Context())
	writeJSON(w, map[string]any{
		"session_usd":     cfg.Guard.Budget.SessionUSD,
		"daily_usd":       cfg.Guard.Budget.DailyUSD,
		"weekly_usd":      cfg.Guard.Budget.WeeklyUSD,
		"monthly_usd":     cfg.Guard.Budget.MonthlyUSD,
		"hard":            cfg.Guard.Budget.Hard,
		"spend_today_usd": spend.DailyUSD,
		"spend_week_usd":  spend.WeeklyUSD,
		"spend_month_usd": spend.MonthlyUSD,
		"window_days":     30,
		"sessions":        obs.Sessions,
		"session_p95_usd": obs.SessionP95USD,
		"session_max_usd": obs.SessionMaxUSD,
		"days":            obs.Days,
		"daily_p95_usd":   obs.DailyP95USD,
		"daily_max_usd":   obs.DailyMaxUSD,
		"window": map[string]any{
			"util_5h":          util5h,
			"util_7d":          util7d,
			"util_5h_warn":     cfg.Guard.Budget.Window.Util5hWarn,
			"util_5h_deny":     cfg.Guard.Budget.Window.Util5hDeny,
			"util_weekly_warn": cfg.Guard.Budget.Window.UtilWeeklyWarn,
			"util_weekly_deny": cfg.Guard.Budget.Window.UtilWeeklyDeny,
		},
	})
}

// guardApprovalJSON is one §6.3 exception-register row on the wire.
type guardApprovalJSON struct {
	ID              int64  `json:"id"`
	Ts              string `json:"ts"`
	RuleID          string `json:"rule_id"`
	Scope           string `json:"scope"`
	SessionID       string `json:"session_id,omitempty"`
	ProjectRootHash string `json:"project_root_hash,omitempty"`
	GrantedBy       string `json:"granted_by,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
}

// handleGuardApprovals serves the §6.3 approvals register (G1.3):
//
//   - GET  → active (non-expired) grants, the `observer guard
//     approvals` list.
//   - POST → grant: {rule_id, scope: session|project|global,
//     session_id?, ttl_hours?}. Project scope anchors to the SESSION's
//     project root (resolved via the store, hashed at the guard layer
//     — never the raw path in the row), so the UI can grant "for this
//     project" straight from a verdict row. DB write, no restart.
//
// Mutations reuse the exact store seams the CLI uses (one owner per
// table); this handler is a thin HTTP adapter.
func (s *Server) handleGuardApprovals(w http.ResponseWriter, r *http.Request) {
	st := store.New(s.opts.DB)
	switch r.Method {
	case http.MethodGet:
		rows, err := st.ActiveGuardApprovals(r.Context(), "", s.now())
		if err != nil {
			writeErr(w, err)
			return
		}
		out := make([]guardApprovalJSON, 0, len(rows))
		for _, a := range rows {
			j := guardApprovalJSON{
				ID: a.ID, Ts: a.TS.UTC().Format(time.RFC3339),
				RuleID: a.RuleID, Scope: a.Scope,
				SessionID: a.SessionID, ProjectRootHash: a.ProjectRootHash,
				GrantedBy: a.GrantedBy,
			}
			if !a.ExpiresAt.IsZero() {
				j.ExpiresAt = a.ExpiresAt.UTC().Format(time.RFC3339)
			}
			out = append(out, j)
		}
		writeJSON(w, map[string]any{"approvals": out})
	case http.MethodPost:
		var req struct {
			RuleID    string  `json:"rule_id"`
			Scope     string  `json:"scope"`
			SessionID string  `json:"session_id"`
			TTLHours  float64 `json:"ttl_hours"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.RuleID == "" {
			http.Error(w, "rule_id required", http.StatusBadRequest)
			return
		}
		// Org-lock gate (Track B): under an org policy bundle only a
		// rule the organization marked `overridable` may be granted a
		// local exception. Refused at CREATION with the reason, so the
		// register never fills with grants that applyApprovals would
		// silently ignore. No bundle = no gate.
		if _, orgLocked := s.orgOverrideFor(r.Context(), req.RuleID); orgLocked {
			http.Error(w, "locked by org policy: "+req.RuleID, http.StatusForbidden)
			return
		}
		now := s.now()
		row := store.GuardApprovalRow{
			TS: now, RuleID: req.RuleID, GrantedBy: "dashboard",
		}
		switch req.Scope {
		case "session":
			if req.SessionID == "" {
				http.Error(w, "session scope needs session_id", http.StatusBadRequest)
				return
			}
			row.Scope, row.SessionID = "session", req.SessionID
		case "project":
			// Anchor to the session's project root. The hash — never
			// the raw path — lands in the row (§6.3 / privacy posture).
			root, err := st.ProjectRootForSession(r.Context(), req.SessionID)
			if err != nil {
				writeErr(w, err)
				return
			}
			if root == "" {
				http.Error(w, "project scope: session has no resolvable project root", http.StatusBadRequest)
				return
			}
			row.Scope, row.ProjectRootHash = "project", guard.HashProjectRoot(root)
		case "global":
			row.Scope = "global"
		default:
			http.Error(w, `scope must be one of "session", "project", "global"`, http.StatusBadRequest)
			return
		}
		if req.TTLHours < 0 {
			http.Error(w, "ttl_hours must be >= 0 (0 = never expires)", http.StatusBadRequest)
			return
		}
		if req.TTLHours > 0 {
			row.ExpiresAt = now.Add(time.Duration(req.TTLHours * float64(time.Hour)))
		}
		id, err := st.InsertGuardApproval(r.Context(), row)
		if err != nil {
			writeErr(w, err)
			return
		}
		resp := map[string]any{"granted": true, "id": id, "rule_id": row.RuleID, "scope": row.Scope}
		if !row.ExpiresAt.IsZero() {
			resp["expires_at"] = row.ExpiresAt.UTC().Format(time.RFC3339)
		}
		writeJSON(w, resp)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// guardMCPServerJSON is one MCP inventory row: a configured server
// joined with its pin status (or a pinned-but-absent orphan).
type guardMCPServerJSON struct {
	Client    string `json:"client"`
	Name      string `json:"name"`
	Transport string `json:"transport,omitempty"`
	Status    string `json:"status"` // unpinned | pinned | approved | changed…
	ToolsSeen bool   `json:"tools_seen"`
	Command   string `json:"command,omitempty"`
	Present   bool   `json:"present"` // false = pinned but absent from any config
}

// handleGuardMCP serves the §9 MCP-security panel (G1.6):
//
//   - GET → the `observer guard mcp list` join: every supported
//     client's configured MCP servers (read-only config probes via the
//     locate table) merged with the guard_pins rows.
//   - POST /api/guard/mcp/approve {server, client?} → the `observer
//     guard mcp approve` status transition through the same one-owner
//     store helper. Unlike the standalone CLI, no fresh config scan
//     runs first: this dashboard always runs inside the daemon, whose
//     watcher re-scans MCP configs on change, so pins are current by
//     construction; a post-approval drift still raises R-302.
func (s *Server) handleGuardMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		writeErr(w, fmt.Errorf("resolve home: %w", err))
		return
	}
	servers, issues := mcpsec.Inventory(locate.Locations(home), nil)
	pinRows, err := store.New(s.opts.DB).LoadGuardPins(r.Context(), "mcp_server")
	if err != nil {
		writeErr(w, err)
		return
	}
	type key struct{ client, name string }
	pinned := map[key]store.GuardPinRow{}
	for _, p := range pinRows {
		pinned[key{p.Client, p.Name}] = p
	}
	out := make([]guardMCPServerJSON, 0, len(servers)+4)
	seen := map[key]bool{}
	for _, sv := range servers {
		k := key{sv.Client, sv.Name}
		seen[k] = true
		row := guardMCPServerJSON{
			Client: sv.Client, Name: sv.Name, Transport: sv.Transport,
			Status: "unpinned", Command: sv.Command, Present: true,
		}
		if p, ok := pinned[k]; ok {
			row.Status = p.Status
			if h, decoded := mcpsec.DecodePinHash(p.PinHash); decoded && h.Tools != "" {
				row.ToolsSeen = true
			}
		}
		out = append(out, row)
	}
	for _, p := range pinRows {
		if seen[key{p.Client, p.Name}] {
			continue
		}
		row := guardMCPServerJSON{Client: p.Client, Name: p.Name, Status: p.Status, Present: false}
		if h, decoded := mcpsec.DecodePinHash(p.PinHash); decoded && h.Tools != "" {
			row.ToolsSeen = true
		}
		out = append(out, row)
	}
	writeJSON(w, map[string]any{"servers": out, "issues": issues})
}

// handleGuardMCPApprove serves POST /api/guard/mcp/approve.
func (s *Server) handleGuardMCPApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Server string `json:"server"`
		Client string `json:"client"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Server == "" {
		http.Error(w, "server required", http.StatusBadRequest)
		return
	}
	n, err := store.New(s.opts.DB).UpdateGuardPinStatus(r.Context(), "mcp_server", req.Server, req.Client, "approved", s.now())
	if err != nil {
		writeErr(w, err)
		return
	}
	if n == 0 {
		http.Error(w, fmt.Sprintf("no pin for server %q", req.Server), http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"approved": true, "server": req.Server, "pins": n})
}

// handleGuardApprovalDelete serves DELETE /api/guard/approvals/{id} —
// the `observer guard revoke` surface.
func (s *Server) handleGuardApprovalDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/guard/approvals/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "approval id required", http.StatusBadRequest)
		return
	}
	existed, err := store.New(s.opts.DB).DeleteGuardApproval(r.Context(), id)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !existed {
		http.Error(w, "no such approval", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"revoked": true, "id": id})
}
