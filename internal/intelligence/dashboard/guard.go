package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/config"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
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

	// PromptGuard is the prompt guard's own state beside the guard mode: it
	// acts on its own mode when EnforceIndependent is set (the default), so
	// "observe" does not mean a prompt is never stopped. Absent when the
	// config does not load.
	PromptGuard *guardPromptPostureJSON `json:"prompt_guard,omitempty"`

	Counts24h guardCounts `json:"counts_24h"`
	Counts7d  guardCounts `json:"counts_7d"`

	Chain guardChainStatus `json:"chain"`

	// UserPolicy is set only when the configured user guard-policy.toml
	// exists and does NOT load (T-323): the guard dropped it, so its
	// rules are off while built-ins and the org bundle stay in force.
	// The Security page renders it as a read-only banner. Derived by
	// guard.CheckUserPolicy, the same check `observer doctor` and the
	// daemon's user_policy_invalid guard event use.
	UserPolicy *guardUserPolicyJSON `json:"user_policy,omitempty"`

	// HookFailure is what a failing gate hook does, per gate family
	// (T-346): "closed" blocks the call, "open" lets it run unevaluated.
	// Absent when the daemon wired no seam (guardhookfailure.go).
	HookFailure *guardHookFailureJSON `json:"hook_failure,omitempty"`

	// ToolGates is, per hook_block tool, whether its tool-gate hook holds
	// on THIS node and the channel it falls back to when not
	// (guardtoolgates.go). Absent when the daemon wired no seam.
	ToolGates []guardToolGateJSON `json:"tool_gates,omitempty"`

	// Org is the organization's half of the posture (FU-235): which rules
	// the org layer makes block or defer whatever the local mode, and how
	// far its lock reaches here. Absent when no org layer is in force (an
	// individual, un-enrolled node, where Mode is the whole story). Read
	// off the same cached org-override posture the verdict timeline and
	// the approvals POST use (orgOverrides), never derived here.
	Org *guardOrgJSON `json:"org,omitempty"`
}

// guardOrgJSON is /api/guard/summary's org object.
type guardOrgJSON struct {
	// EnforcedRules are the rule ids the org layer makes block or defer in
	// the running mode (guard.OrgOverridePosture.Enforced).
	EnforcedRules []string `json:"enforced_rules"`
	// LocksEveryRule: the org lock reaches every rule on this node (a
	// managed node, or a tenancy this process could not resolve).
	LocksEveryRule bool `json:"locks_every_rule"`
	// Unverifiable: the org bundle does not verify and no verified copy
	// stands in, so every rule is locked.
	Unverifiable bool `json:"unverifiable,omitempty"`
	// Line is the one rendered status line (guard.OrgOverridePosture
	// ModeLine), the same words `observer guard status` prints.
	Line string `json:"line"`
}

// orgSummary maps the org-override posture onto the summary's org object
// (nil when the org layer does not reach this node).
func orgSummary(p guard.OrgOverridePosture, mode string) *guardOrgJSON {
	line := p.ModeLine(mode)
	if line == "" {
		return nil
	}
	enforced := p.Enforced
	if enforced == nil {
		enforced = []string{}
	}
	return &guardOrgJSON{EnforcedRules: enforced, LocksEveryRule: p.LocksEveryRule || p.Unverifiable, Unverifiable: p.Unverifiable, Line: line}
}

// guardUserPolicyJSON is the invalid-user-policy banner payload.
type guardUserPolicyJSON struct {
	Path  string `json:"path"`
	Line  int    `json:"line,omitempty"`
	Error string `json:"error"`
	// FailClosed is the organization's T-327 choice in force on this node
	// (D-221): the daemon's verified guard posture says the enforced gated
	// hooks fail closed while this file does not load, so they are BLOCKED
	// now, not merely missing the developer's rules.
	FailClosed bool `json:"fail_closed,omitempty"`
}

// userPolicyProblem reports the on-disk user policy's load failure, or
// nil when it loads, is absent, or the config cannot be read (the
// summary must never fail on this advisory field).
func (s *Server) userPolicyProblem() *guardUserPolicyJSON {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return nil
	}
	home, _ := os.UserHomeDir()
	st := guard.CheckUserPolicy(cfg.Guard, home, os.ReadFile)
	if !st.Invalid() {
		return nil
	}
	return &guardUserPolicyJSON{Path: st.Path, Line: st.Line, Error: st.Error, FailClosed: s.userPolicyFailClosed()}
}

// userPolicyFailClosed reads the organization's fail_closed choice off the
// daemon's own verified guard posture: the same file every hook on this node
// acts on, so the banner can never claim a block the hooks do not apply. An
// absent or unverifiable posture reads as not fail-closed.
func (s *Server) userPolicyFailClosed() bool {
	resolved, err := config.ResolveGlobalPath(s.opts.ConfigPath)
	if err != nil {
		return false
	}
	ld := guardposture.Load(guardposture.PosturePath(resolved), guardposture.KeyPath(resolved))
	return ld.State == guardposture.StateValid && ld.Posture.Enforced && ld.Posture.UserPolicyFailClosed
}

// guardCounts mirrors store.GuardEventSummary for the wire.
type guardCounts struct {
	Total    int `json:"total"`
	Enforced int `json:"enforced"`
	// EnforcedByOrg is the part of Enforced the organization's policy
	// layer produced (FU-235).
	EnforcedByOrg int            `json:"enforced_by_org"`
	ByDecision    map[string]int `json:"by_decision"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
}

// guardChainStatus is the §10.4 verification result for the page
// header badge.
type guardChainStatus struct {
	OK           bool   `json:"ok"`
	Checked      int    `json:"checked"`
	DivergenceID int64  `json:"divergence_id,omitempty"`
	Detail       string `json:"detail,omitempty"`
	// Breaks counts failing rows by class (FU-236).
	Breaks map[string]int `json:"breaks,omitempty"`
	// ActionlessRewritten counts rows that fail as rewritten with no action
	// id at all: the maintenance shape `observer guard repair-anchors`
	// can prove (store.GuardChainReport).
	ActionlessRewritten int `json:"actionless_rewritten,omitempty"`
	// RepairHint is the documented repair path for what the walk found
	// (store.GuardChainRepairHint), "" when none applies.
	RepairHint string `json:"repair_hint,omitempty"`
}

func toGuardCounts(s store.GuardEventSummary) guardCounts {
	return guardCounts{
		Total: s.Total, Enforced: s.Enforced, EnforcedByOrg: s.EnforcedByOrg,
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
			Breaks: report.Breaks, ActionlessRewritten: report.ActionlessRewritten,
			RepairHint: store.GuardChainRepairHint(report),
		},
		UserPolicy:  s.userPolicyProblem(),
		HookFailure: s.hookFailure(),
		ToolGates:   s.toolGates(),
		Org:         orgSummary(s.orgOverrides(r.Context()), s.opts.GuardMode),
		PromptGuard: s.promptGuardPosture(),
	})
}

// guardPromptPostureJSON is the prompt guard's mode and whether it acts on
// that mode independently of the guard mode ([guard.prompt]).
type guardPromptPostureJSON struct {
	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"`
	EnforceIndependent bool   `json:"enforce_independent"`
	// SetByOrg: the organization's posture decided EnforceIndependent (its
	// guard.mode pin, config.governancePinFollowers), so the page says the
	// stance is the organization's.
	SetByOrg bool `json:"set_by_org,omitempty"`
}

// promptGuardPosture reads [guard.prompt] from the config file, governance
// applied; nil when the config does not load.
func (s *Server) promptGuardPosture() *guardPromptPostureJSON {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return nil
	}
	p := cfg.Guard.Prompt
	return &guardPromptPostureJSON{
		Enabled: p.Enabled, Mode: p.Mode, EnforceIndependent: p.EnforceIndependent,
		SetByOrg: governanceApplied(s.opts.ConfigPath, "guard.prompt.enforce_independent"),
	}
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
	APITurnID    *int64 `json:"api_turn_id,omitempty"`
	Tool         string `json:"tool,omitempty"`
	EventKind    string `json:"event_kind,omitempty"`
	RuleID       string `json:"rule_id"`
	Category     string `json:"category,omitempty"`
	Severity     string `json:"severity,omitempty"`
	Decision     string `json:"decision,omitempty"`
	DegradedFrom string `json:"degraded_from,omitempty"`
	Enforced     bool   `json:"enforced"`
	Source       string `json:"source,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// StoredReason is the row's reason exactly as stored, set only when
	// Reason differs from it: a row written before the org-lock note named
	// its cause reads the cause its stored source establishes
	// (guard.ExplainLegacyOrgLockedReason). The stored row is never
	// rewritten (the audit chain hashes it).
	StoredReason  string `json:"stored_reason,omitempty"`
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
	// SubagentSessionID names the `<root>:agent:<agent>` session whose call
	// this hook-path verdict judged when the row is stored under the root
	// session (store.GuardEventAnchoredRow.SubagentSessionID). Session feed
	// only.
	SubagentSessionID string `json:"subagent_session_id,omitempty"`
	// Layer / LayerLabel say which policy layer produced the verdict, read
	// off Source (guardLayerOf): the org's bundle, the developer's own
	// rules, the project's rules, a node pack (the commit gate S-791 to
	// S-794 is the Code security pack), or the built-in table. Session feed
	// only: on a managed node the Security page can be hidden, and this is
	// then the developer's one place to see where a block came from.
	Layer      string `json:"layer,omitempty"`
	LayerLabel string `json:"layer_label,omitempty"`
	// ProjectRootHash is the sha256 hex of the project the gate matched
	// grants on for this verdict (guard_events.project_root_hash, agent
	// migration 253, GRANT-20), else, for a row that recorded none, of the
	// row's SESSION's project root (guard.HashProjectRoot of
	// store.ProjectRootForSession). Never the raw path. The Security page
	// compares it with the active approvals to say "covered by grant #N"
	// and why an ask was not downgraded (P-232). Populated by
	// /api/guard/events only; empty when neither is known.
	ProjectRootHash string `json:"project_root_hash,omitempty"`
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
	j := guardEventJSON{
		ID: row.ID, Ts: row.TS.UTC().Format(time.RFC3339Nano),
		SessionID: row.SessionID, ActionID: row.ActionID, APITurnID: row.APITurnID,
		Tool: row.Tool, EventKind: row.EventKind,
		RuleID: row.RuleID, Category: row.Category,
		Severity: row.Severity, Decision: row.Decision,
		DegradedFrom: row.DegradedFrom, Enforced: row.Enforced,
		Source: row.Source, Reason: row.Reason,
		TargetExcerpt: row.TargetExcerpt, TaintOrigin: row.TaintOrigin,
	}
	if explained, changed := guard.ExplainLegacyOrgLockedReason(row.Reason, row.RuleID, row.Source); changed {
		j.Reason, j.StoredReason = explained, row.Reason
	}
	return j
}

// toGuardEventJSONAnchored extends toGuardEventJSON with the
// message_id/turn_index a GuardEventAnchoredRow resolved via its LEFT JOIN.
func toGuardEventJSONAnchored(row *store.GuardEventAnchoredRow) guardEventJSON {
	j := toGuardEventJSON(&row.GuardEventRow)
	j.MessageID = row.MessageID
	j.TurnIndex = row.TurnIndex
	j.SubagentSessionID = row.SubagentSessionID
	j.Layer, j.LayerLabel = guardLayerOf(row.Source)
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
	// One project lookup per distinct session on the page, never per row.
	rootHash := map[string]string{}
	projectHash := func(sessionID string) string {
		if sessionID == "" {
			return ""
		}
		h, ok := rootHash[sessionID]
		if !ok {
			root, _ := st.ProjectRootForSession(r.Context(), sessionID)
			h = guard.HashProjectRoot(root)
			rootHash[sessionID] = h
		}
		return h
	}
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
		ev.ProjectRootHash = row.ProjectRootHash
		if ev.ProjectRootHash == "" {
			ev.ProjectRootHash = projectHash(row.SessionID)
		}
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
// by id. Source/Enforced ride only the effective view (G1.5); Project names
// the org project a project-scoped org rule applies to. OrgLocked says the
// organization sets the rule on this node (an org-layer rule the org did not
// mark overridable, or a rule its lock reaches here): the dashboard offers
// no local disable or override for it, and the policy save gates refuse one
// (guardOrgLockedEdits).
type guardRuleJSON struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Observe     string `json:"observe"`
	Enforce     string `json:"enforce"`
	Doc         string `json:"doc"`
	Advice      string `json:"advice,omitempty"`
	Source      string `json:"source,omitempty"`
	Enforced    bool   `json:"enforced,omitempty"`
	Project     string `json:"project,omitempty"`
	Overridable bool   `json:"overridable,omitempty"`
	OrgLocked   bool   `json:"org_locked,omitempty"`
	// OrgNamed says the organization's bundle sets the rule itself (an
	// override on it, or a rule the bundle defines). OrgLocked without
	// OrgNamed is a rule at its own decision that the organization only
	// locks (every rule on a managed node), which the dashboard labels as
	// locked, not as set by the organization (2026-11-12 operator report).
	OrgNamed bool `json:"org_named,omitempty"`
}

// handleGuardRules serves GET /api/guard/rules — the rule list the
// Security page reads (the Rules tab, and resolving a verdict's bare
// rule_id into its human definition).
//
// Default: this install's effective listing (guard.Guard.RuleListing, the
// one list `observer guard rules` prints too): a fresh guard built from the
// ON-DISK config — the same layers the daemon binds at start — with
// overrides applied, disabled rules removed, the user and org layers' rules
// with their source, and the org's project-scoped rules labelled with their
// project. ?catalog=1 serves the built-in catalog (policy.Catalog) instead;
// ?effective=1, the pre-default spelling, is accepted. Any construction
// failure degrades to the built-in catalog (fail-open, like every guard
// surface).
func (s *Server) handleGuardRules(w http.ResponseWriter, r *http.Request) {
	infos := policy.Catalog()
	effective := true
	if v := r.URL.Query().Get("catalog"); v == "1" || strings.EqualFold(v, "true") {
		effective = false
	}
	var posture guard.OrgOverridePosture
	if effective {
		if g := s.listingGuard(r.Context()); g != nil {
			infos = g.RuleListing()
		}
		posture = s.orgOverrides(r.Context())
	}
	out := make([]guardRuleJSON, 0, len(infos))
	for _, r := range infos {
		row := guardRuleJSON{
			ID:       r.ID,
			Category: string(r.Category),
			Severity: r.Severity.String(),
			Observe:  r.Observe.String(),
			Enforce:  r.Enforce.String(),
			Doc:      r.Doc,
			Advice:   r.Advice,
			Source:   r.Source,
			Enforced: r.Enforced,
			Project:  r.Project,
		}
		if effective {
			row.Overridable, row.OrgLocked = guardRuleOrgLock(r, posture)
			row.OrgNamed = r.Source == policy.SourceOrg || posture.Named[r.ID]
		}
		out = append(out, row)
	}
	writeJSON(w, map[string]any{"rules": out})
}

// listingGuard builds the guard the rule listing reads from the on-disk
// config (the G1.5 idiom); nil when the config or the guard cannot be built.
func (s *Server) listingGuard(ctx context.Context) *guard.Guard {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return nil
	}
	home, _ := os.UserHomeDir()
	roots, _ := store.New(s.opts.DB).ProjectRoots(ctx)
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home, KnownProjectRoots: roots, ManagedTenancy: s.managedTenancy(ctx)})
	if err != nil {
		return nil
	}
	return g
}

// guardRuleOrgLock is one listed rule's org posture: overridable when the
// organization marked it so, orgLocked when the organization sets it here -
// its lock reaches the rule on this node (OrgOverridePosture.For), or the
// rule is the org layer's own (an org-wide or project-scoped org rule) and
// the org did not mark it overridable.
func guardRuleOrgLock(r policy.RuleInfo, posture guard.OrgOverridePosture) (overridable, orgLocked bool) {
	overridable, orgLocked = posture.For(r.ID)
	if overridable || r.Overridable {
		return true, false
	}
	return false, orgLocked || r.Source == policy.SourceOrg
}

// guardSimulateSlot admits one guard simulation at a time in this process
// (the daemon runs one dashboard): a run holds the slot's one token.
var guardSimulateSlot = make(chan struct{}, 1)

// guardSimulateChunk is how many captured actions a simulation evaluates
// between context checks.
const guardSimulateChunk = 2000

// acquireGuardSimulateSlot waits for the simulation slot until ctx is
// done. A request already gone never takes it.
func acquireGuardSimulateSlot(ctx context.Context) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case guardSimulateSlot <- struct{}{}:
		return func() { <-guardSimulateSlot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// evaluateCancellable runs eval over inputs in chunks of at most chunk,
// checking ctx before each, and returns the verdicts in input order. The
// guard's per-session state (taint, repeat runs, budget records) lives on
// the Guard, so evaluating in chunks on one Guard gives the verdicts one
// call over every input gives.
func evaluateCancellable(ctx context.Context, inputs []guard.ActionInput, chunk int, eval func([]guard.ActionInput) []guard.ActionVerdict) ([]guard.ActionVerdict, error) {
	return evaluateWithProgress(ctx, inputs, chunk, eval, nil)
}

// evaluateWithProgress is evaluateCancellable reporting each finished chunk's
// size to onChunk (nil reports nothing): a simulation run's progress counter.
func evaluateWithProgress(ctx context.Context, inputs []guard.ActionInput, chunk int, eval func([]guard.ActionInput) []guard.ActionVerdict, onChunk func(n int)) ([]guard.ActionVerdict, error) {
	if chunk < 1 {
		chunk = len(inputs)
	}
	var out []guard.ActionVerdict
	for start := 0; start < len(inputs); start += chunk {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		end := min(start+chunk, len(inputs))
		out = append(out, eval(inputs[start:end])...)
		if onChunk != nil {
			onChunk(end - start)
		}
	}
	return out, ctx.Err()
}

// simulateGone answers a simulation whose request went away (a closed tab,
// a superseded replay) and reports true; false while the request is live.
func simulateGone(ctx context.Context, w http.ResponseWriter) bool {
	if ctx.Err() == nil {
		return false
	}
	http.Error(w, "the guard simulation stopped: its request was closed", http.StatusServiceUnavailable)
	return true
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
	spend, obs, unpriced, substrate, err := s.guardBudgetObservations(r.Context(), st, now, weekStart, monthStart)
	if err != nil {
		writeErr(w, err)
		return
	}
	// The token windows on the same substrate (T-204): the node's token caps
	// ([guard.budget] *_tokens) are what a developer under the token-usage
	// cost display reads and edits, so the card needs their usage too.
	tok, err := st.GuardBudgetTokens(r.Context(), "", now.Truncate(24*time.Hour), weekStart, monthStart)
	if err != nil {
		writeErr(w, err)
		return
	}
	util5h, util7d, _, _ := st.LatestLimitWindows(r.Context())
	writeJSON(w, map[string]any{
		"session_usd": cfg.Guard.Budget.SessionUSD,
		"daily_usd":   cfg.Guard.Budget.DailyUSD,
		"weekly_usd":  cfg.Guard.Budget.WeeklyUSD,
		"monthly_usd": cfg.Guard.Budget.MonthlyUSD,
		"hard":        cfg.Guard.Budget.Hard,
		// The guard's mode: hard only blocks in enforce mode, so a surface
		// reading "hard" alone would claim a block an observe-mode machine
		// never makes (budget-enforcement honesty, 2026-11-18).
		"guard_mode": guardBudgetMode(cfg.Guard.Enabled, cfg.Guard.Mode),
		// The token-denominated caps, one for one with the dollar caps above.
		"session_tokens":     cfg.Guard.Budget.SessionTokens,
		"daily_tokens":       cfg.Guard.Budget.DailyTokens,
		"weekly_tokens":      cfg.Guard.Budget.WeeklyTokens,
		"monthly_tokens":     cfg.Guard.Budget.MonthlyTokens,
		"usage_today_tokens": tok.DailyTokens,
		"usage_week_tokens":  tok.WeeklyTokens,
		"usage_month_tokens": tok.MonthlyTokens,
		// The ORG's composed windows (budgetstatus.go): the numbers above are
		// the node's own config, which on an org-budgeted node is usually
		// all zeros - showing only those read as "no budget" (2026-10-02
		// finding).
		"org_budget":      budgetStatusPayload(budgetwarnfile.StatusPath(cfg.Observer.DBPath), nil),
		"spend_today_usd": spend.DailyUSD,
		"spend_week_usd":  spend.WeeklyUSD,
		"spend_month_usd": spend.MonthlyUSD,
		// Which spend the numbers measure (demo bug #6): "priced" is the
		// guard budget rules' own read; "recorded" (no price table wired)
		// sums only stored costs. unpriced_rows counts the window's rows
		// that read counted as $0.
		"spend_substrate": substrate,
		"unpriced_rows":   unpriced,
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

// guardBudgetMode is the guard mode a budget card reports: "off" when the
// guard is disabled, else the configured mode.
func guardBudgetMode(enabled bool, mode string) string {
	if !enabled || mode == "" {
		return "off"
	}
	return mode
}

// guardBudgetObservations measures the Budget guardrails card on the substrate
// the guard's budget rules compare against (demo bug #6). The daemon's budget
// lookup prices every counted row - a recorded cost when the source recorded
// one, otherwise the price table (cmd/observer/guardwire.go, the advisory
// GuardBudgetSpendPriced read) - but the card summed only the RECORDED cost
// columns, so transcript rows (priced at read time, no recorded cost) were
// invisible: "$0.00 today" and "p95 from n=3 days" on a node the Cost page
// priced at ~$3,469 over 30 days. With a price table it now reads the same
// priced substrate; without one it keeps the recorded read and says so.
func (s *Server) guardBudgetObservations(ctx context.Context, st *store.Store, now, weekStart, monthStart time.Time) (store.GuardBudgetWindows, store.GuardBudgetObserved, int, string, error) {
	day := now.Truncate(24 * time.Hour)
	since := now.Add(-30 * 24 * time.Hour)
	if pricer := guardBudgetCardPricer(s.opts.CostEngine); pricer != nil {
		spend, err := st.GuardBudgetSpendPriced(ctx, "", day, weekStart, monthStart, pricer)
		if err != nil {
			return store.GuardBudgetWindows{}, store.GuardBudgetObserved{}, 0, "", err
		}
		obs, err := st.GuardBudgetObservedStatsPriced(ctx, since, pricer)
		if err != nil {
			return store.GuardBudgetWindows{}, store.GuardBudgetObserved{}, 0, "", err
		}
		return spend.GuardBudgetWindows, obs.GuardBudgetObserved, obs.UnpricedRows, "priced", nil
	}
	spend, err := st.GuardBudgetSpend(ctx, "", day, weekStart, monthStart)
	if err != nil {
		return store.GuardBudgetWindows{}, store.GuardBudgetObserved{}, 0, "", err
	}
	obs, err := st.GuardBudgetObservedStats(ctx, since)
	if err != nil {
		return store.GuardBudgetWindows{}, store.GuardBudgetObserved{}, 0, "", err
	}
	return spend, obs, 0, "recorded", nil
}

// guardBudgetCardPricer is the advisory guard budget pricer over the
// dashboard's cost engine: the same table and the same cost.Table.PriceAt the
// daemon's guard budget lookup prices with. nil without an engine.
func guardBudgetCardPricer(engine *cost.Engine) store.GuardBudgetPricer {
	if engine == nil {
		return nil
	}
	table := engine.Table()
	if table == nil {
		return nil
	}
	return func(model string, at time.Time, sp store.PushTokenSplit) (float64, string, bool) {
		usd, source, ok := table.PriceAt(model, at, cost.TokenBundle{
			Input: sp.Input, Output: sp.Output, CacheRead: sp.CacheRead,
			CacheCreation: sp.CacheCreation, CacheCreation1h: sp.CacheCreation1h,
			Reasoning: sp.Reasoning, WebSearchRequests: sp.WebSearchRequests, Fast: sp.Fast,
		})
		return usd, string(source), ok
	}
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
	// LastUsedAt is the latest verdict this grant's scope covers that an
	// approval downgraded since the grant was made ("" = never used,
	// P-232). Advisory: guard_events does not name the grant that
	// downgraded a verdict, so overlapping grants share a use.
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// handleGuardApprovals serves the §6.3 approvals register (G1.3):
//
//   - GET  → active (non-expired) grants, the `observer guard
//     approvals` list.
//   - POST → grant: {rule_id, scope: session|project|global,
//     session_id?, ttl_hours?}. Idempotent: a grant for the same key
//     (rule, scope, session, project hash) is kept and extended to the
//     later expiry, and the reply carries existing=true (P-232). Project
//     scope anchors to the SESSION's
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
		uses := map[string][]store.GuardApprovalUse{}
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
			ru, ok := uses[a.RuleID]
			if !ok {
				// A failed read leaves "last used" empty; the register
				// itself still lists.
				ru, _ = st.GuardApprovalUses(r.Context(), a.RuleID)
				uses[a.RuleID] = ru
			}
			if last := approvalLastUsed(a, ru); !last.IsZero() {
				j.LastUsedAt = last.UTC().Format(time.RFC3339)
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
		// Lane cli-2: a rule that asks on every use (R-168) takes no grant,
		// so a grant here would be inert; refuse it instead of storing it.
		if policy.AsksEveryUse(req.RuleID) {
			http.Error(w, req.RuleID+" asks on every use and no approval covers it", http.StatusBadRequest)
			return
		}
		// Org-lock gate (Track B): under an org policy bundle only a
		// rule the organization marked `overridable` may be granted a
		// local exception. Refused at CREATION with the reason, so the
		// register never fills with grants that applyApprovals would
		// silently ignore. No bundle = no gate.
		//
		// One exception (request-grants G3): when the organization issued a
		// SOFTEN grant for the rule, the approval IS the developer's per-call
		// confirmation the grant asks for, so it is allowed; the guard only
		// lets it act while that grant also covers the call.
		if _, orgLocked := s.orgOverrideFor(r.Context(), req.RuleID); orgLocked {
			if _, softened := orgclient.SoftenGrantForRule(r.Context(), store.New(s.opts.DB), req.RuleID, s.now()); !softened {
				http.Error(w, "locked by org policy: "+req.RuleID, http.StatusForbidden)
				return
			}
		}
		now := s.now()
		row := store.GuardApprovalRow{
			TS: now, RuleID: req.RuleID, GrantedBy: "dashboard", Channel: "dashboard",
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
		// Grant-or-extend (P-232): a second identical POST (approve pressed
		// again on an old ask row, the Grant form resubmitted) names the
		// existing grant, which keeps the later expiry, instead of adding a
		// duplicate row. existing tells the page to say so.
		id, existing, err := st.GrantGuardApproval(r.Context(), row)
		if err != nil {
			writeErr(w, err)
			return
		}
		resp := map[string]any{"granted": true, "id": id, "rule_id": row.RuleID, "scope": row.Scope, "existing": existing}
		if !row.ExpiresAt.IsZero() {
			resp["expires_at"] = row.ExpiresAt.UTC().Format(time.RFC3339)
		}
		writeJSON(w, resp)
	default:
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// approvalLastUsed folds a rule's approved-verdict uses into grant a's
// "last used": the latest use the grant's scope covers, at or after the
// grant was made. Scope matching mirrors store.ApprovalActiveFor ('once'
// rows never apply, so they are never used).
func approvalLastUsed(a store.GuardApprovalRow, uses []store.GuardApprovalUse) time.Time {
	var last time.Time
	for _, u := range uses {
		covered := false
		switch a.Scope {
		case "global":
			covered = true
		case "session":
			covered = a.SessionID != "" && u.SessionID == a.SessionID
		case "project":
			covered = a.ProjectRootHash != "" && guard.HashProjectRoot(u.ProjectRoot) == a.ProjectRootHash
		}
		if covered && !u.LastTS.Before(a.TS) && u.LastTS.After(last) {
			last = u.LastTS
		}
	}
	return last
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
