package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// toGuardApprovalJSON converts one store.GuardApprovalRow to the wire
// shape guard.go's handleGuardApprovals already defines — reused here
// rather than duplicated field-by-field a second time.
func toGuardApprovalJSON(a store.GuardApprovalRow) guardApprovalJSON {
	j := guardApprovalJSON{
		ID: a.ID, Ts: a.TS.UTC().Format(time.RFC3339),
		RuleID: a.RuleID, Scope: a.Scope,
		SessionID: a.SessionID, ProjectRootHash: a.ProjectRootHash,
		GrantedBy: a.GrantedBy,
	}
	if !a.ExpiresAt.IsZero() {
		j.ExpiresAt = a.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return j
}

// PHASE-3b-DASHBOARD: the prompt-submit intervention feature's own
// dashboard surface (docs/plans/prompt-submit-intervention-exploration-
// 2026-09-07.md §8.2, this build's task item 4). [guard.prompt] already
// round-trips through PUT /api/config/section/guard (settings.go); this
// file is the Security-page READ + ACTION surface: live status, the
// event timeline scoped to prompt-submit verdicts, the detector
// vocabulary, and the two mutating actions the Prompt guard card
// exposes (clear a stuck reconsider grant, revoke an allow).
//
// PRIVACY INVARIANT (mirrors promptbridge.go's own canary contract):
// every response type in this file is built from fields that are
// ALREADY content-free by construction upstream — guard_events'
// target_excerpt for a KindUserPrompt row is pv.Fingerprint (an opaque
// sha256 hex digest, never a matched value or prompt span — see
// ActionVerdictFromPrompt's doc comment), and Reason is a stable
// "detected TYPE×N ... in the prompt text" summary
// (matchPromptFindings/matchSecretsOnAPIRequest) that names detector
// TYPES and COUNTS only. Nothing here re-reads the raw prompt or a
// finding's matched value. Pinned by TestGuardPromptEventsNeverLeaksCanary.

// promptEventReasonPattern matches the content-free "detected TYPE×N,
// TYPE2×N2 in the prompt text" fragment BOTH matchPromptFindings
// (R-190) and matchSecretsOnAPIRequest (R-172, KindUserPrompt branch)
// render — the two rules use IDENTICAL wording for a KindUserPrompt
// event (see matchSecretsOnAPIRequest's surface variable), so one
// pattern parses the detector list for either rule id. NOT anchored at
// the start: the full stored Reason is "<rule Doc>: detected ... in
// the prompt text [outcome=X] Advice: ..." (policy's standard
// Doc-plus-matcher-detail reason format, see rules_exfil.go's R-172/
// R-190 KindUserPrompt rows), so the "detected ..." fragment sits
// after a rule-specific prefix sentence, never at position 0.
var promptEventReasonPattern = regexp.MustCompile(`detected (.+?) in the prompt text`)

// promptEventOutcomePattern matches the "[outcome=X]" marker
// ActionVerdictFromPrompt inserts whenever pv.Outcome != "". NOT
// end-anchored: an "Advice: ..." sentence (rules_exfil.go's Doc rows
// all carry one) follows it in the stored Reason when the underlying
// Verdict has Advice set, per store.PersistGuardVerdicts' " Advice: "
// += .
var promptEventOutcomePattern = regexp.MustCompile(`\[outcome=([a-z]+)\]`)

// parsePromptDetectors extracts the detector TYPE ids (never values)
// from a guard_events Reason string, e.g. "credit_card×1, github_pat×2"
// -> ["credit_card", "github_pat"]. Returns nil for a reason with no
// "detected ... in the prompt text" prefix (a degraded-scan warning,
// which by definition found nothing — see promptguard.go's
// degradedScanReason).
func parsePromptDetectors(reason string) []string {
	m := promptEventReasonPattern.FindStringSubmatch(reason)
	if m == nil {
		return nil
	}
	parts := strings.Split(m[1], ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if i := strings.IndexByte(p, '×'); i > 0 { // "×"
			p = p[:i]
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parsePromptOutcome derives the outcome label for the wire
// (task item 2b vocabulary: asked/confirmed/blocked/warned/redacted/
// degraded:<cause>). degradedFrom, when set, wins — it is the more
// specific "why" signal (a channel-capability degrade or an unscanned
// payload) an operator debugging the feature wants to see first. Next
// is the "[outcome=X]" suffix ActionVerdictFromPrompt always appends
// when pv.Outcome is set. The decision-based fallback only fires for
// the rare row with neither (defensive; every live code path sets
// pv.Outcome today).
func parsePromptOutcome(reason, decision, degradedFrom string) string {
	if degradedFrom != "" {
		return "degraded:" + degradedFrom
	}
	if m := promptEventOutcomePattern.FindStringSubmatch(reason); m != nil {
		return m[1]
	}
	switch decision {
	case "deny":
		return "blocked"
	case "ask":
		return "asked"
	case "flag":
		return "warned"
	case "allow":
		return "allowed"
	}
	return ""
}

// promptLaneFor derives which lane produced the event (task item 2b:
// "lane (hook|proxy)"). guard_events carries no dedicated lane column
// (see internal/guard/proxyguard.go::scanPrompt vs
// cmd/observer/hook.go::makePromptGuardPersist) — but the two callers
// populate ActionInput.Tool differently: the hook lane always sets it
// to the invoking CLI tool name, the proxy lane never sets it (only
// SessionID/Target/Timestamp). Tool!="" is therefore a reliable
// derived signal, not a stored fact — documented here rather than
// silently assumed.
func promptLaneFor(tool string) string {
	if tool != "" {
		return "hook"
	}
	return "proxy"
}

// promptRuleIDs is the R-172/R-190 pair the prompt-submit lane
// evaluates on KindUserPrompt events (contract §5.6) — used to filter
// the shared guard_events store and the shared guard_approvals table
// down to this feature's own rows.
var promptRuleIDs = map[string]bool{"R-172": true, "R-190": true}

// ---- GET /api/guard/prompt/status ----

type promptStatusConfigJSON struct {
	Enabled            bool   `json:"enabled"`
	Mode               string `json:"mode"`
	HookLane           bool   `json:"hook_lane"`
	ProxyLane          bool   `json:"proxy_lane"`
	ReconsiderTTL      string `json:"reconsider_ttl"`
	ReconsiderMinDelay string `json:"reconsider_min_delay"`
	SuppressInCode     bool   `json:"suppress_in_code"`
	MaxFindings        int    `json:"max_findings"`
	EnforceIndependent bool   `json:"enforce_independent"`
	AllowPatternCount  int    `json:"allow_pattern_count"`
	EffectiveHookLane  string `json:"effective_hook_lane_state"`
}

type promptClientJSON struct {
	Tool       string `json:"tool"`
	PromptLane string `json:"prompt_lane"`
	Mechanism  string `json:"mechanism,omitempty"`
	AutoWired  bool   `json:"auto_wired"`
	// WireState is a STATIC classification derived from the registry
	// row only (never a live check) — "auto_wired" (observer init/
	// auto-register can write this tool's hook config) or
	// "documented_only" (a tested receiver exists, but no writer —
	// the operator must wire it by hand, or it needs a live probe to
	// even know). Use the "Probe hooks" action for whether a
	// REGISTERED hook actually blocks today.
	WireState string `json:"wire_state"`
}

type promptReconsiderRowJSON struct {
	Fingerprint string `json:"fingerprint"`
	SessionID   string `json:"session_id,omitempty"`
	Tool        string `json:"tool,omitempty"`
	Detectors   string `json:"detectors,omitempty"`
	WarnedAt    string `json:"warned_at"`
	ConfirmedAt string `json:"confirmed_at,omitempty"`
	ExpiresAt   string `json:"expires_at"`
	Expired     bool   `json:"expired"`
}

type promptStatusResponse struct {
	GuardEnabled      bool                      `json:"guard_enabled"`
	GuardMode         string                    `json:"guard_mode"`
	Config            promptStatusConfigJSON    `json:"config"`
	EffectiveModes    map[string]string         `json:"effective_modes"`
	Clients           []promptClientJSON        `json:"clients"`
	ReconsiderTotal   int                       `json:"reconsider_total"`
	ReconsiderExpired int                       `json:"reconsider_expired"`
	Pending           []promptReconsiderRowJSON `json:"pending"`
	Approvals         []guardApprovalJSON       `json:"approvals"`
}

// handleGuardPromptStatus serves GET /api/guard/prompt/status — the
// Prompt guard card's status header (task item 2a): effective mode,
// which lanes are on, which clients are wired vs documented-only, the
// live reconsider-once grant count + pending rows, and active
// R-172/R-190 approvals (esp. global/no-TTL ones — surfaced
// prominently by the caller, same posture as `observer guard prompt
// status`'s printPromptApprovals).
func (s *Server) handleGuardPromptStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	p := cfg.Guard.Prompt

	effective := map[string]string{}
	for _, id := range scrub.DetectorNames() {
		effective[id] = string(guard.EffectivePromptMode(p.Mode, p.Detectors, id))
	}

	var clients []promptClientJSON
	for _, c := range integration.Capabilities() {
		if c.PromptLane == integration.PromptLaneNone {
			continue
		}
		wireState := "documented_only"
		if c.Hook.Mechanism != integration.HookNone && c.Hook.AutoWired {
			wireState = "auto_wired"
		}
		clients = append(clients, promptClientJSON{
			Tool:       c.Tool,
			PromptLane: string(c.PromptLane),
			Mechanism:  string(c.Hook.Mechanism),
			AutoWired:  c.Hook.AutoWired,
			WireState:  wireState,
		})
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].Tool < clients[j].Tool })

	st := store.New(s.opts.DB)
	now := s.now()
	total, expired, err := st.CountPromptReconsider(r.Context(), now)
	if err != nil {
		writeErr(w, err)
		return
	}
	pendingRows, err := st.ListPromptReconsider(r.Context(), 100)
	if err != nil {
		writeErr(w, err)
		return
	}
	pending := make([]promptReconsiderRowJSON, 0, len(pendingRows))
	for _, row := range pendingRows {
		j := promptReconsiderRowJSON{
			Fingerprint: row.Fingerprint,
			SessionID:   row.SessionID,
			Tool:        row.Tool,
			Detectors:   row.Detectors,
			WarnedAt:    row.WarnedAt.UTC().Format(time.RFC3339),
			ExpiresAt:   row.ExpiresAt.UTC().Format(time.RFC3339),
			Expired:     now.After(row.ExpiresAt),
		}
		if !row.ConfirmedAt.IsZero() {
			j.ConfirmedAt = row.ConfirmedAt.UTC().Format(time.RFC3339)
		}
		pending = append(pending, j)
	}

	approvalRows, err := st.ActiveGuardApprovals(r.Context(), "", now)
	if err != nil {
		writeErr(w, err)
		return
	}
	var approvals []guardApprovalJSON
	for _, a := range approvalRows {
		if !promptRuleIDs[a.RuleID] {
			continue
		}
		approvals = append(approvals, toGuardApprovalJSON(a))
	}

	writeJSON(w, promptStatusResponse{
		GuardEnabled: cfg.Guard.Enabled,
		GuardMode:    cfg.Guard.Mode,
		Config: promptStatusConfigJSON{
			Enabled: p.Enabled, Mode: p.Mode, HookLane: p.HookLane, ProxyLane: p.ProxyLane,
			ReconsiderTTL: p.ReconsiderTTL, ReconsiderMinDelay: p.ReconsiderMinDelay, SuppressInCode: p.SuppressInCode,
			MaxFindings: p.MaxFindings, EnforceIndependent: p.EnforceIndependent,
			AllowPatternCount: len(p.Allow),
			EffectiveHookLane: promptEffectiveHookLaneState(cfg.Guard.Enabled, cfg.Guard.Mode, p),
		},
		EffectiveModes:    effective,
		Clients:           clients,
		ReconsiderTotal:   total,
		ReconsiderExpired: expired,
		Pending:           pending,
		Approvals:         approvals,
	})
}

// promptEffectiveHookLaneState mirrors cmd/observer/guard_prompt.go's
// printPromptConfigSummary derivation (the two can't literally share
// code — that file is main-package CLI, this is the dashboard server —
// but both read the same four config fields with the same three-way
// off/observe-only/active logic, so a drift in ONE place is a drift in
// wording only, never in which state is reported).
func promptEffectiveHookLaneState(guardEnabled bool, guardMode string, p config.GuardPromptConfig) string {
	if !(guardEnabled && guardMode != "off" && p.Enabled && p.HookLane) {
		return "off"
	}
	if p.EnforceIndependent || guardMode == "enforce" {
		return "active"
	}
	return "observe_only"
}

// ---- GET /api/guard/prompt/events ----

type promptEventJSON struct {
	ID          int64    `json:"id"`
	Ts          string   `json:"ts"`
	SessionID   string   `json:"session_id,omitempty"`
	Tool        string   `json:"tool,omitempty"`
	Lane        string   `json:"lane"`
	RuleID      string   `json:"rule_id"`
	Category    string   `json:"category,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Decision    string   `json:"decision,omitempty"`
	Outcome     string   `json:"outcome,omitempty"`
	Enforced    bool     `json:"enforced"`
	Detectors   []string `json:"detectors,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

// handleGuardPromptEvents serves GET /api/guard/prompt/events?since=&
// limit=&detector=&outcome= (task item 2b/4) — guard_events rows
// scoped to event_kind=user_prompt (KindUserPrompt), which covers
// BOTH R-172 (secret-in-prompt) and R-190 (PII-in-prompt) hits without
// conflating them with R-172's OTHER surfaces (shell args, proxy
// egress on a non-prompt request). since is a Go duration string
// ("24h", "30m"; default "168h", matching /api/guard/events'
// hours=168 default). NEVER any matched value or prompt/target text —
// see the package doc comment's privacy invariant.
func (s *Server) handleGuardPromptEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	since := 168 * time.Hour
	if v := q.Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			since = d
		}
	}
	limit := 200
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 1000 {
		limit = v
	}
	wantDetector := q.Get("detector")
	wantOutcome := q.Get("outcome")
	// session_id isn't in the task's original query-param list but is
	// the cheapest way for the Session Detail Overview tab's small
	// "Prompt guard" line (task item 3) to scope this same endpoint to
	// one session instead of fetching + filtering the whole window
	// client-side. Additive, defaults to "" (no filter).
	wantSession := q.Get("session_id")

	st := store.New(s.opts.DB)
	fetch := limit * 5 // event_kind isn't filterable in SQL by this loader; over-fetch then filter in Go
	rows, err := st.LoadRecentGuardEvents(r.Context(), s.now().Add(-since), fetch)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]promptEventJSON, 0, limit)
	for i := range rows {
		row := &rows[i]
		if row.EventKind != "user_prompt" {
			continue
		}
		if wantSession != "" && row.SessionID != wantSession {
			continue
		}
		detectors := parsePromptDetectors(row.Reason)
		outcome := parsePromptOutcome(row.Reason, row.Decision, row.DegradedFrom)
		if wantDetector != "" {
			found := false
			for _, d := range detectors {
				if d == wantDetector {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if wantOutcome != "" && outcome != wantOutcome {
			continue
		}
		out = append(out, promptEventJSON{
			ID: row.ID, Ts: row.TS.UTC().Format(time.RFC3339),
			SessionID: row.SessionID, Tool: row.Tool, Lane: promptLaneFor(row.Tool),
			RuleID: row.RuleID, Category: row.Category, Severity: row.Severity,
			Decision: row.Decision, Outcome: outcome, Enforced: row.Enforced,
			Detectors: detectors, Fingerprint: row.TargetExcerpt,
		})
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, map[string]any{"events": out, "count": len(out)})
}

// ---- GET /api/guard/prompt/detectors ----

type promptDetectorJSON struct {
	ID            string `json:"id"`
	Class         string `json:"class"`
	DefaultMode   string `json:"default_mode"`
	EffectiveMode string `json:"effective_mode"`
	Overridden    bool   `json:"overridden"`
}

// handleGuardPromptDetectors serves GET /api/guard/prompt/detectors —
// the full detector vocabulary [guard.prompt.detectors] keys may name
// (scrub.DetectorNames()), each with its class, the configured
// override (if any) and the resolved effective mode after the
// stricter-wins-with-floor clamp (guard.EffectivePromptMode). Backs
// both the Settings detector-override editor's "what else exists
// beyond the fixed set" and the Security page's per-detector
// breakdown.
func (s *Server) handleGuardPromptDetectors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, err)
		return
	}
	p := cfg.Guard.Prompt
	names := scrub.DetectorNames()
	sort.Strings(names)
	out := make([]promptDetectorJSON, 0, len(names))
	for _, id := range names {
		class, _ := scrub.DetectorClass(id)
		override, overridden := p.Detectors[id]
		defaultMode := p.Mode
		if overridden {
			defaultMode = override
		}
		out = append(out, promptDetectorJSON{
			ID: id, Class: class, DefaultMode: defaultMode,
			EffectiveMode: string(guard.EffectivePromptMode(p.Mode, p.Detectors, id)),
			Overridden:    overridden,
		})
	}
	writeJSON(w, map[string]any{"detectors": out})
}

// ---- POST /api/guard/prompt/clear ----

// handleGuardPromptClear serves POST /api/guard/prompt/clear (task
// item 2c/4) — the "clear reconsider row" action: pass {"fingerprint":
// "..."} to remove one grant (forcing a fresh ask-once interrupt on
// the next identical resend) or {"all": true} to clear every pending
// grant. Mirrors `observer guard prompt clear`.
func (s *Server) handleGuardPromptClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
		All         bool   `json:"all"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.All == (req.Fingerprint != "") {
		http.Error(w, "pass exactly one of: fingerprint, or all=true", http.StatusBadRequest)
		return
	}
	st := store.New(s.opts.DB)
	if req.All {
		n, err := st.DeleteAllPromptReconsider(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"cleared": n})
		return
	}
	existed, err := st.DeletePromptReconsider(r.Context(), req.Fingerprint)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !existed {
		http.Error(w, "no reconsider-once grant found for that fingerprint", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"cleared": 1, "fingerprint": req.Fingerprint})
}

// ---- DELETE /api/guard/prompt/allow/{id} ----

// handleGuardPromptAllowDelete serves DELETE /api/guard/prompt/allow/
// <id> (task item 2c/4) — the "revoke grant" action, scoped to the
// Prompt guard card. Delegates to the same store.DeleteGuardApproval
// the generic /api/guard/approvals/<id> route already uses (single
// owner of the guard_approvals table, CLAUDE.md rule 4); this route
// exists so the Security page's Prompt guard card can link a
// revoke button directly at a prompt-scoped grant's own URL rather
// than reusing the general approvals list's id space implicitly.
func (s *Server) handleGuardPromptAllowDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/guard/prompt/allow/")
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

// ---- POST /api/guard/prompt/probe ----

// promptProbeCheckJSON mirrors internal/diag.Check for the wire, with
// Status rendered as its string form (diag.Check has no json tags and
// Status is a bare int — the subprocess's own --json output would
// otherwise hand the browser a raw 0/1/2).
type promptProbeCheckJSON struct {
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Message string   `json:"message"`
	Details []string `json:"details,omitempty"`
}

// diagJSONReport is the on-the-wire shape `observer doctor --probe-hook
// --json` actually emits (internal/diag.Report / .Check have no json
// tags, so encoding/json uses the exported Go field names verbatim —
// this struct decodes that exact shape without importing diag's own
// Check type, whose Status is an unexported-underlying int enum with
// no UnmarshalJSON).
type diagJSONReport struct {
	Checks []struct {
		Name    string      `json:"Name"`
		Status  diag.Status `json:"Status"`
		Message string      `json:"Message"`
		Details []string    `json:"Details"`
	} `json:"Checks"`
}

// handleGuardPromptProbe serves POST /api/guard/prompt/probe (task
// item 2d/4) — the one-click "probe hooks" action. Body {"tool":
// "<name>"} probes one tool; an empty/absent tool probes every
// PromptLane=hook registry row concurrently.
//
// REUSE, NOT REIMPLEMENTATION: the actual probe logic (fire a
// synthetic, obviously-fake secret through the REGISTERED hook command
// exactly as the host tool would invoke it, and report whether it
// actually got blocked) lives in cmd/observer/probehook.go's
// runProbeHook — unexported `main`-package code this dashboard package
// cannot import (and, per this build's file scope, must not move).
// This handler reuses it at the PROCESS boundary instead: it self-
// execs `<this binary> doctor --probe-hook --json [tool]`, the exact
// CLI contract `observer doctor --probe-hook` already documents and
// tests (probehook_test.go) — so there is exactly one implementation
// of the probe, this is just a second caller of its `--json` output.
func (s *Server) handleGuardPromptProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Tool string `json:"tool"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) // empty body = probe every tool

	exe, err := os.Executable()
	if err != nil {
		writeErr(w, fmt.Errorf("resolve this binary's own path: %w", err))
		return
	}
	args := []string{"doctor", "--probe-hook", "--json"}
	if req.Tool != "" {
		args = append(args, req.Tool)
	}
	if s.opts.ConfigPath != "" {
		args = append(args, "--config", s.opts.ConfigPath)
	}
	// Bounded overall timeout: this is an operator-triggered, one-shot
	// diagnostic action (not a poll loop), and probing every
	// PromptLane=hook tool sequentially inside the CLI process can take
	// several seconds per tool (each dialect invocation carries its own
	// 10s sub-timeout, probehook.go::runProbeHook). 60s covers the
	// registry's current size with headroom; a caller that wants a
	// single tool's result faster should pass {"tool": "..."}.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...) //nolint:gosec // G204: exe is this process's own resolved path, args are a fixed literal set plus an operator-supplied tool name the probe subcommand itself validates against the registry
	out, runErr := cmd.Output()
	if ctx.Err() != nil {
		writeErr(w, fmt.Errorf("probe timed out"))
		return
	}
	// `observer doctor --probe-hook` exits non-zero when any probe
	// fails (a real, expected outcome — "this hook isn't blocking" —
	// not an invocation error), so runErr alone doesn't mean the probe
	// didn't run; only trust it when stdout carries nothing to parse.
	if len(out) == 0 && runErr != nil {
		writeErr(w, fmt.Errorf("probe failed to run: %w", runErr))
		return
	}
	var report diagJSONReport
	if err := json.Unmarshal(out, &report); err != nil {
		writeErr(w, fmt.Errorf("decode probe output: %w", err))
		return
	}
	checks := make([]promptProbeCheckJSON, 0, len(report.Checks))
	for _, c := range report.Checks {
		checks = append(checks, promptProbeCheckJSON{
			Name: c.Name, Status: c.Status.String(), Message: c.Message, Details: c.Details,
		})
	}
	writeJSON(w, map[string]any{"checks": checks})
}
