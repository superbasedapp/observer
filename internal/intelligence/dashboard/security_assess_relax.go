//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_relax.go is the dashboard half of the relaxations addendum
// (docs/plans/security-assessments-module-plan-2026-11-13.md section 13): the
// facts the consent table reads, the selection of a launch's ticks, the store
// ports the reconcile pass walks, and the audit rows. The decisions are the
// pure tables in internal/secassess; this file only reads facts, calls them and
// applies the answer.

// securityAssessTenancy reads the node's tenancy from the governance handle
// the guard reads too. No provider wired reads as unresolved, which is treated
// as managed.
func (s *Server) securityAssessTenancy(ctx context.Context) secassess.Tenancy {
	if s.opts.Governance == nil {
		return secassess.TenancyUnresolved
	}
	if s.opts.Governance(ctx).Managed {
		return secassess.TenancyManaged
	}
	return secassess.TenancyIndividual
}

// securityAssessConfig reads the node's config (governance pins applied). A
// config that cannot be read reads as the defaults, under which nothing is
// relaxed.
func (s *Server) securityAssessConfig() config.Config {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return config.Default()
	}
	return cfg
}

// securityAssessRelaxSwitches is the one place the per-kind config switches
// meet the kind ids (the config test pins that every kind with rows has one).
var securityAssessRelaxSwitches = []struct {
	Kind secassess.ID
	On   func(a config.SecurityAssessmentsConfig) bool
}{
	{secassess.PentestLocal, func(a config.SecurityAssessmentsConfig) bool { return a.RelaxPentestLocal }},
	{secassess.RedTeamLocal, func(a config.SecurityAssessmentsConfig) bool { return a.RelaxRedTeamLocal }},
}

// securityAssessPolicy turns the config block into the pure policy, with the
// managed caps (session scope, at most 60 minutes) applied.
func securityAssessPolicy(cfg config.Config, t secassess.Tenancy) secassess.Policy {
	a := cfg.Security.Assessments
	p := secassess.Policy{
		Relax: map[secassess.ID]bool{}, ScopedApproval: a.ScopedApproval, MaxTier: a.MaxNetworkTier,
		Scope: secassess.EffectiveScope(t, a.RelaxationScope), MaxMinutes: secassess.EffectiveMinutes(t, a.RelaxationMaxMinutes),
		ReportToOrg: a.ReportToOrg,
	}
	for _, sw := range securityAssessRelaxSwitches {
		p.Relax[sw.Kind] = sw.On(a)
	}
	return p
}

// securityAssessEnrolled reports whether the node can ask an organization.
func (s *Server) securityAssessEnrolled(ctx context.Context) bool {
	svc := s.opts.Requests
	if svc == nil {
		return false
	}
	st, err := svc.Status(ctx)
	return err == nil && st.Enrolled
}

// securityAssessRuleKeys lists the rule ids a kind's rows name.
func securityAssessRuleKeys(kind secassess.ID) []string {
	var out []string
	for _, r := range secassess.RelaxationsFor(kind) {
		if r.Type == secassess.RelaxRule {
			out = append(out, r.Key)
		}
	}
	return out
}

// securityAssessRuleFacts reads the guard's answer for every rule row of the
// kind in one project. A guard that is off decides nothing; an unwired seam, or
// a rule missing from its answer, reads as locked and undecided (fail closed).
func (s *Server) securityAssessRuleFacts(ctx context.Context, cfg config.Config, kind secassess.ID, root string) map[string]secassess.RuleFacts {
	keys := securityAssessRuleKeys(kind)
	out := make(map[string]secassess.RuleFacts, len(keys))
	if !cfg.Guard.Enabled || cfg.Guard.Mode == "off" {
		for _, k := range keys {
			out[k] = secassess.RuleFacts{Lock: secassess.LockUntouched, Decision: "allow"}
		}
		return out
	}
	var got map[string]dashapi.RuleRelaxationFact
	if s.opts.RuleRelaxation != nil && len(keys) > 0 {
		got = s.opts.RuleRelaxation(ctx, root, keys)
	}
	for _, k := range keys {
		f, ok := got[k]
		if !ok {
			out[k] = secassess.RuleFacts{Lock: secassess.LockLocked}
			continue
		}
		lock := secassess.LockLocked
		switch f.Lock {
		case "untouched":
			lock = secassess.LockUntouched
		case "overridable":
			lock = secassess.LockOverridable
		}
		out[k] = secassess.RuleFacts{Lock: lock, Decision: f.Decision}
	}
	return out
}

// securityAssessTierFacts reads the tier row's facts from the probe and the
// node's sandbox config.
func securityAssessTierFacts(cfg config.Config, liveTier string) secassess.TierFacts {
	return secassess.TierFacts{
		Live: liveTier, Hosts: append([]string(nil), cfg.Terminal.Sandbox.EgressAllowHosts...),
		NoHostPinned: cfg.Terminal.Sandbox.PinnedNoEgressHost != "",
	}
}

// securityAssessRelaxPlan is every fact a plan or a launch resolves its rows
// from, read once.
type securityAssessRelaxPlan struct {
	Cfg     config.Config
	Tenancy secassess.Tenancy
	Policy  secassess.Policy
	Tier    secassess.TierFacts
	Rows    []secassess.PlanRow
}

// securityAssessRelaxFacts resolves a kind's relaxation rows for one project.
func (s *Server) securityAssessRelaxFacts(ctx context.Context, kind secassess.ID, root string, av SandboxAvailability) securityAssessRelaxPlan {
	cfg := s.securityAssessConfig()
	t := s.securityAssessTenancy(ctx)
	pol := securityAssessPolicy(cfg, t)
	tier := securityAssessTierFacts(cfg, av.Egress)
	in := secassess.PlanInput{Policy: pol, Tenancy: t, Tier: tier}
	if len(secassess.RelaxationsFor(kind)) > 0 {
		in.Enrolled = s.securityAssessEnrolled(ctx)
		in.Rules = s.securityAssessRuleFacts(ctx, cfg, kind, root)
	}
	return securityAssessRelaxPlan{Cfg: cfg, Tenancy: t, Policy: pol, Tier: tier, Rows: secassess.PlanRelaxations(kind, in)}
}

// securityAssessSelection is a request's ticked rows, resolved.
type securityAssessSelection struct {
	// Rows are the ticked rows in table order.
	Rows []secassess.PlanRow
	// Tier says the tier row is ticked.
	Tier bool
}

func (sel securityAssessSelection) has(key string) bool {
	for _, r := range sel.Rows {
		if r.Key == key {
			return true
		}
	}
	return false
}

// securityAssessSelectErr is a refusal the caller sends as is.
type securityAssessSelectErr struct {
	Status int
	Code   string
	Rule   string
	Reason string
}

// securityAssessSelect resolves the ticks of a request against the plan rows:
// an unknown key is a 400, a row whose route is not one a tick can use (self
// or org_request) is a 409 relaxation_not_available carrying the table's own
// sentence.
func securityAssessSelect(rows []secassess.PlanRow, ticks []string, tier bool) (securityAssessSelection, *securityAssessSelectErr) {
	want := map[string]bool{}
	for _, t := range ticks {
		want[strings.TrimSpace(t)] = true
	}
	if tier {
		want[secassess.TierKey] = true
	}
	delete(want, "")
	var sel securityAssessSelection
	for _, r := range rows {
		if !want[r.Key] {
			continue
		}
		delete(want, r.Key)
		if r.Route != secassess.RouteSelf && r.Route != secassess.RouteOrgRequest {
			code := r.Code
			if r.Route == secassess.RouteNotNeeded || code == "" {
				code = secassess.CodeRelaxNotAvailable
			}
			return sel, &securityAssessSelectErr{Status: http.StatusConflict, Code: code, Rule: r.Row, Reason: r.Reason}
		}
		sel.Rows = append(sel.Rows, r)
		if r.Type == secassess.RelaxTier {
			sel.Tier = true
		}
	}
	if len(want) > 0 {
		return sel, &securityAssessSelectErr{Status: http.StatusBadRequest, Code: "unknown_relaxation", Reason: "that relaxation is not one this assessment offers"}
	}
	return sel, nil
}

// orgRules are the ticked rows that need the organization.
func (sel securityAssessSelection) orgRules() []secassess.PlanRow {
	var out []secassess.PlanRow
	for _, r := range sel.Rows {
		if r.Type == secassess.RelaxRule && r.Route == secassess.RouteOrgRequest {
			out = append(out, r)
		}
	}
	return out
}

// selfRules are the ticked rows a local approval covers.
func (sel securityAssessSelection) selfRules() []secassess.PlanRow {
	var out []secassess.PlanRow
	for _, r := range sel.Rows {
		if r.Type == secassess.RelaxRule && r.Route == secassess.RouteSelf {
			out = append(out, r)
		}
	}
	return out
}

// promptRelax is what the prompt says about the ticked rows.
func (sel securityAssessSelection) promptRelax(scope string, hosts []string) []secassess.InForce {
	var out []secassess.InForce
	for _, r := range sel.Rows {
		f := secassess.InForce{Key: r.Key, Scope: scope}
		switch {
		case r.Type == secassess.RelaxTier:
			f.Hosts = hosts
		case r.Route == secassess.RouteOrgRequest:
			f.Scope = secassess.ScopeOrg
		}
		out = append(out, f)
	}
	return out
}

// securityAssessFactsRelaxed adds the relaxation facts to the sandbox facts.
func securityAssessFactsRelaxed(f secassess.Facts, plan securityAssessRelaxPlan) secassess.Facts {
	f.TierRelax = plan.Tier
	if row, ok := secassess.PlanRowFor(plan.Rows, secassess.TierKey); ok {
		f.TierRelaxOK = row.Route == secassess.RouteSelf
	}
	return f
}

// securityAssessGrantor is the approval rows' grantor: it carries the run id
// (ownership is matched on it exactly), and says "assessment" only for a run
// that is reported to the org.
func securityAssessGrantor(reported bool, runID string) string {
	if reported {
		return secassessGrantorPrefix + runID
	}
	return secassessLocalGrantorPrefix + runID
}

const (
	secassessGrantorPrefix      = "assessment:"
	secassessLocalGrantorPrefix = "local-run:"
)

func isRunGrantor(by string) bool {
	return strings.HasPrefix(by, secassessGrantorPrefix) || strings.HasPrefix(by, secassessLocalGrantorPrefix)
}

// TerminalFunc says whether a terminal handle is live and, for a live one, the
// session it resolved to and the confidence of that link.
type TerminalFunc func(handle string) (live bool, sessionID string, confidence float64)

// SecAssessPorts builds the reconcile pass's store-backed ports. The daemon's
// loop and the dashboard's lazy pass share it, so there is one set of
// statements that touch the approval rows.
func SecAssessPorts(st *store.Store, term TerminalFunc) secassesssvc.Ports {
	channelFor := func(by string) string {
		if strings.HasPrefix(by, secassessGrantorPrefix) {
			return "assessment"
		}
		return "dashboard"
	}
	return secassesssvc.Ports{
		Now:      time.Now,
		Terminal: term,
		CreateApproval: func(ctx context.Context, rule, scope, sessionID, projectHash, by string, exp time.Time) (int64, bool, error) {
			return st.CreateApprovalIfAbsent(ctx, store.GuardApprovalRow{
				RuleID: rule, Scope: scope, SessionID: sessionID, ProjectRootHash: projectHash,
				GrantedBy: by, ExpiresAt: exp, Channel: channelFor(by),
			})
		},
		RenewApproval: func(ctx context.Context, id int64, by string, was, now time.Time) (bool, error) {
			return st.RenewOwnedApproval(ctx, id, by, was, now)
		},
		DeleteApproval: func(ctx context.Context, id int64, by string, exp time.Time) (bool, error) {
			return st.DeleteOwnedApproval(ctx, id, by, exp)
		},
		Event: func(ctx context.Context, phase, projectHash, sessionID, detail string) error {
			return st.RecordSecAssessEvent(ctx, store.SecAssessEvent{Phase: phase, ProjectRootHash: projectHash, SessionID: sessionID, Detail: detail})
		},
		Count: func(ctx context.Context, by string, sessions, rules []string, since, until time.Time) (int, int, error) {
			c, err := st.CountRelaxedVerdicts(ctx, by, sessions, rules, since, until)
			return c.Exact, c.Approx, err
		},
	}
}

// securityAssessTerminal adapts the dashboard's session resolver to
// TerminalFunc. A dashboard with no resolver wired reads every terminal as gone
// (fail closed: nothing stays relaxed for a run nobody can see).
func (s *Server) securityAssessTerminal() TerminalFunc {
	res := s.opts.SessionResolver
	if res == nil {
		return nil
	}
	return func(handle string) (bool, string, float64) {
		link, known := res(handle)
		if !known {
			return false, "", 0
		}
		return true, link.SessionID, link.Confidence
	}
}

// securityAssessReconcile runs one reconcile pass (the dashboard's lazy call;
// the daemon's loop runs the same function). Best effort: every failure is
// kept on the relaxation it concerns.
func (s *Server) securityAssessReconcile(ctx context.Context) {
	// Only the dashboard that owns the live terminals can say a terminal is
	// gone: a standalone dashboard process sees none and must end nothing.
	if s.db() == nil || s.opts.LaunchManager == nil || s.opts.SessionResolver == nil {
		return
	}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	retention := s.securityAssessConfig().Security.Assessments.EvidenceRetentionDays
	// The list's pass closes an overdue terminal and prunes stored evidence, but
	// takes no git snapshot: that is git I/O and belongs to the daemon's loop.
	ports := SecAssessFullPorts(store.New(s.db()), s.securityAssessTerminal(), runs, SecAssessExtra{
		Close: s.opts.LaunchManager.Close, RetentionDays: func() int { return retention },
	})
	secassesssvc.Reconcile(ctx, runs, ports)
}

// securityAssessAudit writes one lifecycle audit row when the run is reported.
func (s *Server) securityAssessAudit(ctx context.Context, reported bool, phase, projectHash, sessionID, detail string) {
	if !reported || s.db() == nil {
		return
	}
	if err := store.New(s.db()).RecordSecAssessEvent(ctx, store.SecAssessEvent{Phase: phase, ProjectRootHash: projectHash, SessionID: sessionID, Detail: detail}); err != nil && s.opts.Logger != nil {
		s.opts.Logger.Warn("security assessments: audit row not written", "phase", phase, "error", err)
	}
}

// securityAssessConfigDetail is the effective [security.assessments] values
// the launch row carries, in words.
func securityAssessConfigDetail(p secassess.Policy, t secassess.Tenancy) string {
	on := securityAssessOnOff
	return "config tenancy=" + string(t) + " relax_pentest_local=" + on(p.Relax[secassess.PentestLocal]) +
		" relax_red_team_local=" + on(p.Relax[secassess.RedTeamLocal]) + " scoped_approval=" + on(p.ScopedApproval) +
		" max_network_tier=" + p.MaxTier + " scope=" + p.Scope + " minutes=" + strconv.Itoa(p.MaxMinutes) + " report_to_org=" + on(p.ReportToOrg)
}

// securityAssessLimitsDetail is the time box, the deadline action and the
// boundary audit switch the run started under, in words (the launch row's
// effective values; a later settings change does not rewrite them).
func securityAssessLimitsDetail(run secassesssvc.Run) string {
	audit := "on"
	if run.Audit == string(secassess.AuditOff) {
		audit = "off"
	}
	return "limits time_box_minutes=" + strconv.Itoa(run.TimeBoxMinutes) + " time_box_action=" + run.TimeBoxAction + " boundary_audit=" + audit
}

// securityAssessOnOff is a switch in the words the audit lines use.
func securityAssessOnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// securityAssessAuditWord keeps a value on an audit line to an enum word or a
// number: anything else (it cannot come out of a validated config, but a line
// that ships to the organization does not rely on that) reads "unrecognized".
func securityAssessAuditWord(v string) string {
	if v == "" || len(v) > 32 {
		return "unrecognized"
	}
	for _, c := range v {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return "unrecognized"
		}
	}
	return v
}

// securityAssessAuditSettings is the [security.assessments] values that shape
// a run and that the launch row's other sections do not carry, one row per
// key, walked in order. A key added to the config block is one row here (the
// coverage test fails until it is, or until it is named as carried elsewhere).
var securityAssessAuditSettings = []struct {
	Key string
	Get func(a config.SecurityAssessmentsConfig) string
}{
	{"rerun_dedup", func(a config.SecurityAssessmentsConfig) string { return securityAssessOnOff(a.RerunDedup) }},
	{"findings_cap", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.FindingsCap) }},
	{"import_min_band", func(a config.SecurityAssessmentsConfig) string { return a.ImportMinBand }},
	{"prompt_selfcheck", func(a config.SecurityAssessmentsConfig) string { return securityAssessOnOff(a.PromptSelfcheck) }},
	{"report_validation_to_org", func(a config.SecurityAssessmentsConfig) string { return securityAssessOnOff(a.ReportValidationToOrg) }},
	{"tm_frameworks", func(a config.SecurityAssessmentsConfig) string { return a.TMFrameworks }},
	{"tm_method_extras", func(a config.SecurityAssessmentsConfig) string { return a.TMMethodExtras }},
	{"pt_categories", func(a config.SecurityAssessmentsConfig) string { return a.PTCategories }},
	{"evidence_retention_days", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.EvidenceRetentionDays) }},
	{"ref_match_window_lines", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.RefMatchWindowLines) }},
	{"model_max_mib", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.ModelMaxMiB) }},
	{"ref_budget_files", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.RefBudgetFiles) }},
	{"ref_budget_mib", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.RefBudgetMiB) }},
	{"ref_budget_seconds", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.RefBudgetSeconds) }},
	{"grounding", func(a config.SecurityAssessmentsConfig) string { return a.Grounding }},
	{"workspace_secret_mode", func(a config.SecurityAssessmentsConfig) string { return a.WorkspaceSecretMode }},
	{"pentest_request_budget", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.PentestRequestBudget) }},
	{"pentest_pace_rps", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.PentestPaceRPS) }},
	{"probe_helper", func(a config.SecurityAssessmentsConfig) string { return securityAssessOnOff(a.ProbeHelper) }},
	{"display_redaction", func(a config.SecurityAssessmentsConfig) string { return securityAssessOnOff(a.DisplayRedaction) }},
	{"diagram_max_nodes", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.DiagramMaxNodes) }},
	{"diagram_label_chars", func(a config.SecurityAssessmentsConfig) string { return strconv.Itoa(a.DiagramLabelChars) }},
}

// securityAssessSettingsDetail is the effective values of those keys the run
// was launched under, as key=value words (the launch row's settings section; a
// later settings change does not rewrite it).
func securityAssessSettingsDetail(a config.SecurityAssessmentsConfig) string {
	parts := make([]string, 0, len(securityAssessAuditSettings)+1)
	parts = append(parts, "settings")
	for _, row := range securityAssessAuditSettings {
		parts = append(parts, row.Key+"="+securityAssessAuditWord(row.Get(a)))
	}
	return strings.Join(parts, " ")
}

// securityAssessTicks reads a plan's ticks from its query: relax=KEY (repeat
// or comma-separate) and tier_relax=1.
func securityAssessTicks(q url.Values) (ticks []string, tier bool) {
	for _, v := range q["relax"] {
		for _, k := range strings.Split(v, ",") {
			if k = strings.TrimSpace(k); k != "" && k != secassess.TierKey {
				ticks = append(ticks, k)
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(q.Get("tier_relax"))) {
	case "1", "true", "on", "yes":
		tier = true
	}
	return ticks, tier
}

// securityAssessHeldTicks is the ticks a held run was filed with.
func securityAssessHeldTicks(r secassesssvc.Run) (ticks []string, tier bool) {
	for _, x := range r.Relax {
		if x.Type == string(secassess.RelaxTier) {
			tier = true
			continue
		}
		ticks = append(ticks, x.Key)
	}
	return ticks, tier
}

// securityAssessLenientSelection is the plan's reading of its ticks: a row
// that is not offered (or not in the table) is simply not ticked, because the
// plan shows the reason beside the row. The launch route is the strict reader.
func securityAssessLenientSelection(rows []secassess.PlanRow, ticks []string, tier bool) securityAssessSelection {
	want := map[string]bool{}
	for _, t := range ticks {
		want[t] = true
	}
	if tier {
		want[secassess.TierKey] = true
	}
	var sel securityAssessSelection
	for _, r := range rows {
		if !want[r.Key] || (r.Route != secassess.RouteSelf && r.Route != secassess.RouteOrgRequest) {
			continue
		}
		sel.Rows = append(sel.Rows, r)
		if r.Type == secassess.RelaxTier {
			sel.Tier = true
		}
	}
	return sel
}

// securityAssessRelaxPlanView is the relaxations part of the plan.
func securityAssessRelaxPlanView(kind secassess.ID, plan securityAssessRelaxPlan, sel securityAssessSelection, inForce []secassess.InForce, enrolled bool) *securityAssessRelaxPlanJS {
	_, reportRow := secassess.ReportRoute(secassess.ReportInput{Tenancy: plan.Tenancy, ReportToOrg: plan.Policy.ReportToOrg})
	reported, _ := secassess.ReportRoute(secassess.ReportInput{Tenancy: plan.Tenancy, ReportToOrg: plan.Policy.ReportToOrg})
	hosts := plan.Tier.Hosts
	if hosts == nil {
		hosts = []string{}
	}
	out := &securityAssessRelaxPlanJS{
		Tenancy: string(plan.Tenancy), Scope: plan.Policy.Scope, ScopeWords: secassess.ScopeWords(plan.Policy.Scope),
		Minutes: plan.Policy.MaxMinutes, Reported: reported, ReportRow: reportRow, Enrolled: enrolled,
		TierLive: plan.Tier.LiveTier(), TierHosts: hosts, Rows: []securityAssessRelaxRowJS{},
		Lines: secassess.RelaxPromptLines(kind, inForce),
	}
	if out.Lines == nil {
		out.Lines = []string{}
	}
	for _, r := range plan.Rows {
		out.Rows = append(out.Rows, securityAssessRelaxRowJS{
			Key: r.Key, Type: string(r.Type), Title: r.Title, Lifts: r.Lifts, Why: r.Why, Route: string(r.Route),
			Row: r.Row, Code: r.Code, Reason: r.Reason, Ticked: sel.has(r.Key),
		})
	}
	return out
}

// securityAssessSameTicks reports whether a launch's selection is exactly the
// keys (and tier tick) a held run was filed with.
func securityAssessSameTicks(sel securityAssessSelection, keys []string, tier bool) bool {
	if sel.Tier != tier {
		return false
	}
	var have []string
	for _, r := range sel.Rows {
		if r.Type != secassess.RelaxTier {
			have = append(have, r.Key)
		}
	}
	slices.Sort(have)
	want := slices.Clone(keys)
	slices.Sort(want)
	return slices.Equal(have, want)
}

// securityAssessProjectRowHeld refuses a project-scoped relaxation another
// assessment run's approval already holds: one run's end must never remove a
// row another run still relies on. A developer's own row is not refused (the
// run proceeds under it and never touches it).
func (s *Server) securityAssessProjectRowHeld(ctx context.Context, st *store.Store, sel securityAssessSelection, pol secassess.Policy, projectHash string) *securityAssessRefusal {
	if pol.Scope != secassess.ScopeProject {
		return nil
	}
	for _, r := range sel.selfRules() {
		row, found, err := st.ActiveApprovalOnKey(ctx, r.Key, secassess.ScopeProject, "", projectHash, time.Now())
		if err != nil {
			return &securityAssessRefusal{Status: http.StatusInternalServerError, Code: "internal", Reason: "the approvals could not be read"}
		}
		if found && isRunGrantor(row.GrantedBy) {
			return &securityAssessRefusal{
				Status: http.StatusConflict, Rule: r.Row, Code: codeHeldByAnotherRun,
				Reason: "Another assessment run in this project already holds the approval for " + r.Key + ". Wait for that run to end, or use the session scope.",
			}
		}
	}
	return nil
}

// securityAssessApplyLocal applies the local half of a started run's
// relaxations: a project-scoped approval row is created now, a session-scoped
// one waits for the run's session (the reconcile pass binds it), the tier row
// records its host list. An org-approved row needs nothing here: its grant is
// the organization's. A row that already exists is recorded and never touched.
func (s *Server) securityAssessApplyLocal(ctx context.Context, st *store.Store, recs []secassesssvc.Relax, runID string, reported bool, projectHash string, plan securityAssessRelaxPlan, now time.Time) {
	ports := SecAssessPorts(st, nil)
	grantor := securityAssessGrantor(reported, runID)
	for i := range recs {
		x := &recs[i]
		switch {
		case x.Type == string(secassess.RelaxTier):
			x.Hosts = append([]string(nil), plan.Tier.Hosts...)
		case x.Type == string(secassess.RelaxRule) && x.Route == string(secassess.RouteSelf):
			x.GrantedBy, x.Scope = grantor, plan.Policy.Scope
			if plan.Policy.Scope != secassess.ScopeProject {
				x.State = string(secassess.RelaxPendingBind)
				continue
			}
			exp := secassess.RenewExpiry(now, now, plan.Policy.MaxMinutes).UTC().Truncate(time.Second)
			id, created, err := ports.CreateApproval(ctx, x.Key, secassess.ScopeProject, "", projectHash, grantor, exp)
			switch {
			case err != nil:
				x.State, x.Note = string(secassess.RelaxFailed), "create_failed"
			case !created:
				x.State, x.Note = string(secassess.RelaxExisting), "existing_row"
			default:
				x.State, x.ApprovalID, x.ExpiresAt = string(secassess.RelaxActive), id, exp
			}
		}
	}
}

// securityAssessLaunchDetail is the content-free line of the `launch` audit
// row: the run, what it started under, the configuration in force (the config,
// limits and settings sections together carry every [security.assessments]
// value that shapes a run) and each relaxation with its route and the approval
// or grant id. Sections are separated by "; "; a section is a word and its
// key=value pairs. The line is longer than one audit row used to keep, so the
// row's cap is store.SecAssessDetailMax (a test measures the worst case
// against it).
func securityAssessLaunchDetail(run secassesssvc.Run, plan securityAssessRelaxPlan) string {
	var b strings.Builder
	b.WriteString("run " + run.ID + " kind " + run.Kind + " tool " + run.Tool)
	if run.Sandboxed {
		b.WriteString(" sandbox " + run.Backend + " tier " + run.Tier)
	} else {
		b.WriteString(" unsandboxed")
	}
	b.WriteString("; " + securityAssessConfigDetail(plan.Policy, plan.Tenancy))
	b.WriteString("; " + securityAssessLimitsDetail(run))
	b.WriteString("; " + securityAssessSettingsDetail(plan.Cfg.Security.Assessments))
	if c := securityAssessChoicesDetail(run); c != "" {
		b.WriteString("; " + c)
	}
	for _, x := range run.Relax {
		b.WriteString("; " + x.Key + " " + x.Route + " " + x.State)
		if x.ApprovalID != 0 {
			b.WriteString(" approval " + strconv.FormatInt(x.ApprovalID, 10))
		}
		if x.GrantID != 0 {
			b.WriteString(" grant " + strconv.FormatInt(x.GrantID, 10))
		}
		if x.Scope != "" {
			b.WriteString(" scope " + x.Scope)
		}
		if !x.ExpiresAt.IsZero() {
			b.WriteString(" until " + x.ExpiresAt.UTC().Format(time.RFC3339))
		}
	}
	return b.String()
}
