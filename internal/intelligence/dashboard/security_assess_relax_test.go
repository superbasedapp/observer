//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// relaxHarness is one assessment server with the knobs the relaxations read:
// the config, the tenancy, the guard's per-rule answer and the org seam.
type relaxHarness struct {
	t     *testing.T
	s     *Server
	lm    *fakeLaunchManager
	root  string
	hash  string
	runs  *secassesssvc.Store
	reqs  *relaxRequests
	rules map[string]dashapi.RuleRelaxationFact
}

// relaxRequests is the fake org seam: fakeRequests plus a send error.
type relaxRequests struct {
	fakeRequests
	sendErr  error
	cancels  []int64
	nextID   int64
	declined map[int64]bool
}

func (f *relaxRequests) SendOrQueueAccessRequest(ctx context.Context, p orgcontract.AccessRequestCreate) (orgclient.OrgRequest, int64, error) {
	if f.sendErr != nil {
		return orgclient.OrgRequest{}, 0, f.sendErr
	}
	got, queued, err := f.fakeRequests.SendOrQueueAccessRequest(ctx, p)
	f.nextID++
	got.ID = 100 + f.nextID
	return got, queued, err
}

func (f *relaxRequests) CancelQueuedAccessRequest(_ context.Context, id int64) (bool, error) {
	f.cancels = append(f.cancels, id)
	return true, nil
}

func (f *relaxRequests) ListMyOrgRequests(context.Context) ([]orgclient.OrgRequest, error) {
	var out []orgclient.OrgRequest
	for id := range f.declined {
		out = append(out, orgclient.OrgRequest{ID: id, Status: "declined", ResolutionNote: "not this quarter"})
	}
	return out, nil
}

func (f *relaxRequests) AccessGrantsView(context.Context) (store.AccessGrantsView, bool, error) {
	var gs []store.AccessGrantView
	for _, h := range f.held {
		gs = append(gs, store.AccessGrantView{Grant: orgcontract.AccessGrantWire{
			ID: h.ID, Type: h.Type, Effect: h.Effect, RuleID: h.RuleID, Lane: h.Lane, ProjectRootHash: h.ProjectRootHash,
			CommandClass: h.CommandClass, OperandHash: h.OperandHash, MaxUses: h.MaxUses, ExpiresAtNs: h.ExpiresAtNs,
		}, Honoured: true})
	}
	return store.AccessGrantsView{Version: 1, Grants: gs}, true, nil
}

// newRelaxHarness builds the server. cfg is the [security.assessments] body.
func newRelaxHarness(t *testing.T, cfg string) *relaxHarness {
	t.Helper()
	// proxy_only is the live tier: nothing the tier row could add.
	av := assessProbe("proxy_only", "claude-code")
	s, lm, root := assessTestServer(t, &av)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[guard]\nenabled = true\nmode = \"enforce\"\n\n[security.assessments]\n"+cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	s.opts.ConfigPath = path
	h := &relaxHarness{
		t: t, s: s, lm: lm, root: root, hash: secposture.ProjectRootHash(root),
		runs: secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)), reqs: &relaxRequests{}, rules: map[string]dashapi.RuleRelaxationFact{},
	}
	h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "untouched", Decision: "ask", Known: true}
	s.opts.RuleRelaxation = func(_ context.Context, _ string, ids []string) map[string]dashapi.RuleRelaxationFact {
		out := map[string]dashapi.RuleRelaxationFact{}
		for _, id := range ids {
			if f, ok := h.rules[id]; ok {
				out[id] = f
			}
		}
		return out
	}
	s.opts.Governance = func(context.Context) govern.Effective { return govern.Effective{} }
	return h
}

func (h *relaxHarness) managed(enrolled bool) {
	h.s.opts.Governance = func(context.Context) govern.Effective { return govern.Effective{Managed: true} }
	if enrolled {
		h.reqs.enrolled = true
		h.s.opts.Requests = h.reqs
	}
}

func (h *relaxHarness) plan(query string) securityAssessPlanJS {
	h.t.Helper()
	var p securityAssessPlanJS
	url := "/api/security/assessments/plan?kind=pentest_local&project=" + h.hash + "&target=http://localhost:3000/" + query
	if code := getAssessJSON(h.t, h.s.handleSecurityAssessPlan, url, &p); code != http.StatusOK {
		h.t.Fatalf("plan: %d", code)
	}
	return p
}

// launchBody is the body the New terminal dialog posts for a pen test: no
// sandbox, backend or workspace member, because the route chooses them.
func (h *relaxHarness) launchBody(id string, extra map[string]any) map[string]any {
	b := map[string]any{
		"assessment": "pentest_local", "project_root_hash": h.hash, "run_id": id, "tool": "claude-code",
		"target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/",
	}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func (h *relaxHarness) launch(body map[string]any) (int, map[string]string) {
	h.t.Helper()
	h.lm.lastFreshSpec = FreshLaunchSpec{}
	w := postAssess(h.t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// auditRows counts the module's lifecycle rows in guard_events by phase.
func (h *relaxHarness) auditRows() map[string]int {
	h.t.Helper()
	out := map[string]int{}
	rows, err := h.s.db().QueryContext(context.Background(), `SELECT tool FROM guard_events WHERE rule_id = ? AND event_kind = 'audit'`, store.SecAssessEventRuleID)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var tool string
		if err := rows.Scan(&tool); err != nil {
			h.t.Fatal(err)
		}
		out[strings.TrimPrefix(tool, store.SecAssessToolPrefix)]++
	}
	return out
}

func (h *relaxHarness) approvals() int {
	h.t.Helper()
	var n int
	if err := h.s.db().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM guard_approvals`).Scan(&n); err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.t.Fatal(err)
	}
	return n
}

func relaxRow(t *testing.T, p securityAssessPlanJS, key string) securityAssessRelaxRowJS {
	t.Helper()
	if p.Relax == nil {
		t.Fatalf("the plan carries no relaxations")
	}
	for _, r := range p.Relax.Rows {
		if r.Key == key {
			return r
		}
	}
	t.Fatalf("no relaxation row %q in %+v", key, p.Relax.Rows)
	return securityAssessRelaxRowJS{}
}

const relaxOn = "relax_pentest_local = true\nscoped_approval = true\n"

// TestSecurityAssessPlanRelaxRoutes: the plan's relaxation rows carry the
// route the consent table decides from the live facts, one row per case.
func TestSecurityAssessPlanRelaxRoutes(t *testing.T) {
	cases := []struct {
		name  string
		cfg   string
		setup func(h *relaxHarness)
		route secassess.Route
		code  string
		scope string
	}{
		{"individual, untouched rule, switches on: the tick is the consent", relaxOn, nil, secassess.RouteSelf, "", "session"},
		{"kind switch off", "scoped_approval = true\n", nil, secassess.RouteRefused, secassess.CodeRelaxDisabled, "session"},
		{"scoped approval off", "relax_pentest_local = true\n", nil, secassess.RouteRefused, secassess.CodeRelaxDisabled, "session"},
		{"observe mode: nothing to lift", relaxOn, func(h *relaxHarness) {
			h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "untouched", Decision: "flag", Known: true}
		}, secassess.RouteNotNeeded, "", "session"},
		{"project scope is an individual option", relaxOn + "relaxation_scope = \"project\"\n", nil, secassess.RouteSelf, "", "project"},
		{"managed, locked, enrolled: the organization decides", relaxOn, func(h *relaxHarness) {
			h.managed(true)
			h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "locked", Decision: "ask", Known: true}
		}, secassess.RouteOrgRequest, "", "session"},
		{"managed project scope is never offered", relaxOn + "relaxation_scope = \"project\"\n", func(h *relaxHarness) {
			h.managed(true)
			h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "locked", Decision: "ask", Known: true}
		}, secassess.RouteOrgRequest, "", "session"},
		{"managed, locked, not enrolled", relaxOn, func(h *relaxHarness) {
			h.managed(false)
			h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "locked", Decision: "ask", Known: true}
		}, secassess.RouteRefused, secassess.CodeNeedsOrg, "session"},
		{"the org marked the rule overridable", relaxOn, func(h *relaxHarness) {
			h.managed(true)
			h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "overridable", Decision: "ask", Known: true}
		}, secassess.RouteSelf, "", "session"},
		{"an unreadable guard reads as locked", relaxOn, func(h *relaxHarness) {
			h.rules = map[string]dashapi.RuleRelaxationFact{}
			h.s.opts.Governance = nil
		}, secassess.RouteRefused, secassess.CodeNeedsOrg, "session"},
		{"no governance provider reads as managed", relaxOn, func(h *relaxHarness) {
			h.s.opts.Governance = nil
			h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "untouched", Decision: "ask", Known: true}
		}, secassess.RouteRefused, secassess.CodeNeedsOrg, "session"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRelaxHarness(t, tc.cfg)
			if tc.setup != nil {
				tc.setup(h)
			}
			p := h.plan("")
			row := relaxRow(t, p, secassess.RuleScanner)
			if secassess.Route(row.Route) != tc.route || row.Code != tc.code {
				t.Fatalf("route %q code %q, want %q %q (%s)", row.Route, row.Code, tc.route, tc.code, row.Reason)
			}
			if p.Relax.Scope != tc.scope {
				t.Errorf("scope %q, want %q", p.Relax.Scope, tc.scope)
			}
			// The tier row under proxy_only needs nothing.
			if tier := relaxRow(t, p, secassess.TierKey); secassess.Route(tier.Route) == secassess.RouteSelf {
				t.Errorf("a proxy_only box offers a tier relaxation: %+v", tier)
			}
		})
	}
}

// TestSecurityAssessNeverRelaxedRulesAreNotRows pins the closed list: a rule
// the table names as never relaxed is no row of any kind, and every one of
// them exists in the policy catalog (a typo here would pin nothing).
func TestSecurityAssessNeverRelaxedRulesAreNotRows(t *testing.T) {
	catalog := map[string]bool{}
	for _, r := range policy.Catalog() {
		catalog[r.ID] = true
		if r.ID == secassess.RuleScanner && (r.Observe != policy.DecisionFlag || r.Enforce != policy.DecisionAsk) {
			t.Errorf("R-179 is observe %v enforce %v, not flag and ask: the consent table's C2 row assumes it", r.Observe, r.Enforce)
		}
	}
	if !catalog[secassess.RuleScanner] {
		t.Fatal("R-179 is not in the policy catalog")
	}
	if !policy.AsksEveryUse("R-168") {
		t.Error("R-168 no longer asks on every use: the never-relaxed list reasons from it")
	}
	rowKeys := map[string]bool{}
	for _, r := range secassess.Relaxations() {
		rowKeys[r.Key] = true
	}
	for _, n := range secassess.NeverRelaxed() {
		if !catalog[n.ID] {
			t.Errorf("never-relaxed rule %s is not in the policy catalog", n.ID)
		}
		if rowKeys[n.ID] {
			t.Errorf("never-relaxed rule %s is a relaxation row", n.ID)
		}
	}
	// A body that ticks a never-relaxed rule is refused before anything starts.
	h := newRelaxHarness(t, relaxOn)
	for _, n := range secassess.NeverRelaxed() {
		code, body := h.launch(h.launchBody(secassesssvc.NewRunID(), map[string]any{"relaxations": []string{n.ID}}))
		if code != http.StatusBadRequest || body["code"] != "unknown_relaxation" || h.lm.lastFreshSpec.Tool != "" {
			t.Errorf("%s ticked: %d %v (launched %+v)", n.ID, code, body, h.lm.lastFreshSpec)
		}
	}
	if h.approvals() != 0 {
		t.Errorf("an approval was created for a refused tick")
	}
}

// TestSecurityAssessLaunchWithoutRelaxationIsUnchanged pins the addendum's
// first invariant: a launch that names no relaxation records what it always
// did, creates no approval and writes no audit row on an individual node, and
// the prompt has no lifted-guardrail line, whatever the config says.
func TestSecurityAssessLaunchWithoutRelaxationIsUnchanged(t *testing.T) {
	for _, cfg := range []string{"", relaxOn + "report_to_org = false\n"} {
		h := newRelaxHarness(t, cfg)
		id := secassesssvc.NewRunID()
		code, body := h.launch(h.launchBody(id, nil))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		run, _ := h.runs.Get(id)
		if run.Phase != "" || len(run.Relax) != 0 || run.Reported || run.Held != nil || run.RelaxMinutes != 0 || !run.EndedAt.IsZero() {
			t.Fatalf("run = %+v", run)
		}
		if n := h.approvals(); n != 0 {
			t.Errorf("%d approvals created", n)
		}
		if rows := h.auditRows(); len(rows) != 0 {
			t.Errorf("audit rows on an individual node that did not opt in: %v", rows)
		}
		if strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "lifted ONE guardrail") {
			t.Errorf("the prompt names a relaxation: %s", h.lm.lastFreshSpec.TaskPrompt)
		}
	}
}

// TestSecurityAssessLaunchRelaxIndividual: the local approval path.
func TestSecurityAssessLaunchRelaxIndividual(t *testing.T) {
	t.Run("session scope waits for the session and creates no row yet", func(t *testing.T) {
		h := newRelaxHarness(t, relaxOn)
		id := secassesssvc.NewRunID()
		code, body := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		run, _ := h.runs.Get(id)
		if len(run.Relax) != 1 {
			t.Fatalf("relax = %+v", run.Relax)
		}
		x := run.Relax[0]
		if x.Key != "R-179" || x.Route != "self" || x.State != string(secassess.RelaxPendingBind) || x.Scope != "session" || x.GrantedBy != "local-run:"+id {
			t.Fatalf("relaxation = %+v", x)
		}
		if run.RelaxMinutes != 60 || run.Reported || h.approvals() != 0 {
			t.Fatalf("minutes %d reported %v approvals %d", run.RelaxMinutes, run.Reported, h.approvals())
		}
		if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "lifted ONE guardrail") || !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "this terminal's session only") {
			t.Fatalf("prompt lacks the relaxation line:\n%s", h.lm.lastFreshSpec.TaskPrompt)
		}
	})
	t.Run("project scope creates the row at once, owned by the run", func(t *testing.T) {
		h := newRelaxHarness(t, relaxOn+"relaxation_scope = \"project\"\nreport_to_org = true\n")
		id := secassesssvc.NewRunID()
		code, body := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		run, _ := h.runs.Get(id)
		x := run.Relax[0]
		if x.State != string(secassess.RelaxActive) || x.ApprovalID == 0 || x.GrantedBy != "assessment:"+id || x.Scope != "project" || !run.Reported {
			t.Fatalf("relaxation = %+v reported %v", x, run.Reported)
		}
		if d := time.Until(x.ExpiresAt); d <= 0 || d > secassess.ShortTTL+time.Minute {
			t.Errorf("expiry in %v, want within the short TTL", d)
		}
		row, found, err := store.New(h.s.db()).ActiveApprovalOnKey(context.Background(), "R-179", "project", "", h.hash, time.Now())
		if err != nil || !found || row.GrantedBy != "assessment:"+id || row.ID != x.ApprovalID {
			t.Fatalf("approval row = %+v %v %v", row, found, err)
		}
		if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "for every session in this project") {
			t.Errorf("prompt lacks the project scope words")
		}
		if rows := h.auditRows(); rows["launch"] != 1 {
			t.Errorf("audit rows = %v", rows)
		}
		// A second run may not take a project row another run holds.
		code, body = h.launch(h.launchBody(secassesssvc.NewRunID(), map[string]any{"relaxations": []string{secassess.RuleScanner}}))
		if code != http.StatusConflict || body["code"] != codeHeldByAnotherRun {
			t.Fatalf("second run: %d %v", code, body)
		}
	})
	t.Run("a developer's own project row is kept, never extended or removed", func(t *testing.T) {
		h := newRelaxHarness(t, relaxOn+"relaxation_scope = \"project\"\n")
		own := time.Now().Add(3 * time.Hour).UTC()
		if _, _, err := store.New(h.s.db()).CreateApprovalIfAbsent(context.Background(), store.GuardApprovalRow{
			RuleID: "R-179", Scope: "project", ProjectRootHash: h.hash, GrantedBy: "dashboard", ExpiresAt: own, Channel: "dashboard",
		}); err != nil {
			t.Fatal(err)
		}
		id := secassesssvc.NewRunID()
		code, body := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		run, _ := h.runs.Get(id)
		if x := run.Relax[0]; x.State != string(secassess.RelaxExisting) || x.ApprovalID != 0 || x.Note != "existing_row" {
			t.Fatalf("relaxation = %+v", x)
		}
	})
	t.Run("refusals", func(t *testing.T) {
		h := newRelaxHarness(t, "scoped_approval = true\n")
		for _, tc := range []struct {
			name string
			body map[string]any
			code int
			want string
		}{
			{"a row whose switch is off", map[string]any{"relaxations": []string{"R-179"}}, http.StatusConflict, secassess.CodeRelaxDisabled},
			{"a rule that is not a row", map[string]any{"relaxations": []string{"R-999"}}, http.StatusBadRequest, "unknown_relaxation"},
			{"a tier tick under proxy_only", map[string]any{"tier_relax": true}, http.StatusConflict, ""},
		} {
			code, body := h.launch(h.launchBody(secassesssvc.NewRunID(), tc.body))
			if code != tc.code || (tc.want != "" && body["code"] != tc.want) || h.lm.lastFreshSpec.Tool != "" {
				t.Errorf("%s: %d %v (launched %+v)", tc.name, code, body, h.lm.lastFreshSpec)
			}
		}
		// A kind with no relaxation row names an unknown relaxation.
		w := postAssess(t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", map[string]any{
			"assessment": "threat_model", "project_root_hash": h.hash, "run_id": secassesssvc.NewRunID(), "tool": "claude-code",
			"relaxations": []string{"R-179"},
		}, true)
		if w.Code != http.StatusBadRequest {
			t.Errorf("threat model with a relaxation: %d %s", w.Code, w.Body)
		}
	})
}

// TestSecurityAssessTierRelaxation: the tier row under the internet tier.
func TestSecurityAssessTierRelaxation(t *testing.T) {
	setup := func(t *testing.T, cfg string, hosts bool) *relaxHarness {
		h := newRelaxHarness(t, cfg)
		av := assessProbe("internet", "claude-code")
		h.s.opts.SandboxProber = &fakeSandboxProber{avail: av}
		if hosts {
			cfg := "[guard]\nenabled = true\nmode = \"enforce\"\n\n[terminal.sandbox]\negress_allow_hosts = [\"registry.npmjs.org\"]\n\n[security.assessments]\n" + cfg
			if err := os.WriteFile(h.s.opts.ConfigPath, []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return h
	}
	t.Run("offered with a host list under a max of internet, individual", func(t *testing.T) {
		h := setup(t, relaxOn+"max_network_tier = \"internet\"\n", true)
		p := h.plan("&tier_relax=1")
		row := relaxRow(t, p, secassess.TierKey)
		if secassess.Route(row.Route) != secassess.RouteSelf || !row.Ticked || len(p.Relax.TierHosts) != 1 || p.Relax.TierLive != "internet" {
			t.Fatalf("tier row = %+v relax = %+v", row, p.Relax)
		}
		if !p.OK {
			t.Fatalf("the plan is refused with the tier ticked: %s %s", p.Rule, p.Reason)
		}
		id := secassesssvc.NewRunID()
		code, body := h.launch(h.launchBody(id, map[string]any{"tier_relax": true}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		run, _ := h.runs.Get(id)
		if len(run.Relax) != 1 || run.Relax[0].Key != "tier" || run.Relax[0].State != string(secassess.RelaxTierOn) || len(run.Relax[0].Hosts) != 1 || run.Tier != "internet" {
			t.Fatalf("run = %+v", run)
		}
		if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "registry.npmjs.org") {
			t.Errorf("the prompt does not name the host list:\n%s", h.lm.lastFreshSpec.TaskPrompt)
		}
		// Without the tick the same box is refused as before.
		code, body = h.launch(h.launchBody(secassesssvc.NewRunID(), nil))
		if code != http.StatusConflict || !strings.Contains(body["code"], secassess.CodeTierNotConfined) {
			t.Errorf("untick launch: %d %v", code, body)
		}
	})
	t.Run("refused above the configured maximum and with no host list", func(t *testing.T) {
		h := setup(t, relaxOn, true)
		if row := relaxRow(t, h.plan(""), secassess.TierKey); row.Code != secassess.CodeTierAboveMax {
			t.Errorf("above max: %+v", row)
		}
		h = setup(t, relaxOn+"max_network_tier = \"internet\"\n", false)
		if row := relaxRow(t, h.plan(""), secassess.TierKey); row.Code != secassess.CodeNeedsAllowHosts {
			t.Errorf("no host list: %+v", row)
		}
	})
	t.Run("never offered on a managed node", func(t *testing.T) {
		h := setup(t, relaxOn+"max_network_tier = \"internet\"\n", true)
		h.managed(true)
		if row := relaxRow(t, h.plan(""), secassess.TierKey); row.Code != secassess.CodeNeedsOrgSetting {
			t.Errorf("managed: %+v", row)
		}
	})
	t.Run("the gateway port is not a target port under the internet tier", func(t *testing.T) {
		h := setup(t, relaxOn+"max_network_tier = \"internet\"\n", true)
		code, body := h.launch(h.launchBody(secassesssvc.NewRunID(), map[string]any{
			"tier_relax": true, "target": "http://localhost:3128/", "confirm_target": "http://localhost:3128/",
		}))
		if code != http.StatusConflict || body["rule"] != "E5" {
			t.Errorf("target on the gateway port: %d %v", code, body)
		}
	})
}

// grantFor is an org grant in force: an exemption for the rule on the project,
// rule-wide, tool lane, member subject (the fake node has no machine identity).
func grantFor(id int64, hash string, hours int) accessgrant.Held {
	return accessgrant.Held{
		ID: id, Type: accessgrant.TypeGuardExemption, Effect: orgcontract.AccessGrantEffectExempt,
		SubjectKind: orgcontract.AccessGrantSubjectMember, RuleID: secassess.RuleScanner, Lane: accessgrant.LaneTool,
		ProjectRootHash: hash, ExpiresAtNs: time.Now().Add(time.Duration(hours) * time.Hour).UnixNano(),
	}
}

func (h *relaxHarness) lockRule() {
	h.rules[secassess.RuleScanner] = dashapi.RuleRelaxationFact{Lock: "locked", Decision: "ask", Known: true}
}

func (h *relaxHarness) request(id string) (int, map[string]json.RawMessage) {
	h.t.Helper()
	w := postAssess(h.t, h.s.handleSecurityAssessRequest, "/api/security/assessments/request", map[string]any{
		"assessment": "pentest_local", "project_root_hash": h.hash, "run_id": id, "target": "http://localhost:3000/",
		"relaxations": []string{secassess.RuleScanner},
	}, true)
	var out map[string]json.RawMessage
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (h *relaxHarness) runView(id string) securityAssessRunJS {
	h.t.Helper()
	var list securityAssessListJS
	getAssessJSON(h.t, h.s.handleSecurityAssess, "/api/security/assessments", &list)
	for _, r := range list.Runs {
		if r.ID == id {
			return r
		}
	}
	h.t.Fatalf("run %s is not in the list", id)
	return securityAssessRunJS{}
}

// TestSecurityAssessHeldRunLifecycle: the managed-node path from request to
// start, through the approval the organization gives, and the cancel path.
func TestSecurityAssessHeldRunLifecycle(t *testing.T) {
	newManaged := func(t *testing.T) *relaxHarness {
		h := newRelaxHarness(t, relaxOn)
		h.managed(true)
		h.lockRule()
		return h
	}
	t.Run("request files one exemption request, holds the run and starts it once granted", func(t *testing.T) {
		h := newManaged(t)
		id := secassesssvc.NewRunID()
		code, out := h.request(id)
		if code != http.StatusCreated {
			t.Fatalf("request: %d %s", code, out)
		}
		if len(h.reqs.sent) != 1 {
			t.Fatalf("requests sent = %d", len(h.reqs.sent))
		}
		sent := h.reqs.sent[0]
		p := sent.Payload
		if sent.RequestType != accessgrant.TypeGuardExemption || p == nil || p.RuleID != "R-179" || p.Lane != "tool" || p.Breadth != "rule" ||
			p.Effect != "exempt" || p.ProjectRootHash != h.hash || sent.RequestedDurationS != 3600 {
			t.Fatalf("request = %+v payload %+v", sent, p)
		}
		if !strings.Contains(sent.Message, id) || !strings.Contains(sent.Message, "R-179") {
			t.Errorf("the justification does not name the run and rule: %q", sent.Message)
		}
		run, _ := h.runs.Get(id)
		if run.Phase != secassesssvc.PhaseHeld || run.Held == nil || len(run.Held.RequestIDs) != 1 || run.Held.RequestIDs[0] == 0 || !run.Reported || run.Tenancy != "managed" {
			t.Fatalf("run = %+v held %+v", run, run.Held)
		}
		if rows := h.auditRows(); rows["held"] != 1 {
			t.Fatalf("audit rows = %v", rows)
		}
		v := h.runView(id)
		if v.Phase != "held" || v.State != "held" || v.Held == nil || v.Held.Ready || len(v.Held.Rules) != 1 || v.Held.Rules[0].State != heldWaiting {
			t.Fatalf("view = %+v held %+v", v, v.Held)
		}
		// Not granted yet: the launch is refused and nothing starts.
		start := h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}})
		if c, body := h.launch(start); c != http.StatusConflict || body["code"] != codeRelaxNotGranted || h.lm.lastFreshSpec.Tool != "" {
			t.Fatalf("early start: %d %v", c, body)
		}
		if r, _ := h.runs.Get(id); r.Phase != secassesssvc.PhaseHeld {
			t.Fatalf("a refused start moved the run to %q", r.Phase)
		}
		// The organization approves: a grant lands in the node's cache.
		h.reqs.held = []accessgrant.Held{grantFor(31, h.hash, 2)}
		v = h.runView(id)
		if !v.Held.Ready || v.Held.Rules[0].State != heldApproved || v.Held.Rules[0].GrantID != 31 {
			t.Fatalf("approved view = %+v", v.Held)
		}
		// The plan replays the held run: same id, same prompt as the launch will send.
		rp := h.plan("&run=" + id)
		if rp.RunID != id || rp.Held == nil || !rp.Held.Ready || rp.Relax == nil || !relaxRow(t, rp, "R-179").Ticked || !strings.Contains(rp.Prompt, "lifted ONE guardrail") || !strings.Contains(rp.Prompt, "your organization's grant") {
			t.Fatalf("replay plan: id %s held %+v prompt %q", rp.RunID, rp.Held, rp.Prompt)
		}
		// A launch that names different relaxations is not this run.
		if c, body := h.launch(h.launchBody(id, nil)); c != http.StatusConflict || body["code"] != codeHeldRunMismatch {
			t.Fatalf("mismatch: %d %v", c, body)
		}
		// Start: one terminal, org grant recorded, no local approval.
		if c, body := h.launch(start); c != http.StatusOK {
			t.Fatalf("start: %d %v", c, body)
		}
		run, _ = h.runs.Get(id)
		if run.Phase != secassesssvc.PhaseStarted || run.Handle == "" || run.Held == nil || len(run.Relax) != 1 {
			t.Fatalf("started run = %+v", run)
		}
		if x := run.Relax[0]; x.State != string(secassess.RelaxOrgGrant) || x.GrantID != 31 || x.Route != "org_request" || x.ApprovalID != 0 || x.GrantedBy != "" {
			t.Fatalf("relaxation = %+v", x)
		}
		if h.approvals() != 0 {
			t.Errorf("a local approval was created for an org-approved rule")
		}
		rows := h.auditRows()
		if rows["launch"] != 1 || rows["held"] != 1 {
			t.Fatalf("audit rows = %v", rows)
		}
		if c, _ := h.launch(start); c != http.StatusConflict {
			t.Errorf("a second start of the same run: %d", c)
		}
	})
	t.Run("a grant narrower than the ask is said so and does not start the run", func(t *testing.T) {
		h := newManaged(t)
		id := secassesssvc.NewRunID()
		if code, out := h.request(id); code != http.StatusCreated {
			t.Fatalf("request: %d %s", code, out)
		}
		g := grantFor(40, "someotherprojecthash", 2)
		h.reqs.held = []accessgrant.Held{g}
		v := h.runView(id)
		if v.Held.Ready || v.Held.Rules[0].State != heldNarrower || v.Held.Rules[0].GrantID != 40 || !strings.Contains(v.Held.Rules[0].Why, "another project") {
			t.Fatalf("view = %+v", v.Held)
		}
	})
	t.Run("a rule an existing grant covers files nothing and the run is ready at once", func(t *testing.T) {
		h := newManaged(t)
		h.reqs.held = []accessgrant.Held{grantFor(50, h.hash, 3)}
		id := secassesssvc.NewRunID()
		code, out := h.request(id)
		if code != http.StatusCreated || len(h.reqs.sent) != 0 {
			t.Fatalf("request: %d %s (sent %d)", code, out, len(h.reqs.sent))
		}
		if v := h.runView(id); !v.Held.Ready {
			t.Fatalf("view = %+v", v.Held)
		}
	})
	t.Run("a fresh launch under an existing grant needs no hold", func(t *testing.T) {
		h := newManaged(t)
		h.reqs.held = []accessgrant.Held{grantFor(51, h.hash, 3)}
		id := secassesssvc.NewRunID()
		if code, body := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}})); code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		if run, _ := h.runs.Get(id); run.Relax[0].GrantID != 51 || run.Phase != "" {
			t.Fatalf("run = %+v", run)
		}
	})
	t.Run("a failed send leaves no run and takes back what went out", func(t *testing.T) {
		h := newManaged(t)
		h.reqs.sendErr = &orgclient.RequestRefusedError{}
		id := secassesssvc.NewRunID()
		code, out := h.request(id)
		if code != http.StatusBadRequest {
			t.Fatalf("request: %d %s", code, out)
		}
		if h.runs.Exists(id) {
			t.Errorf("a run was recorded for a refused request")
		}
		h.reqs.sendErr = orgclient.ErrOrgRequestCapReached
		if code, _ := h.request(secassesssvc.NewRunID()); code != http.StatusTooManyRequests {
			t.Errorf("cap: %d", code)
		}
		h.reqs.sendErr = store.ErrOutboxFull
		if code, _ := h.request(secassesssvc.NewRunID()); code != http.StatusTooManyRequests {
			t.Errorf("outbox: %d", code)
		}
	})
	t.Run("cancel withdraws the request and marks the run cancelled", func(t *testing.T) {
		h := newManaged(t)
		id := secassesssvc.NewRunID()
		if code, out := h.request(id); code != http.StatusCreated {
			t.Fatalf("request: %d %s", code, out)
		}
		w := postAssess(t, h.s.handleSecurityAssessCancel, "/api/security/assessments/cancel", map[string]any{"run": id}, true)
		if w.Code != http.StatusOK {
			t.Fatalf("cancel: %d %s", w.Code, w.Body)
		}
		run, _ := h.runs.Get(id)
		if run.Phase != secassesssvc.PhaseCancelled || len(h.reqs.withdrawn) != 1 || h.reqs.withdrawn[0] != run.Held.RequestIDs[0] {
			t.Fatalf("run %+v withdrawn %v", run, h.reqs.withdrawn)
		}
		if rows := h.auditRows(); rows["cancel"] != 1 {
			t.Errorf("audit rows = %v", rows)
		}
		// Cancelled is final: it cannot be cancelled again or started.
		if w := postAssess(t, h.s.handleSecurityAssessCancel, "/api/security/assessments/cancel", map[string]any{"run": id}, true); w.Code != http.StatusConflict {
			t.Errorf("second cancel: %d", w.Code)
		}
		if c, _ := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}})); c != http.StatusConflict {
			t.Errorf("start after cancel: %d", c)
		}
	})
	t.Run("a declined request shows the organization's answer", func(t *testing.T) {
		h := newManaged(t)
		id := secassesssvc.NewRunID()
		if code, out := h.request(id); code != http.StatusCreated {
			t.Fatalf("request: %d %s", code, out)
		}
		run, _ := h.runs.Get(id)
		h.reqs.declined = map[int64]bool{run.Held.RequestIDs[0]: true}
		securityAssessMyRequests.at = time.Time{} // drop the short cache
		v := h.runView(id)
		if v.Held.Rules[0].State != heldDeclined || v.Held.Rules[0].Why != "not this quarter" {
			t.Fatalf("view = %+v", v.Held)
		}
	})
	t.Run("an unenrolled node cannot ask", func(t *testing.T) {
		h := newRelaxHarness(t, relaxOn)
		h.lockRule()
		if code, _ := h.request(secassesssvc.NewRunID()); code != http.StatusConflict {
			t.Fatalf("request: %d", code)
		}
	})
	t.Run("nothing ticked needs the organization", func(t *testing.T) {
		h := newRelaxHarness(t, relaxOn)
		h.s.opts.Requests = h.reqs
		h.reqs.enrolled = true
		w := postAssess(t, h.s.handleSecurityAssessRequest, "/api/security/assessments/request", map[string]any{
			"assessment": "pentest_local", "project_root_hash": h.hash, "run_id": secassesssvc.NewRunID(), "target": "http://localhost:3000/",
			"relaxations": []string{secassess.RuleScanner},
		}, true)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "nothing_to_request") {
			t.Fatalf("request for a self row: %d %s", w.Code, w.Body)
		}
	})
}

// TestSecurityAssessManagedRunsAreReported: a managed node writes the audit
// rows for every run, with or without a relaxation (the enterprise rule); an
// individual node writes them only when it chose to.
func TestSecurityAssessManagedRunsAreReported(t *testing.T) {
	cases := []struct {
		name    string
		managed bool
		cfg     string
		want    int
	}{
		{"managed", true, "", 1},
		{"individual, off", false, "", 0},
		{"individual, on", false, "report_to_org = true\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRelaxHarness(t, tc.cfg)
			if tc.managed {
				h.managed(false)
			}
			id := secassesssvc.NewRunID()
			if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
				t.Fatalf("launch: %d %v", code, body)
			}
			if rows := h.auditRows(); rows["launch"] != tc.want {
				t.Fatalf("audit rows = %v, want %d launch", rows, tc.want)
			}
			if run, _ := h.runs.Get(id); run.Reported != (tc.want == 1) {
				t.Fatalf("reported = %v", run.Reported)
			}
		})
	}
}

// TestSecurityAssessSessionBindingConfidenceMatchesTermrun pins the seam the
// relaxation binds on: the threshold only the launcher's own out-of-band echo
// reaches, read against termrun's own confidence table.
func TestSecurityAssessSessionBindingConfidenceMatchesTermrun(t *testing.T) {
	conf := func(src termrun.Source) float64 {
		c, ok := termrun.Score("r", "s", []termrun.Observation{{Source: src}})
		if !ok {
			t.Fatalf("source %q does not score", src)
		}
		return c.Confidence
	}
	if got := conf(termrun.SourceOOB); got < secassess.BindMinConfidence {
		t.Errorf("an out-of-band echo scores %v, below the bind threshold %v", got, secassess.BindMinConfidence)
	}
	for _, src := range []termrun.Source{termrun.SourceDiscovered, termrun.SourceMarker, termrun.SourceHeuristic} {
		if got := conf(src); got >= secassess.BindMinConfidence {
			t.Errorf("source %q scores %v and would bind a relaxation", src, got)
		}
	}
}

// TestSecurityAssessReconcileEndsRelaxationsWithTheTerminal: the list's lazy
// pass uses the dashboard's resolver and removes the run's own approval row
// when its terminal is gone.
func TestSecurityAssessReconcileEndsRelaxationsWithTheTerminal(t *testing.T) {
	h := newRelaxHarness(t, relaxOn+"relaxation_scope = \"project\"\nreport_to_org = true\n")
	live := true
	h.s.opts.SessionResolver = func(string) (dashapi.TerminalSessionLink, bool) {
		return dashapi.TerminalSessionLink{SessionID: "sess-1", Confidence: 0.95}, live
	}
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, map[string]any{"relaxations": []string{secassess.RuleScanner}})); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	if h.approvals() != 1 {
		t.Fatalf("approvals = %d", h.approvals())
	}
	if v := h.runView(id); v.Relax[0].State != string(secassess.RelaxActive) || v.EndedAt != nil {
		t.Fatalf("live view = %+v", v)
	}
	live = false
	v := h.runView(id)
	if v.Relax[0].State != string(secassess.RelaxEnded) || v.Relax[0].EndReason != secassess.EndTerminalExit || v.EndedAt == nil {
		t.Fatalf("ended view = %+v", v)
	}
	if h.approvals() != 0 {
		t.Errorf("the run's approval row outlived its terminal")
	}
	if rows := h.auditRows(); rows["end"] != 1 {
		t.Errorf("audit rows = %v", rows)
	}
}

// TestSecurityAssessImportAuditRowIsContentFree: the import phase is one audit
// row for a reported run, and the launch row of the same run carries every
// effective setting and none of the project's name or path (the project here is
// named to look like part of an audit line).
func TestSecurityAssessImportAuditRowIsContentFree(t *testing.T) {
	h := newRelaxHarness(t, "report_to_org = true\n")
	h.s.opts.SARIFImport = nil
	hostileRoot, hostileHash := addHostileProject(t, h)
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, map[string]any{"project_root_hash": hostileHash})); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	// The import is not selected in this build, so it answers "unavailable"; a
	// reported run still writes its import row, with the outcome and counts.
	w := postAssess(t, h.s.handleSecurityAssessImport, "/api/security/assessments/import", map[string]any{"run": id}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	if rows := h.auditRows(); rows["import"] != 1 {
		t.Errorf("audit rows = %v", rows)
	}
	var detail string
	if err := h.s.db().QueryRowContext(context.Background(), `SELECT reason FROM guard_events WHERE rule_id = ? AND tool = ?`, store.SecAssessEventRuleID, store.SecAssessToolPrefix+"launch").Scan(&detail); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{h.root, hostileRoot, filepath.Base(hostileRoot), "evil", "999999", "deadbeef", "report.md", "findings.sarif"} {
		if strings.Contains(detail, banned) {
			t.Errorf("the launch row carries %q: %s", banned, detail)
		}
	}
	if !strings.Contains(detail, "relax_pentest_local=off") || !strings.Contains(detail, "report_to_org=on") {
		t.Errorf("the launch row does not carry the effective configuration: %s", detail)
	}
	// Every setting of the settings table is on the line, at its default here.
	def := config.DefaultSecurityAssessmentsConfig()
	for _, row := range securityAssessAuditSettings {
		if want := row.Key + "=" + row.Get(def); !strings.Contains(detail, " "+want) {
			t.Errorf("the launch row lacks %q: %s", want, detail)
		}
	}
}
