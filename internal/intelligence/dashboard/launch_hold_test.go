package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// fakePending is an in-memory dashapi.PendingLaunches with the daemon's
// confirm rule (an agent's confirm is refused; a hold is single use).
type fakePending struct {
	mu    sync.Mutex
	n     int
	holds map[string]dashapi.PendingLaunch
	start map[string]func(context.Context) (dashapi.PendingLaunchResult, error)
}

func newFakePending() *fakePending {
	return &fakePending{holds: map[string]dashapi.PendingLaunch{}, start: map[string]func(context.Context) (dashapi.PendingLaunchResult, error){}}
}

func (f *fakePending) Hold(p dashapi.PendingLaunch, start func(context.Context) (dashapi.PendingLaunchResult, error)) (dashapi.PendingLaunch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	p.ID = "pend-" + string(rune('0'+f.n))
	f.holds[p.ID], f.start[p.ID] = p, start
	return p, nil
}

func (f *fakePending) List() []dashapi.PendingLaunch {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []dashapi.PendingLaunch
	for _, p := range f.holds {
		out = append(out, p)
	}
	return out
}

func (f *fakePending) Confirm(ctx context.Context, id, who string) (dashapi.PendingLaunch, dashapi.PendingLaunchResult, error) {
	if who == dashapi.InitiatorAgent {
		return dashapi.PendingLaunch{}, dashapi.PendingLaunchResult{}, &dashapi.PendingLaunchError{Code: dashapi.PendingCodeConfirmRefused, Message: "an agent may not confirm"}
	}
	f.mu.Lock()
	p, ok := f.holds[id]
	start := f.start[id]
	delete(f.holds, id)
	f.mu.Unlock()
	if !ok {
		return dashapi.PendingLaunch{}, dashapi.PendingLaunchResult{}, &dashapi.PendingLaunchError{Code: dashapi.PendingCodeNotFound, Message: "no such hold"}
	}
	res, err := start(ctx)
	return p, res, err
}

func (f *fakePending) Reject(id string) (dashapi.PendingLaunch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.holds[id]
	if !ok {
		return dashapi.PendingLaunch{}, &dashapi.PendingLaunchError{Code: dashapi.PendingCodeNotFound, Message: "no such hold"}
	}
	delete(f.holds, id)
	return p, nil
}

// TestAgentDashboardLaunchIsHeldUntilAHumanConfirms pins the ruling on
// audit M2 for the dashboard: an agent's POST to a launch route starts
// nothing and answers 202 with the hold; an agent's confirm is refused; a
// human's confirm replays exactly that request, recorded as the agent's.
func TestAgentDashboardLaunchIsHeldUntilAHumanConfirms(t *testing.T) {
	lm := &fakeLaunchManager{}
	pending := newFakePending()
	caller := dashapi.InitiatorAgent
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{
		DB: database, LaunchManager: lm, PendingLaunches: pending,
		LaunchCaller: func(context.Context, netip.AddrPort, netip.AddrPort) (string, string) {
			if caller == dashapi.InitiatorAgent {
				return caller, "sess-parent"
			}
			return caller, ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	rec := postGUILaunch(t, h, terminalLaunchRequest{Tool: "claude-code", ProjectRoot: "/w"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("an agent's launch = %d %s, want 202", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code    string                `json:"code"`
		Pending dashapi.PendingLaunch `json:"pending"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Code != dashapi.PendingCodeConfirmRequired || resp.Pending.ID == "" || resp.Pending.Tool != "claude-code" || resp.Pending.Initiator != "agent" {
		t.Fatalf("hold = %+v", resp)
	}
	if lm.lastFreshSpec.Tool != "" {
		t.Fatalf("an agent's launch reached the launch manager: %+v", lm.lastFreshSpec)
	}

	confirm := func(id string) *httptest.ResponseRecorder {
		req := armLocalWrite(httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/terminal/pending/"+id+"/confirm", strings.NewReader(`{}`)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := confirm(resp.Pending.ID); rec.Code != http.StatusForbidden || lm.lastFreshSpec.Tool != "" {
		t.Fatalf("an agent's confirm = %d %s (launched %+v), want 403", rec.Code, rec.Body.String(), lm.lastFreshSpec)
	}
	caller = "human_dashboard"
	if rec := confirm(resp.Pending.ID); rec.Code != http.StatusOK {
		t.Fatalf("a human's confirm = %d %s", rec.Code, rec.Body.String())
	}
	if lm.lastFreshSpec.Tool != "claude-code" || lm.lastFreshSpec.ProjectRoot != "/w" || lm.lastFreshSpec.Initiator != "agent" || lm.lastFreshSpec.ParentSessionID != "sess-parent" {
		t.Fatalf("confirmed launch spec = %+v", lm.lastFreshSpec)
	}
	if rec := confirm(resp.Pending.ID); rec.Code != http.StatusNotFound {
		t.Fatalf("a second confirm = %d, want 404 (single use)", rec.Code)
	}
	// A human's own launch is never held.
	lm.lastFreshSpec = FreshLaunchSpec{}
	if rec := postGUILaunch(t, h, terminalLaunchRequest{Tool: "codex"}); rec.Code != http.StatusOK || lm.lastFreshSpec.Tool != "codex" {
		t.Fatalf("a human's launch = %d, spec %+v", rec.Code, lm.lastFreshSpec)
	}
}

// TestAgentLaunchWithoutAHoldIsRefused: with no hold store an agent's
// launch is refused, never run unconfirmed.
func TestAgentLaunchWithoutAHoldIsRefused(t *testing.T) {
	lm := &fakeLaunchManager{}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, LaunchManager: lm, LaunchCaller: func(context.Context, netip.AddrPort, netip.AddrPort) (string, string) {
		return dashapi.InitiatorAgent, ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	rec := postGUILaunch(t, s.Handler(), terminalLaunchRequest{Tool: "claude-code"})
	if rec.Code != http.StatusForbidden || lm.lastFreshSpec.Tool != "" {
		t.Fatalf("= %d %s, launched %+v", rec.Code, rec.Body.String(), lm.lastFreshSpec)
	}
}

// TestBenchmarkDryRunIsNotHeld: the benchmark row holds only a spend run.
func TestBenchmarkDryRunIsNotHeld(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"spec":"x"}`, false},
		{`{"spec":"x","confirm_spend":false}`, false},
		{`{"spec":"x","confirm_spend":true}`, true},
		{`not json`, true},
	} {
		if got := benchmarkSpendBody([]byte(tc.body)); got != tc.want {
			t.Errorf("benchmarkSpendBody(%s) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

// TestHeldDetailsShowEveryBodyMember pins audit M-B (lane cli-2 fixes-2):
// a held dashboard launch's card carries every top-level member of the
// body the confirm replays, plus the path's session, and says plainly when
// the launch is unsandboxed or copies a sign-in.
func TestHeldDetailsShowEveryBodyMember(t *testing.T) {
	bodies := map[string]string{
		"/api/terminal/launch": `{"kind":"gui","tool":"claude-code","project_root":"/w","model":"opus","sandbox":false,"workspace_source":"clone-remote","workspace_remote":"https://e.x/r.git","workspace_branch":"fix-1","backend":"bwrap","sign_in_seed":true,"sign_in_ask":false,"future_field":{"x":1}}`,
		"/api/arena/runs":      `{"prompt":"do it","candidates":[{"tool":"codex"},{"tool":"claude-code"}],"project_root":"/w"}`,
		"/api/session/":        `{"carry":"full","fork_message":3}`,
		"/api/tools/launch":    `{"tool":"claude-code"}`,
		"/api/benchmarks/run":  `{"spec":"name = 'x'","confirm_spend":true,"allow_unpriced":true}`,
		// Code security tasks: the fix route's selection and the assessment's
		// run, target and its echo, each with the agent choice.
		"/api/security/fix/launch":         `{"query":"","finding":"F-1","project_root_hash":"h1","tool":"claude-code","model":"opus"}`,
		"/api/security/assessments/launch": `{"assessment":"pentest_local","project_root_hash":"h1","run_id":"20261114-ab12cd","target":"http://localhost:3000/","confirm_target":"http://localhost:3000/","relaxations":["R-179"],"tier_relax":true,"tool":"claude-code","model":"opus"}`,
		"/api/security/assessments/fix":    `{"run":"3fa9c2d17b0e4a56","item":"T-1","prompt_sha256":"abc","tool":"claude-code","model":"opus"}`,
	}
	for _, row := range agentLaunchRoutes {
		body, ok := bodies[row.pattern]
		if !ok {
			t.Errorf("row %q has no sample body", row.pattern)
			continue
		}
		path := launchRouteSamples[row.pattern].path
		details := heldSummary(row, path, []byte(body)).Details
		labels := map[string]dashapi.PendingLaunchDetail{}
		for _, d := range details {
			labels[d.Label] = d
		}
		members, ok := orderedMembers([]byte(body))
		if !ok {
			t.Fatalf("sample body of %s does not decode", row.pattern)
		}
		for _, m := range members {
			if m.key == "sandbox" {
				continue // read as the sandbox line
			}
			if _, ok := labels[m.key]; !ok {
				t.Errorf("%s: body member %q is not on the confirm card: %+v", row.pattern, m.key, details)
			}
		}
		if row.pattern == "/api/session/" && labels["session"].Value != "abc" {
			t.Errorf("session route card lacks the session: %+v", details)
		}
	}
	tl := heldSummary(agentLaunchRoutes[0], "/api/terminal/launch", []byte(bodies["/api/terminal/launch"])).Details
	byLabel := map[string]dashapi.PendingLaunchDetail{}
	for _, d := range tl {
		byLabel[d.Label] = d
	}
	if d := byLabel["sandbox"]; !d.Warn || !strings.Contains(d.Value, "unsandboxed") {
		t.Errorf("an unsandboxed launch is not said so: %+v", d)
	}
	if d := byLabel["sign_in_seed"]; !d.Warn || !strings.Contains(d.Value, "copies your sign-in") {
		t.Errorf("the sign-in copy is not said plainly: %+v", d)
	}
	if d := byLabel["kind"]; !strings.Contains(d.Value, "desktop app") {
		t.Errorf("a GUI launch is not said so: %+v", d)
	}
}

// TestHeldDetailsRelaxationsAndFixSandbox pins plan section 13.11: a held
// assessment launch shows the relaxations it carries as warnings, and the fix
// launch (which has no sandbox control at all) says "unsandboxed" instead of
// saying nothing about the sandbox.
func TestHeldDetailsRelaxationsAndFixSandbox(t *testing.T) {
	rowFor := func(pattern string) agentLaunchRoute {
		for _, r := range agentLaunchRoutes {
			if r.pattern == pattern {
				return r
			}
		}
		t.Fatalf("no launch row %q", pattern)
		return agentLaunchRoute{}
	}
	label := func(ds []dashapi.PendingLaunchDetail, name string) (dashapi.PendingLaunchDetail, bool) {
		for _, d := range ds {
			if strings.EqualFold(d.Label, name) {
				return d, true
			}
		}
		return dashapi.PendingLaunchDetail{}, false
	}
	fix := heldSummary(rowFor("/api/security/fix/launch"), "/api/security/fix/launch", []byte(`{"finding":"F-1","project_root_hash":"h1","tool":"claude-code"}`)).Details
	if d, ok := label(fix, "sandbox"); !ok || !d.Warn || !strings.Contains(d.Value, "unsandboxed") {
		t.Errorf("the fix launch card does not say it is unsandboxed: %+v", fix)
	}
	for _, c := range []struct {
		name, body string
		relaxWarn  bool
		tierWarn   bool
	}{
		{"none", `{"assessment":"pentest_local","project_root_hash":"h1","sandbox":true}`, false, false},
		{"empty list", `{"assessment":"pentest_local","relaxations":[],"tier_relax":false,"sandbox":true}`, false, false},
		{"rule and tier", `{"assessment":"pentest_local","relaxations":["R-179"],"tier_relax":true,"sandbox":true}`, true, true},
		{"folded spelling", `{"assessment":"pentest_local","RELAXATIONS":["R-179"],"Tier_Relax":true,"sandbox":true}`, true, true},
	} {
		ds := heldSummary(rowFor("/api/security/assessments/launch"), "/api/security/assessments/launch", []byte(c.body)).Details
		rel, hasRel := label(ds, "relaxations")
		tier, hasTier := label(ds, "tier_relax")
		if hasRel && rel.Warn != c.relaxWarn {
			t.Errorf("%s: relaxations warn = %v, want %v (%+v)", c.name, rel.Warn, c.relaxWarn, rel)
		}
		if hasTier && tier.Warn != c.tierWarn {
			t.Errorf("%s: tier_relax warn = %v, want %v (%+v)", c.name, tier.Warn, c.tierWarn, tier)
		}
		if c.relaxWarn && (!hasRel || !hasTier) {
			t.Errorf("%s: a relaxation member is missing from the card: %+v", c.name, ds)
		}
	}
}
