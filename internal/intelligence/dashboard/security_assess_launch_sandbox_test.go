//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// The first live run (2026-11-15) found every pen test launch refused with 409
// sandbox_required: the web side deliberately sends no sandbox fields for a
// task whose route chooses the sandbox (web terminalTask.ts serverSandbox), but
// the route read the body's own sandbox flag, so E6 always failed. The route
// decides. These tests pin that: the body the dialog really sends launches, and
// the sandbox, the live workspace and the backend are the route's own answer.

// dialogSandboxMembers are the launch members the dialog leaves off for a task
// that runs only in a sandbox: the Isolation and Workspace controls it hides
// and the sign-in step that goes with them (NewTerminalDialog sandboxManaged).
var dialogSandboxMembers = []string{
	"sandbox", "backend", "workspace_source", "workspace_remote", "workspace_branch", "sign_in_seed", "sign_in_ask",
}

// dialogBody is the body the New terminal dialog sends for a pen test or red
// team: the task's own fields, then the agent choice. No sandbox member.
func dialogBody(kind, hash, id string, extra map[string]any) map[string]any {
	b := map[string]any{
		"assessment": kind, "project_root_hash": hash, "run_id": id, "tool": "claude-code",
		"target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/",
	}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// TestSecurityAssessLaunchRouteChoosesTheSandbox: a kind that runs only in a
// sandbox is sandboxed by the route whatever the body says, and what the body
// does name (a backend, a workspace source) is still checked, never replaced.
func TestSecurityAssessLaunchRouteChoosesTheSandbox(t *testing.T) {
	// A retest needs the request helper; the machine running this test may have no python3.
	stubTools(t, secassess.ToolFacts{"python3": true})
	good := assessProbe("proxy_only", "claude-code")
	s, lm, root := assessTestServer(t, &good)
	hash := secposture.ProjectRootHash(root)
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	type want struct {
		status  int
		rule    string
		sandbox bool
		backend string
		source  string
	}
	rows := []struct {
		name string
		kind string
		tool string
		body map[string]any
		want want
	}{
		{"pen test, the dialog's body", "pentest_local", "", nil, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"red team, the dialog's body", "red_team_local", "", nil, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"pen test with a model chosen", "pentest_local", "", map[string]any{"model": "sonnet"}, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"sandbox true (an older body)", "pentest_local", "", map[string]any{"sandbox": true}, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"sandbox false is not read: the route sandboxes", "pentest_local", "", map[string]any{"sandbox": false}, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"backend auto", "pentest_local", "", map[string]any{"backend": "auto"}, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"a grounded backend named", "pentest_local", "", map[string]any{"backend": "bwrap"}, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"the live source named", "pentest_local", "", map[string]any{"workspace_source": "live"}, want{status: 200, sandbox: true, backend: "bwrap", source: "live"}},
		{"a backend that is not grounded is refused, not replaced", "pentest_local", "", map[string]any{"backend": "oci-runc"}, want{status: 409, rule: "E9"}},
		{"a clone source is refused, not replaced", "pentest_local", "", map[string]any{"workspace_source": "clone-local"}, want{status: 409, rule: "E10"}},
		{"no target still waits for one", "pentest_local", "", map[string]any{"target": "", "confirm_target": ""}, want{status: 409, rule: "E3"}},
		{"a different confirmation is still refused", "pentest_local", "", map[string]any{"confirm_target": "http://localhost:3001/"}, want{status: 409, rule: "E4"}},
		{"an agent that cannot be sandboxed is still refused", "pentest_local", "hermes", nil, want{status: 409, rule: "E7"}},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			id := secassesssvc.NewRunID()
			body := dialogBody(tc.kind, hash, id, tc.body)
			if tc.tool != "" {
				body["tool"] = tc.tool
			}
			lm.lastFreshSpec = FreshLaunchSpec{}
			w := postAssess(t, s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
			if w.Code != tc.want.status {
				t.Fatalf("status %d, want %d (%s)", w.Code, tc.want.status, w.Body)
			}
			spec := lm.lastFreshSpec
			if tc.want.status != http.StatusOK {
				var out map[string]string
				_ = json.Unmarshal(w.Body.Bytes(), &out)
				if out["rule"] != tc.want.rule || out["code"] == "" || out["code"] == secassess.CodeSandboxRequired {
					t.Fatalf("refusal = %v, want rule %s", out, tc.want.rule)
				}
				if spec.Tool != "" {
					t.Fatalf("the launcher was reached: %+v", spec)
				}
				return
			}
			if spec.Sandbox != tc.want.sandbox || spec.Backend != tc.want.backend || spec.WorkspaceSource != tc.want.source || spec.ProjectRoot != root {
				t.Fatalf("spec = %+v, want sandbox %v backend %q source %q", spec, tc.want.sandbox, tc.want.backend, tc.want.source)
			}
			run, ok := runs.Get(id)
			if !ok || !run.Sandboxed || run.Backend != tc.want.backend || run.Tier != "proxy_only" || run.Target != "http://localhost:3000/" {
				t.Fatalf("run = %+v (recorded %v)", run, ok)
			}
		})
	}
}

// TestSecurityAssessLaunchRouteDoesNotSandboxWhatItDoesNotRequire: the route's
// sandbox rule is for a kind that runs only in a sandbox. A kind whose sandbox
// is the developer's own choice keeps it: no sandbox member runs on the host, a
// true one runs in the box (the existing launch of a threat model).
func TestSecurityAssessLaunchRouteDoesNotSandboxWhatItDoesNotRequire(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	s, lm, root := assessTestServer(t, &good)
	hash := secposture.ProjectRootHash(root)
	for _, tc := range []struct {
		name    string
		kind    string
		sandbox any
		want    bool
	}{
		{"threat model with no member", "threat_model", nil, false},
		{"threat model false", "threat_model", false, false},
		{"threat model true", "threat_model", true, true},
		{"cloud posture with no member", "cspm_readonly", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"assessment": tc.kind, "project_root_hash": hash, "run_id": secassesssvc.NewRunID(), "tool": "claude-code"}
			if tc.sandbox != nil {
				body["sandbox"] = tc.sandbox
			}
			lm.lastFreshSpec = FreshLaunchSpec{}
			w := postAssess(t, s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
			if w.Code != http.StatusOK {
				t.Fatalf("launch: %d %s", w.Code, w.Body)
			}
			if lm.lastFreshSpec.Sandbox != tc.want {
				t.Fatalf("sandbox = %v, want %v (%+v)", lm.lastFreshSpec.Sandbox, tc.want, lm.lastFreshSpec)
			}
		})
	}
}

// TestSecurityAssessLaunchRouteStillRefusesWhatItCannotConfine: the route
// sandboxes only what it can confine. The rules after E6 hold for the dialog's
// body: no sandbox support, an unconfined tier and an agent without a proxy
// route each refuse it and nothing starts.
func TestSecurityAssessLaunchRouteStillRefusesWhatItCannotConfine(t *testing.T) {
	for _, tc := range []struct {
		name string
		av   *SandboxAvailability
		want string
		code string
	}{
		{"no sandbox probe", nil, "E7", secassess.CodeSandboxUnavailable},
		{"the internet tier", ptrAvail(assessProbe("internet", "claude-code")), "E8", secassess.CodeTierNotConfined},
		{"the host tier", ptrAvail(assessProbe("host", "claude-code")), "E8", secassess.CodeTierNotConfined},
		{"the none tier", ptrAvail(assessProbe("none", "claude-code")), "E8", secassess.CodeTierNotConfined},
		{"no sandboxable agent", ptrAvail(assessProbe("proxy_only")), "E7", secassess.CodeSandboxUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, lm, root := assessTestServer(t, tc.av)
			w := postAssess(t, s.handleSecurityAssessLaunch, "/api/security/assessments/launch",
				dialogBody("pentest_local", secposture.ProjectRootHash(root), secassesssvc.NewRunID(), nil), true)
			var out map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != http.StatusConflict || out["rule"] != tc.want || out["code"] != tc.code || lm.lastFreshSpec.Tool != "" {
				t.Fatalf("%d %s (launched %+v)", w.Code, w.Body, lm.lastFreshSpec)
			}
		})
	}
}

func ptrAvail(a SandboxAvailability) *SandboxAvailability { return &a }

// TestSecurityAssessEligibilityRequest is the request the launch hands the
// eligibility rules, row by row: the sandbox flag is the route's for a kind that
// requires one and the body's for the rest; every other member passes through.
func TestSecurityAssessEligibilityRequest(t *testing.T) {
	named := securityAssessLaunchRequest{
		Target: "http://localhost:3000/", ConfirmTarget: "http://localhost:3000/",
	}
	named.Backend, named.WorkspaceSource = "bwrap", "live"
	for _, tc := range []struct {
		name    string
		kind    secassess.ID
		body    securityAssessLaunchRequest
		relax   bool
		sandbox bool
	}{
		{"pen test, empty body", secassess.PentestLocal, securityAssessLaunchRequest{}, false, true},
		{"pen test, sandbox false", secassess.PentestLocal, withSandbox(securityAssessLaunchRequest{}, false), false, true},
		{"pen test, sandbox true", secassess.PentestLocal, withSandbox(securityAssessLaunchRequest{}, true), false, true},
		{"red team, empty body", secassess.RedTeamLocal, securityAssessLaunchRequest{}, false, true},
		{"threat model, empty body", secassess.ThreatModel, securityAssessLaunchRequest{}, false, false},
		{"threat model, sandbox true", secassess.ThreatModel, withSandbox(securityAssessLaunchRequest{}, true), false, true},
		{"cloud posture, empty body", secassess.CSPMReadonly, securityAssessLaunchRequest{}, false, false},
		{"members pass through, tier relaxed", secassess.PentestLocal, named, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, ok := secassess.KindByID(string(tc.kind))
			if !ok {
				t.Fatalf("no kind %q", tc.kind)
			}
			got := securityAssessEligibilityRequest(k, tc.body, tc.relax)
			want := secassess.Request{
				Kind: tc.kind, Target: tc.body.Target, ConfirmTarget: tc.body.ConfirmTarget, Sandbox: tc.sandbox,
				Backend: tc.body.Backend, WorkspaceSource: tc.body.WorkspaceSource, TierRelax: tc.relax,
			}
			if got != want {
				t.Fatalf("request\n got: %+v\nwant: %+v", got, want)
			}
		})
	}
}

func withSandbox(b securityAssessLaunchRequest, v bool) securityAssessLaunchRequest {
	b.Sandbox = v
	return b
}

// TestHeldAssessmentLaunchCardAgreesWithTheRoute: the confirm card of a held
// launch says the run is sandboxed exactly when the route will sandbox it, so a
// human is never shown "unsandboxed: runs on this machine with your access" for
// a pen test the route puts in a box, and is still warned of a run that is bare.
func TestHeldAssessmentLaunchCardAgreesWithTheRoute(t *testing.T) {
	row, ok := launchRouteFor("/api/security/assessments/launch")
	if !ok {
		t.Fatal("no assessments launch row")
	}
	const path = "/api/security/assessments/launch"
	for _, tc := range []struct {
		name      string
		body      string
		sandboxed bool
		summary   string
	}{
		{"pen test, the dialog's body", `{"assessment":"pentest_local","project_root_hash":"h1","run_id":"20261114-ab12cd","target":"http://localhost:3000/","confirm_target":"http://localhost:3000/","tool":"claude-code"}`, true, "auto"},
		{"red team, the dialog's body", `{"assessment":"red_team_local","tool":"claude-code"}`, true, "auto"},
		{"pen test, sandbox false is not read", `{"assessment":"pentest_local","sandbox":false,"tool":"claude-code"}`, true, "auto"},
		{"pen test, a backend named", `{"assessment":"pentest_local","backend":"bwrap","tool":"claude-code"}`, true, "bwrap"},
		{"pen test, folded member names", `{"ASSESSMENT":"pentest_local","tool":"claude-code"}`, true, "auto"},
		{"pen test, sandbox true", `{"assessment":"pentest_local","sandbox":true,"tool":"claude-code"}`, true, "auto"},
		{"threat model, no member runs on the host", `{"assessment":"threat_model","tool":"claude-code"}`, false, ""},
		{"threat model, sandbox true", `{"assessment":"threat_model","sandbox":true,"tool":"claude-code"}`, true, "auto"},
		{"an unknown kind is not sandboxed by the route", `{"assessment":"nope","tool":"claude-code"}`, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := heldSummary(row, path, []byte(tc.body))
			var d dashapi.PendingLaunchDetail
			for _, got := range p.Details {
				if got.Label == "sandbox" {
					d = got
				}
			}
			if tc.sandboxed {
				if d.Value != "sandboxed" || d.Warn {
					t.Errorf("sandbox line = %+v, want sandboxed", d)
				}
			} else if !strings.Contains(d.Value, "unsandboxed") || !d.Warn {
				t.Errorf("sandbox line = %+v, want the unsandboxed warning", d)
			}
			if p.Sandbox != tc.summary {
				t.Errorf("summary sandbox = %q, want %q", p.Sandbox, tc.summary)
			}
		})
	}
	// A route that does not choose the sandbox is read from its own member only.
	fix, _ := launchRouteFor("/api/security/fix/launch")
	if p := heldSummary(fix, "/api/security/fix/launch", []byte(`{"assessment":"pentest_local","tool":"claude-code"}`)); p.Sandbox != "" {
		t.Errorf("a route with no sandbox rule read the assessment member: %+v", p)
	}
}

// launchBodiesFixture is the file web/src/lib/secAssess.test.ts writes: the body
// the New terminal dialog posts to the assessments launch for each confined
// task, built by the web's own assessTaskFor and taskLaunchBody.
const launchBodiesFixture = "../../secassess/testdata/assess_launch_bodies.json"

// TestDialogLaunchBodiesStartPastTheSandboxRules is the pin between the two
// sides of the contract: the web sends no sandbox fields for a task whose route
// chooses the sandbox, and the route starts that body. A member the web adds or
// renames fails the decode here by name; a sandbox member the web starts
// sending fails the key check (the web's own test asserts the same list, so
// either side moving without the other is loud on both).
func TestDialogLaunchBodiesStartPastTheSandboxRules(t *testing.T) {
	data, err := os.ReadFile(launchBodiesFixture)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 3 {
		t.Fatalf("only %d fixtures: the file is cut short", len(fixtures))
	}
	good := assessProbe("proxy_only", "claude-code")
	s, lm, root := assessTestServer(t, &good)
	hash := secposture.ProjectRootHash(root)
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	for name, blob := range fixtures {
		t.Run(name, func(t *testing.T) {
			dec := json.NewDecoder(bytes.NewReader(blob))
			dec.DisallowUnknownFields()
			var req securityAssessLaunchRequest
			if err := dec.Decode(&req); err != nil {
				t.Fatalf("the web's body is not a launch body: %v", err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(blob, &members); err != nil {
				t.Fatal(err)
			}
			for _, m := range dialogSandboxMembers {
				if _, has := members[m]; has {
					t.Errorf("the web sends %q for a task whose route chooses the sandbox", m)
				}
			}
			k, ok := secassess.KindByID(req.Assessment)
			if !ok || !securityAssessRouteSandboxes(k) {
				t.Fatalf("fixture %s names %q, which is not a kind the route sandboxes", name, req.Assessment)
			}
			// The fixture's own project and run are placeholders: this server's project,
			// and a fresh run id, are what the route needs; every other member is as sent.
			members["project_root_hash"], _ = json.Marshal(hash)
			id := secassesssvc.NewRunID()
			members["run_id"], _ = json.Marshal(id)
			// A retest names an earlier run whose checked model holds the findings it asks
			// for: seed one, and name it, in place of the fixture's placeholder.
			if _, has := members["of_run"]; has {
				of := seedRetestableRun(t, runs, hash, req.FindingIDs)
				members["of_run"], _ = json.Marshal(of)
			}
			body := make(map[string]any, len(members))
			for k, v := range members {
				var any1 any
				if err := json.Unmarshal(v, &any1); err != nil {
					t.Fatal(err)
				}
				body[k] = any1
			}
			lm.lastFreshSpec = FreshLaunchSpec{}
			w := postAssess(t, s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
			if w.Code != http.StatusOK {
				t.Fatalf("the body the dialog sends was refused: %d %s", w.Code, w.Body)
			}
			spec := lm.lastFreshSpec
			if !spec.Sandbox || spec.WorkspaceSource != "live" || spec.Backend != "bwrap" || spec.ProjectRoot != root {
				t.Fatalf("spec = %+v", spec)
			}
			if run, ok := runs.Get(id); !ok || !run.Sandboxed || run.Kind != req.Assessment {
				t.Fatalf("run = %+v (recorded %v)", run, ok)
			}
		})
	}
	// Every kind the route sandboxes has a fixture, so a kind added to the table
	// cannot reach the dialog without its body being read here.
	var covered []string
	for _, blob := range fixtures {
		var req securityAssessLaunchRequest
		_ = json.Unmarshal(blob, &req)
		covered = append(covered, req.Assessment)
	}
	for _, k := range secassess.Kinds() {
		if securityAssessRouteSandboxes(k) && !slices.Contains(covered, string(k.ID)) {
			t.Errorf("kind %s is sandboxed by the route but the web writes no launch body for it (web/src/lib/secAssess.test.ts)", k.ID)
		}
	}
}

// TestSecurityAssessBodySandboxed: the card's reading of a held body is the
// route's own answer for the kind the body names, and no for a body that names
// no kind the route knows (the launch itself refuses such a body).
func TestSecurityAssessBodySandboxed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"a kind that requires the sandbox", `{"assessment":"pentest_local"}`, true},
		{"the other required kind", `{"assessment":"red_team_local"}`, true},
		{"a kind whose sandbox is the developer's choice", `{"assessment":"threat_model"}`, false},
		{"a kind with no launch", `{"assessment":"rasp"}`, false},
		{"an unknown kind", `{"assessment":"nope"}`, false},
		{"no kind", `{"tool":"claude-code"}`, false},
		{"a body that is not an object", `["pentest_local"]`, false},
		{"not JSON", `pentest_local`, false},
		{"empty", ``, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := securityAssessBodySandboxed([]byte(tc.body)); got != tc.want {
				t.Fatalf("securityAssessBodySandboxed(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
