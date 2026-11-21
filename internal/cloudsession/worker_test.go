package cloudsession

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

func envMap(m map[string]string) LookupEnv {
	return func(n string) (string, bool) {
		v, ok := m[n]
		return v, ok
	}
}

const testPort = 18820

// anthropicHosted is the live-grounded Anthropic-hosted environment.
var anthropicHosted = map[string]string{
	"CLAUDE_CODE_REMOTE":                  "true",
	"CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE": "cloud_default",
}

// TestWorkerEnvironmentRows: one case per row of the worker table, with that
// environment's proof present.
func TestWorkerEnvironmentRows(t *testing.T) {
	cases := []struct {
		env      string
		vars     map[string]string
		verdict  WorkerVerdict
		route    string // "NAME=value" of the one route variable
		reasonIn string
	}{
		{
			env:     "claude-code-self-hosted",
			vars:    map[string]string{"CLAUDE_CODE_REMOTE": "true", WorkerAttestEnv: "claude-code-self-hosted"},
			verdict: VerdictRoute,
			route:   "ANTHROPIC_BASE_URL=http://127.0.0.1:18820",
		},
		{
			env:     "copilot-self-hosted-runner",
			vars:    map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted", "COPILOT_PROVIDER_API_KEY": "k", "COPILOT_MODEL": "gpt-x"},
			verdict: VerdictRoute,
			route:   "COPILOT_PROVIDER_BASE_URL=http://127.0.0.1:18820/v1",
		},
		{
			env:      "devin-outpost",
			vars:     map[string]string{WorkerAttestEnv: "devin-outpost"},
			verdict:  VerdictUnrouted,
			reasonIn: "agent loop",
		},
		{
			env:     "warp-self-hosted-worker",
			vars:    map[string]string{WorkerAttestEnv: "warp-self-hosted-worker"},
			verdict: VerdictRoute,
			route:   "ANTHROPIC_BASE_URL=http://127.0.0.1:18820",
		},
	}
	if len(cases) != len(workerEnvironments) {
		t.Fatalf("%d cases for %d worker table rows", len(cases), len(workerEnvironments))
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			p, err := PlanWorker(WorkerRequest{Env: tc.env, ProxyPort: testPort, LookupEnv: envMap(tc.vars)})
			if err != nil {
				t.Fatal(err)
			}
			if p.Verdict != tc.verdict {
				t.Fatalf("verdict %s (%s), want %s", p.Verdict, p.Reason, tc.verdict)
			}
			if p.Location != ExecutionCustomerWorker {
				t.Fatalf("location %q, want customer_worker", p.Location)
			}
			if tc.route != "" {
				if len(p.Route) != 1 || p.Route[0].Name+"="+p.Route[0].Value != tc.route {
					t.Fatalf("route %+v, want %s", p.Route, tc.route)
				}
			} else if len(p.Route) != 0 {
				t.Fatalf("unexpected route %+v", p.Route)
			}
			if tc.reasonIn != "" && !strings.Contains(p.Reason, tc.reasonIn) {
				t.Fatalf("reason %q lacks %q", p.Reason, tc.reasonIn)
			}
		})
	}
}

// TestWorkerRefusesVendorHosted: a vendor-hosted marker refuses every
// environment, even with the administrator attestation for that
// environment set (a repository setup script on a vendor sandbox could set
// it), and the plan carries no route and no customer_worker location.
func TestWorkerRefusesVendorHosted(t *testing.T) {
	hosted := []struct {
		name string
		vars map[string]string
	}{
		{"anthropic-hosted claude code", anthropicHosted},
		{"github-hosted runner", map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "COPILOT_PROVIDER_API_KEY": "k", "COPILOT_MODEL": "m"}},
	}
	for _, h := range hosted {
		for _, e := range workerEnvironments {
			t.Run(h.name+"/"+e.ID, func(t *testing.T) {
				vars := map[string]string{WorkerAttestEnv: e.ID}
				for k, v := range h.vars {
					vars[k] = v
				}
				p, err := PlanWorker(WorkerRequest{Env: e.ID, ProxyPort: testPort, LookupEnv: envMap(vars)})
				if err != nil {
					t.Fatal(err)
				}
				if p.Verdict != VerdictRefused {
					t.Fatalf("verdict %s (%s), want refused", p.Verdict, p.Reason)
				}
				if !strings.Contains(p.Reason, "CA-D10") || p.HostedEnv == "" {
					t.Fatalf("refusal does not name the vendor-hosted rule: %q (hosted env %q)", p.Reason, p.HostedEnv)
				}
				if p.Location != "" || len(p.Route) != 0 {
					t.Fatalf("refused plan carries location %q / route %+v", p.Location, p.Route)
				}
			})
		}
	}
}

// TestWorkerNotProvenRefuses: no marker at all (a developer laptop) refuses
// every environment: unknown is never customer compute.
func TestWorkerNotProvenRefuses(t *testing.T) {
	for _, e := range workerEnvironments {
		p, err := PlanWorker(WorkerRequest{Env: e.ID, ProxyPort: testPort, LookupEnv: envMap(nil)})
		if err != nil {
			t.Fatal(err)
		}
		if p.Verdict != VerdictRefused || !strings.Contains(p.Reason, "not proven") {
			t.Fatalf("%s: verdict %s (%s), want refused not proven", e.ID, p.Verdict, p.Reason)
		}
		// An attestation for ANOTHER environment proves nothing here.
		other := map[string]string{WorkerAttestEnv: "something-else", "CLAUDE_CODE_REMOTE": "true"}
		if p, _ := PlanWorker(WorkerRequest{Env: e.ID, ProxyPort: testPort, LookupEnv: envMap(other)}); p.Verdict != VerdictRefused {
			t.Fatalf("%s: a foreign attestation was accepted: %s", e.ID, p.Reason)
		}
	}
}

// TestWorkerVerdictRows: one case per row of the verdict table.
func TestWorkerVerdictRows(t *testing.T) {
	copilot := map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}
	with := func(base map[string]string, kv ...string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	cases := []struct {
		row      string
		env      string
		harness  string
		vars     map[string]string
		verdict  WorkerVerdict
		reasonIn string
	}{
		{"vendor-hosted", "claude-code-self-hosted", "", with(anthropicHosted, WorkerAttestEnv, "claude-code-self-hosted"), VerdictRefused, "Anthropic-hosted"},
		{"not-proven", "warp-self-hosted-worker", "", nil, VerdictRefused, WorkerAttestEnv},
		{"no-harness", "devin-outpost", "", map[string]string{WorkerAttestEnv: "devin-outpost"}, VerdictUnrouted, "no model call leaves the worker"},
		{"not-env-route", "warp-self-hosted-worker", "codex", map[string]string{WorkerAttestEnv: "warp-self-hosted-worker"}, VerdictUnrouted, "config file"},
		{"gate/no credential", "copilot-self-hosted-runner", "", copilot, VerdictUnrouted, "COPILOT_PROVIDER_API_KEY"},
		{"gate/model required", "copilot-self-hosted-runner", "", with(copilot, "COPILOT_PROVIDER_API_KEY", "k"), VerdictUnrouted, "explicit model"},
		{"gate/foreign provider", "copilot-self-hosted-runner", "", with(copilot, "COPILOT_PROVIDER_API_KEY", "k", "COPILOT_MODEL", "m", "COPILOT_PROVIDER_TYPE", "azure"), VerdictUnrouted, "provider type"},
		{"own-endpoint", "warp-self-hosted-worker", "", map[string]string{WorkerAttestEnv: "warp-self-hosted-worker", "ANTHROPIC_BASE_URL": "https://gateway.example"}, VerdictUnrouted, "never overrides"},
		{"route/own proxy already set", "warp-self-hosted-worker", "", map[string]string{WorkerAttestEnv: "warp-self-hosted-worker", "ANTHROPIC_BASE_URL": "http://127.0.0.1:18820"}, VerdictRoute, "ANTHROPIC_BASE_URL="},
		{"route", "copilot-self-hosted-runner", "", with(copilot, "COPILOT_PROVIDER_API_KEY", "k", "COPILOT_MODEL", "m"), VerdictRoute, "COPILOT_PROVIDER_BASE_URL="},
	}
	for _, tc := range cases {
		t.Run(tc.row, func(t *testing.T) {
			p, err := PlanWorker(WorkerRequest{Env: tc.env, Harness: tc.harness, ProxyPort: testPort, LookupEnv: envMap(tc.vars)})
			if err != nil {
				t.Fatal(err)
			}
			if p.Verdict != tc.verdict || !strings.Contains(p.Reason, tc.reasonIn) {
				t.Fatalf("verdict %s %q, want %s containing %q", p.Verdict, p.Reason, tc.verdict, tc.reasonIn)
			}
		})
	}
	// Rows the shipped table cannot reach through a real registry row are
	// checked on a synthetic state: a harness with no route, and one that
	// needs a lane.
	env := WorkerEnvironment{ID: "x", DisplayName: "X", Harnesses: []string{"h"}}
	noRoute := &workerState{req: WorkerRequest{LookupEnv: envMap(nil)}, env: env, plan: &WorkerPlan{Harness: "h"}, proof: &Marker{}}
	if v, why := firstVerdict(noRoute); v != "no-route" {
		t.Fatalf("no route: row %s (%s)", v, why)
	}
	laned := &workerState{
		req: WorkerRequest{LookupEnv: envMap(nil)}, env: env, plan: &WorkerPlan{Harness: "h"}, proof: &Marker{},
		route: &integration.ProxyRoute{EnvVar: "X_BASE_URL", Lane: &integration.ProxyLane{}},
	}
	if v, why := firstVerdict(laned); v != "needs-lane" {
		t.Fatalf("lane: row %s (%s)", v, why)
	}
}

func firstVerdict(s *workerState) (string, string) {
	for _, r := range workerVerdictRules {
		if why, ok := r.match(s); ok {
			return r.name, why
		}
	}
	return "", ""
}

// TestWorkerSinks: the default sink per mode and the refusals.
func TestWorkerSinks(t *testing.T) {
	runner := map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}
	withGH := map[string]string{"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted", "GITHUB_ENV": "/tmp/gh-env"}
	cases := []struct {
		name       string
		env        string
		sink       RouteSink
		background bool
		vars       map[string]string
		want       RouteSink
		errIn      string
	}{
		{"run defaults to child", "copilot-self-hosted-runner", "", false, runner, SinkChild, ""},
		{"start in actions defaults to github-env", "copilot-self-hosted-runner", "", true, withGH, SinkGitHubEnv, ""},
		{"start outside actions falls back to env-file", "copilot-self-hosted-runner", "", true, runner, SinkEnvFile, ""},
		{"start defaults to env-file", "claude-code-self-hosted", "", true, nil, SinkEnvFile, ""},
		{"child needs run", "claude-code-self-hosted", SinkChild, true, nil, "", "needs `worker run`"},
		{"env-file needs start", "claude-code-self-hosted", SinkEnvFile, false, nil, "", "needs `worker start`"},
		{"github-env needs GITHUB_ENV", "copilot-self-hosted-runner", SinkGitHubEnv, true, runner, "", "GITHUB_ENV"},
		{"github-env not offered", "claude-code-self-hosted", SinkGitHubEnv, true, withGH, "", "not available"},
		{"unknown sink", "claude-code-self-hosted", "pipe", true, nil, "", "unknown route sink"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := PlanWorker(WorkerRequest{Env: tc.env, Sink: tc.sink, Background: tc.background, ProxyPort: testPort, LookupEnv: envMap(tc.vars)})
			if tc.errIn != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errIn) {
					t.Fatalf("err %v, want %q", err, tc.errIn)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Sink != tc.want {
				t.Fatalf("sink %s, want %s", p.Sink, tc.want)
			}
		})
	}
}

// TestWorkerRequestErrors: requests the planner cannot evaluate.
func TestWorkerRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		req  WorkerRequest
		in   string
	}{
		{"unknown env", WorkerRequest{Env: "laptop", ProxyPort: testPort}, "unknown worker environment"},
		{"foreign harness", WorkerRequest{Env: "claude-code-self-hosted", Harness: "codex", ProxyPort: testPort}, "not one of"},
		{"harness where none", WorkerRequest{Env: "devin-outpost", Harness: "claude-code", ProxyPort: testPort}, "no routable harness"},
		{"bad port", WorkerRequest{Env: "claude-code-self-hosted", ProxyPort: 0}, "out of range"},
	}
	for _, tc := range cases {
		if _, err := PlanWorker(tc.req); err == nil || !strings.Contains(err.Error(), tc.in) {
			t.Fatalf("%s: err %v, want %q", tc.name, err, tc.in)
		}
	}
}

// TestWorkerTableWellFormed: every row proves customer compute only, names
// a live check, offers the child sink, and every harness is a registry row
// (or the row says why it has none).
func TestWorkerTableWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range workerEnvironments {
		if seen[e.ID] {
			t.Fatalf("duplicate worker environment %s", e.ID)
		}
		seen[e.ID] = true
		if len(e.Proof) == 0 || e.ProofHint == "" || e.LiveCheck == "" || e.Grounding == "" {
			t.Fatalf("%s: proof, hint, grounding and live check are required", e.ID)
		}
		for _, m := range e.Proof {
			if m.Location != ExecutionCustomerWorker {
				t.Fatalf("%s: a proof row resolves to %q", e.ID, m.Location)
			}
		}
		hasChild := false
		for _, s := range e.Sinks {
			if _, ok := sinkFor(s); !ok {
				t.Fatalf("%s: unknown sink %s", e.ID, s)
			}
			hasChild = hasChild || s == SinkChild
		}
		if !hasChild {
			t.Fatalf("%s: every environment must offer `worker run` (the child sink)", e.ID)
		}
		if len(e.Harnesses) == 0 && e.NoHarnessReason == "" {
			t.Fatalf("%s: no harness and no reason", e.ID)
		}
		for _, h := range e.Harnesses {
			if _, ok := integration.For(h); !ok {
				t.Fatalf("%s: harness %s has no integration registry row", e.ID, h)
			}
		}
	}
	for _, r := range hostedRules {
		if r.Marker.Location != ExecutionVendorCloud || r.What == "" || r.Grounding == "" {
			t.Fatalf("hosted rule %+v is malformed", r)
		}
	}
}

// TestWorkerLifecycleOrder: every lifecycle satisfies the order table, and
// the route-off-before-stop rule catches a swapped teardown.
func TestWorkerLifecycleOrder(t *testing.T) {
	for _, mode := range []WorkerMode{ModeRun, ModeStart, ModeStop} {
		steps, err := WorkerSteps(mode)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckWorkerSteps(steps); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	bad := []struct {
		name  string
		steps []WorkerStep
		in    string
	}{
		{"stop before route off", []WorkerStep{StepStopProxy, StepRouteOff}, "route off before stop"},
		{"route before ready", []WorkerStep{StepVerify, StepStartProxy, StepRouteOn, StepAwaitReady}, "does not answer"},
		{"start before verify", []WorkerStep{StepStartProxy, StepVerify}, "refusal"},
		{"stamp before scan", []WorkerStep{StepStamp, StepScan}, "session rows"},
		{"duplicate", []WorkerStep{StepRouteOff, StepRouteOff}, "twice"},
	}
	for _, tc := range bad {
		if err := CheckWorkerSteps(tc.steps); err == nil || !strings.Contains(err.Error(), tc.in) {
			t.Fatalf("%s: err %v, want %q", tc.name, err, tc.in)
		}
	}
	if _, err := WorkerSteps("pause"); err == nil {
		t.Fatal("unknown mode accepted")
	}
	// The stop lifecycle starts with route off.
	if steps, _ := WorkerSteps(ModeStop); steps[0] != StepRouteOff {
		t.Fatalf("stop starts with %s, want route-off", steps[0])
	}
}

// TestRouteLines: the sink renderings and their refusals.
func TestRouteLines(t *testing.T) {
	route := []RouteVar{{Name: "ANTHROPIC_BASE_URL", Value: "http://127.0.0.1:18820"}}
	got, err := RouteOnLines(SinkEnvFile, route)
	if err != nil || got != "export ANTHROPIC_BASE_URL=http://127.0.0.1:18820\n" {
		t.Fatalf("env-file: %q %v", got, err)
	}
	got, err = RouteOnLines(SinkGitHubEnv, route)
	if err != nil || got != "ANTHROPIC_BASE_URL=http://127.0.0.1:18820\n" {
		t.Fatalf("github-env: %q %v", got, err)
	}
	off, err := RouteOffLines(SinkGitHubEnv, route)
	if err != nil || off != "ANTHROPIC_BASE_URL=\n" {
		t.Fatalf("github-env off: %q %v", off, err)
	}
	restored, err := RouteOffLines(SinkGitHubEnv, []RouteVar{{Name: "X_BASE_URL", Value: "v", Previous: "https://prev", HadPrevious: true}})
	if err != nil || restored != "X_BASE_URL=https://prev\n" {
		t.Fatalf("github-env restore: %q %v", restored, err)
	}
	if _, err := RouteOnLines(SinkChild, route); err == nil {
		t.Fatal("child sink rendered lines")
	}
	if _, err := RouteOffLines(SinkEnvFile, route); err == nil {
		t.Fatal("env-file off rendered lines")
	}
	if _, err := RouteOnLines(SinkGitHubEnv, []RouteVar{{Name: "A", Value: "x\nB=y"}}); err == nil {
		t.Fatal("a newline in a value was accepted")
	}
	if _, err := RouteOffLines(SinkGitHubEnv, []RouteVar{{Name: "A", Previous: "x\nB=y", HadPrevious: true}}); err == nil {
		t.Fatal("a newline in a restored value was accepted")
	}
}

// TestAgentMarkersAgreeWithWorkerProof: under any worker proof row's
// variables, no Rail S agent marker table (the hook and flush stamp) says
// vendor_cloud, because the first stamp wins and would contradict the
// worker's customer_worker stamp; and the Anthropic-hosted marker still
// beats the attestation there.
func TestAgentMarkersAgreeWithWorkerProof(t *testing.T) {
	for _, e := range workerEnvironments {
		for _, m := range e.Proof {
			vars := map[string]string{m.Env: m.Equals}
			if m.Equals == "" {
				vars[m.Env] = "1"
			}
			if m.AlsoEnv != "" {
				vars[m.AlsoEnv] = m.AlsoEquals
			}
			for _, a := range agents {
				if !a.Supported() {
					continue
				}
				if d := Detect(a, envMap(vars)); d.InCloud && d.Location != ExecutionCustomerWorker {
					t.Fatalf("%s proof %+v: agent %s stamps %s", e.ID, m, a.ID, d.Location)
				}
			}
		}
	}
	cc, err := AgentByID("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	hosted := map[string]string{WorkerAttestEnv: "claude-code-self-hosted"}
	for k, v := range anthropicHosted {
		hosted[k] = v
	}
	if d := Detect(cc, envMap(hosted)); d.Location != ExecutionVendorCloud {
		t.Fatalf("Anthropic-hosted with an attestation stamps %s, want vendor_cloud", d.Location)
	}
	if d := Detect(cc, envMap(map[string]string{"CLAUDE_CODE_REMOTE": "true"})); d.Location != ExecutionVendorCloud {
		t.Fatalf("a cloud session without the attestation stamps %s, want vendor_cloud", d.Location)
	}
}

// TestWorkerRecoverySteps: every recovery list is teardown only and keeps
// the order rules; a mode whose table ends in teardown needs none.
func TestWorkerRecoverySteps(t *testing.T) {
	for _, mode := range []WorkerMode{ModeRun, ModeStart, ModeStop} {
		rec := WorkerRecoverySteps(mode)
		for _, s := range rec {
			if !IsTeardownStep(s) {
				t.Fatalf("%s recovery runs %s, not a teardown step", mode, s)
			}
		}
		if err := CheckWorkerSteps(rec); err != nil {
			t.Fatalf("%s recovery: %v", mode, err)
		}
	}
	if len(WorkerRecoverySteps(ModeStart)) == 0 {
		t.Fatal("a failed start must take its route off and stop its proxy")
	}
	if len(WorkerRecoverySteps(ModeRun)) != 0 || len(WorkerRecoverySteps(ModeStop)) != 0 {
		t.Fatal("run and stop already end in teardown")
	}
}
