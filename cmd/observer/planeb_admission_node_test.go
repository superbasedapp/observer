package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	policyfamadmission "github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
)

// fakeCodingEngine denies text containing "drop table", asks on "maybe",
// and reports the judge unavailable when the judge errors.
type fakeCodingEngine struct {
	mu    sync.Mutex
	texts []string
}

func (f *fakeCodingEngine) eval(ctx context.Context, text string, spec policyfamadmission.PolicySpec, judge func(context.Context, string) (string, error)) promptadmit.EngineResult {
	f.mu.Lock()
	f.texts = append(f.texts, text)
	f.mu.Unlock()
	if strings.Contains(text, "drop table") {
		return promptadmit.EngineResult{Decision: policyfamadmission.DecisionDeny, Criterion: "c1", Reason: "destructive"}
	}
	if strings.Contains(text, "maybe") {
		return promptadmit.EngineResult{Decision: policyfamadmission.DecisionAsk, Criterion: "c2", Reason: "unclear"}
	}
	if judge != nil {
		if _, err := judge(ctx, "rubric"); err != nil {
			return promptadmit.EngineResult{Decision: policyfamadmission.DecisionAllow, Reason: err.Error(), JudgeUnavailable: true}
		}
	} else if admissionRequiresJudge(spec) {
		return promptadmit.EngineResult{Decision: policyfamadmission.DecisionAllow, Reason: "no judge", JudgeUnavailable: true}
	}
	return promptadmit.EngineResult{Decision: policyfamadmission.DecisionAllow}
}

func admissionRequiresJudge(spec policyfamadmission.PolicySpec) bool {
	return policyfamadmission.RequiresJudge(spec)
}

func mustSpec(t *testing.T, body string) planebadmission.PolicySpec {
	t.Helper()
	spec, _, err := planebadmission.CompileBody([]byte(body), 0)
	if err != nil {
		t.Fatalf("compile %s: %v", body, err)
	}
	return spec
}

func promptBody(t *testing.T, msgs ...any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"model": "m", "messages": msgs})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPlaneBNodeLaneRows is one row per posture x scope x verdict x strict
// case of the node lane (P-228).
func TestPlaneBNodeLaneRows(t *testing.T) {
	type m = map[string]any
	const det = `"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}}`
	const detObserve = `"admission":{"mode":"observe","prefilter":{"deny":["zzz"]}}`
	judged := func(strict bool) string {
		s := `"admission":{"mode":"enforce"`
		if strict {
			s += `,"strict":true`
		}
		return s + `,"criteria":[{"id":"j","type":"custom","definition":"bad"}]},"judge_upstream_id":"up"`
	}
	prompt := func(text string) []any { return []any{m{"role": "user", "content": text}} }
	loop := []any{
		m{"role": "user", "content": "please drop table users"},
		m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t", "name": "Bash", "input": m{}}}},
		m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t", "content": "drop table done"}}},
	}
	cases := []struct {
		name           string
		body           string
		managed        bool
		enforceAllowed bool
		judgeErr       error
		noJudge        bool
		msgs           []any
		wantAction     promptadmit.Action
		wantTexts      []string
		wantAudit      bool
	}{
		{name: "individual node: off, not even observed", body: "{" + det + `,"node_lane":true}`, msgs: prompt("please drop table users"), wantAction: promptadmit.ActionAllow},
		{name: "managed, node_lane off: off", body: "{" + det + "}", managed: true, enforceAllowed: true, msgs: prompt("please drop table users"), wantAction: promptadmit.ActionAllow},
		{name: "managed enforce deny refuses", body: "{" + det + `,"node_lane":true}`, managed: true, enforceAllowed: true, msgs: prompt("please drop table users"), wantAction: promptadmit.ActionBlock, wantTexts: []string{"please drop table users"}, wantAudit: true},
		{name: "enforce not preauthorized: deny only flags", body: "{" + det + `,"node_lane":true}`, managed: true, msgs: prompt("please drop table users"), wantAction: promptadmit.ActionFlag, wantTexts: []string{"please drop table users"}, wantAudit: true},
		{name: "managed observe deny flags", body: "{" + detObserve + `,"node_lane":true}`, managed: true, enforceAllowed: true, msgs: prompt("please drop table users"), wantAction: promptadmit.ActionFlag, wantTexts: []string{"please drop table users"}, wantAudit: true},
		{name: "enforce ask refuses", body: "{" + det + `,"node_lane":true}`, managed: true, enforceAllowed: true, msgs: prompt("maybe do it"), wantAction: promptadmit.ActionBlock, wantTexts: []string{"maybe do it"}, wantAudit: true},
		{name: "user_prompts judges an uncached loop's opening prompt", body: "{" + det + `,"node_lane":true}`, managed: true, enforceAllowed: true, msgs: loop, wantAction: promptadmit.ActionBlock, wantTexts: []string{"please drop table users"}, wantAudit: true},
		{name: "user_prompts skips a loop with no typed prompt", body: "{" + det + `,"node_lane":true}`, managed: true, enforceAllowed: true, msgs: loop[2:], wantAction: promptadmit.ActionAllow},
		{name: "all_calls judges the tool results", body: "{" + det + `,"node_lane":true,"scope":"all_calls"}`, managed: true, enforceAllowed: true, msgs: loop, wantAction: promptadmit.ActionBlock, wantTexts: []string{"drop table done"}, wantAudit: true},
		{name: "clean prompt allows, no audit", body: "{" + det + `,"node_lane":true}`, managed: true, enforceAllowed: true, msgs: prompt("add a test"), wantAction: promptadmit.ActionAllow, wantTexts: []string{"add a test"}},
		{name: "judge error, not strict: allow flagged", body: "{" + judged(false) + `,"node_lane":true}`, managed: true, enforceAllowed: true, judgeErr: errors.New("timeout"), msgs: prompt("add a test"), wantAction: promptadmit.ActionFlag, wantTexts: []string{"add a test"}, wantAudit: true},
		{name: "judge error, strict: refuses", body: "{" + judged(true) + `,"node_lane":true}`, managed: true, enforceAllowed: true, judgeErr: errors.New("timeout"), msgs: prompt("add a test"), wantAction: promptadmit.ActionBlock, wantTexts: []string{"add a test"}, wantAudit: true},
		{name: "no relay, strict: refuses", body: "{" + judged(true) + `,"node_lane":true}`, managed: true, enforceAllowed: true, noJudge: true, msgs: prompt("add a test"), wantAction: promptadmit.ActionBlock, wantTexts: []string{"add a test"}, wantAudit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lane := newPlaneBNodeLane()
			eng := &fakeCodingEngine{}
			lane.engine = eng.eval
			if !tc.noJudge {
				lane.judge = func(context.Context, string) (string, error) { return "ok", tc.judgeErr }
			}
			managed := tc.managed
			lane.managedFn = func() bool { return managed }
			var mu sync.Mutex
			var rows []guard.ActionVerdict
			done := make(chan struct{}, 1)
			lane.persist = func(_ context.Context, vs []guard.ActionVerdict) error {
				mu.Lock()
				rows = append(rows, vs...)
				mu.Unlock()
				done <- struct{}{}
				return nil
			}
			lane.publish(orgclient.PolicyResourceResult{Version: 3, BodyHash: "h", EnforceAllowed: tc.enforceAllowed, Spec: mustSpec(t, tc.body)}, nil)
			o := lane.admit(context.Background(), planeBPromptInput{Provider: "anthropic", Body: promptBody(t, tc.msgs...), SessionID: "s1", Tool: "claude-code"})
			if o.Action != tc.wantAction {
				t.Fatalf("action = %s (%+v), want %s", o.Action, o, tc.wantAction)
			}
			if strings.Join(eng.texts, "|") != strings.Join(tc.wantTexts, "|") {
				t.Fatalf("engine judged %q, want %q", eng.texts, tc.wantTexts)
			}
			if tc.wantAudit {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("no audit row recorded")
				}
				mu.Lock()
				defer mu.Unlock()
				v := rows[0]
				if v.Verdict.RuleID != planeBPromptJudgeRuleID || v.Kind != policy.KindUserPrompt || v.Verdict.Source != policy.SourceOrg {
					t.Fatalf("audit row = %+v", v)
				}
				if v.Enforced != (tc.wantAction == promptadmit.ActionBlock) {
					t.Fatalf("enforced = %v for action %s", v.Enforced, tc.wantAction)
				}
				for _, text := range tc.wantTexts {
					if strings.Contains(v.Verdict.Reason, text) || strings.Contains(v.Input.Target, text) {
						t.Fatalf("audit row carries prompt text: %+v", v)
					}
				}
				if !strings.HasPrefix(v.Input.Target, "prompt sha256:") {
					t.Fatalf("target = %q, want a digest", v.Input.Target)
				}
			} else {
				select {
				case <-done:
					t.Fatal("unexpected audit row")
				case <-time.After(50 * time.Millisecond):
				}
			}
		})
	}
}

// TestPlaneBNodeLaneCacheAndPostures pins the verdict cache (one engine call
// per prompt and policy version), a clear, and a build without the engine.
func TestPlaneBNodeLaneCacheAndPostures(t *testing.T) {
	type m = map[string]any
	lane := newPlaneBNodeLane()
	eng := &fakeCodingEngine{}
	lane.engine = eng.eval
	lane.managedFn = func() bool { return true }
	body := `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true}`
	lane.publish(orgclient.PolicyResourceResult{Version: 1, BodyHash: "a", EnforceAllowed: true, Spec: mustSpec(t, body)}, nil)
	in := planeBPromptInput{Provider: "openai", Body: promptBody(t, m{"role": "user", "content": "please drop table users"})}
	for i := 0; i < 3; i++ {
		if o := lane.admit(context.Background(), in); o.Action != promptadmit.ActionBlock {
			t.Fatalf("call %d: %+v", i, o)
		}
	}
	if len(eng.texts) != 1 {
		t.Fatalf("engine called %d times for one prompt, want 1", len(eng.texts))
	}
	lane.publish(orgclient.PolicyResourceResult{Version: 2, BodyHash: "b", EnforceAllowed: true, Spec: mustSpec(t, body)}, nil)
	_ = lane.admit(context.Background(), in)
	if len(eng.texts) != 2 {
		t.Fatalf("a new policy version must judge again; calls=%d", len(eng.texts))
	}
	lane.clear()
	if o := lane.admit(context.Background(), in); o.Action != promptadmit.ActionAllow {
		t.Fatalf("cleared lane: %+v", o)
	}
	// F7: a build without the engine never admits silently.
	noEngineRows := []struct {
		name           string
		body           string
		enforceAllowed bool
		want           promptadmit.Action
	}{
		{"enforce non-strict flags", body, true, promptadmit.ActionFlag},
		{"enforce strict refuses", `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["zzz"]}},"node_lane":true}`, true, promptadmit.ActionBlock},
		{"strict but enforce not preauthorized flags", `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["zzz"]}},"node_lane":true}`, false, promptadmit.ActionFlag},
		{"observe flags", `{"admission":{"mode":"observe","prefilter":{"deny":["zzz"]}},"node_lane":true}`, true, promptadmit.ActionFlag},
	}
	for _, r := range noEngineRows {
		noEngine := newPlaneBNodeLane()
		noEngine.managedFn = func() bool { return true }
		noEngine.publish(orgclient.PolicyResourceResult{Version: 1, EnforceAllowed: r.enforceAllowed, Spec: mustSpec(t, r.body)}, nil)
		if o := noEngine.admit(context.Background(), in); o.Action != r.want || o.Basis != promptadmit.BasisEngineMissing {
			t.Fatalf("no engine, %s: %+v, want %s", r.name, o, r.want)
		}
	}
}

// TestPlaneBNodeLaneManagedGate pins the authority gate: a nil governance
// handle (individual node, not enrolled) never lifts the node lane.
func TestPlaneBNodeLaneManagedGate(t *testing.T) {
	if managedEnforceFor(nil, policyfam.FamilyPlaneBAdmission) {
		t.Fatal("managedEnforceFor(nil, planeb.admission) = true; an individual node must never run the node lane")
	}
	lane := newPlaneBNodeLane()
	if lane.managedNow() {
		t.Fatal("a lane with no governance handle must not be managed")
	}
}

// TestPlaneBNodeCapability pins the capability token: advertised only when
// the engine and the org relay judge are both bound.
func TestPlaneBNodeCapability(t *testing.T) {
	lane := newPlaneBNodeLane()
	if lane.judgeAvailable() {
		t.Fatal("an unconfigured lane must not advertise the judge")
	}
	lane.engine = (&fakeCodingEngine{}).eval
	if lane.judgeAvailable() {
		t.Fatal("no relay: must not advertise the judge")
	}
	lane.judge = func(context.Context, string) (string, error) { return "", nil }
	if !lane.judgeAvailable() {
		t.Fatal("engine and relay bound: must advertise the judge")
	}
	lane.configure(nil, nil, nil)
	if lane.judgeAvailable() {
		t.Fatal("configure with no relay must unbind the judge")
	}
}

// TestPublishPolicyResourceResultPlaneBAdmission pins the dispatch: an
// installed planeb.admission result lands on the process lane, a signed
// withdrawal clears it, and an identity mismatch installs nothing.
func TestPublishPolicyResourceResultPlaneBAdmission(t *testing.T) {
	prev := processPlaneBLane
	processPlaneBLane = newPlaneBNodeLane()
	t.Cleanup(func() { processPlaneBLane = prev })
	spec := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`)
	res := orgclient.PolicyResourceResult{Status: orgclient.PRApplied, OrgKey: "k", Generation: 1, Version: 4, Spec: spec}
	deny := orgIdentityGate(func(string, int64) bool { return false })
	allow := orgIdentityGate(func(string, int64) bool { return true })
	if publishPolicyResourceResult(deny, nil, nil, nil, nil, policyfam.FamilyPlaneBAdmission, res, nil) || processPlaneBLane.policy != nil {
		t.Fatal("identity mismatch must install nothing")
	}
	if !publishPolicyResourceResult(allow, nil, nil, nil, nil, policyfam.FamilyPlaneBAdmission, res, nil) {
		t.Fatal("install reported false")
	}
	if p := processPlaneBLane.policy; p == nil || p.version != 4 || !p.spec.NodeLane {
		t.Fatalf("installed policy = %+v", p)
	}
	withdrawn := orgclient.PolicyResourceResult{Status: orgclient.PRWithdrawn, OrgKey: "k", Generation: 1}
	publishPolicyResourceResult(allow, nil, nil, nil, nil, policyfam.FamilyPlaneBAdmission, withdrawn, nil)
	if processPlaneBLane.policy != nil {
		t.Fatal("a signed withdrawal must clear the node lane policy")
	}
}

// TestNodeLaneJudgeBudgetFromSignedBytes pins F1 (fix round 1) on the node:
// the spec the node holds is compiled from the org server's signed canonical
// bytes, and a body with no latency_budget_ms must give the relay default.
func TestNodeLaneJudgeBudgetFromSignedBytes(t *testing.T) {
	det := `"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true`
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"absent budget: relay default", "{" + det + "}", nodeLaneRelayDefaultBudget},
		{"explicit budget kept", "{" + det + `,"latency_budget_ms":2500}`, 2500 * time.Millisecond},
	}
	for _, tc := range cases {
		_, signed, err := planebadmission.CompileBody([]byte(tc.raw), 0)
		if err != nil {
			t.Fatal(err)
		}
		if got := nodeLaneJudgeBudget(mustSpec(t, string(signed))); got != tc.want {
			t.Errorf("%s: budget %v, want %v (signed %s)", tc.name, got, tc.want, signed)
		}
	}
}

// TestPlaneBNodeLaneLoopReusesTheOpeningVerdict pins F3 on the node: a real
// tool loop's continuations reuse the verdict of the prompt that opened it.
func TestPlaneBNodeLaneLoopReusesTheOpeningVerdict(t *testing.T) {
	type m = map[string]any
	lane := newPlaneBNodeLane()
	eng := &fakeCodingEngine{}
	lane.engine = eng.eval
	lane.managedFn = func() bool { return true }
	lane.publish(orgclient.PolicyResourceResult{
		Version: 1, BodyHash: "a", EnforceAllowed: true,
		Spec: mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true}`),
	}, nil)
	opening := []any{m{"role": "user", "content": "refactor the parser"}}
	loop := append(append([]any{}, opening...),
		m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t", "name": "Bash", "input": m{}}}},
		m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t", "content": "ok"}}})
	for _, msgs := range [][]any{opening, loop, loop} {
		if o := lane.admit(context.Background(), planeBPromptInput{Provider: "anthropic", Body: promptBody(t, msgs...)}); o.Action != promptadmit.ActionAllow {
			t.Fatalf("refused: %+v", o)
		}
	}
	if len(eng.texts) != 1 {
		t.Fatalf("engine judged %q, want the opening prompt once", eng.texts)
	}
}

// TestPlaneBNodeLaneAuditsACachedVerdictOnce pins F6 on the node: the same
// refused prompt sent again is refused from the cache and recorded once.
func TestPlaneBNodeLaneAuditsACachedVerdictOnce(t *testing.T) {
	type m = map[string]any
	lane := newPlaneBNodeLane()
	lane.engine = (&fakeCodingEngine{}).eval
	lane.managedFn = func() bool { return true }
	var mu sync.Mutex
	rows := 0
	lane.persist = func(context.Context, []guard.ActionVerdict) error {
		mu.Lock()
		rows++
		mu.Unlock()
		return nil
	}
	lane.publish(orgclient.PolicyResourceResult{
		Version: 1, BodyHash: "a", EnforceAllowed: true,
		Spec: mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true}`),
	}, nil)
	in := planeBPromptInput{Provider: "anthropic", Body: promptBody(t, m{"role": "user", "content": "please drop table users"})}
	for i := 0; i < 4; i++ {
		if o := lane.admit(context.Background(), in); o.Action != promptadmit.ActionBlock {
			t.Fatalf("call %d: %+v", i, o)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := rows
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if rows != 1 {
		t.Fatalf("audit rows = %d for one repeated refusal, want 1", rows)
	}
}

// TestPromptJudgeStatusLine pins F8: `observer org status` tells a managed
// developer whose grant holds enforce.admission that the organization's judge
// may read their coding-agent prompts, and says nothing elsewhere.
func TestPromptJudgeStatusLine(t *testing.T) {
	accepted := config.OrgClientPolicyConfig{AcceptFamilies: []string{"admission.input", "planeb.admission"}}
	notAccepted := config.OrgClientPolicyConfig{AcceptFamilies: []string{"admission.input"}}
	withAdm := []string{govern.AuthorityEnforceAdmission}
	cases := []struct {
		name      string
		managed   bool
		authority []string
		policy    config.OrgClientPolicyConfig
		want      string
	}{
		{"individual node: silent", false, withAdm, accepted, ""},
		{"managed without enforce.admission: silent", true, []string{govern.AuthorityFeatureLock}, accepted, ""},
		{"managed, accepted: judge may read prompts", true, withAdm, accepted, "may let the organization's LLM judge read the prompts you type"},
		{"managed, not accepted: does not run here", true, withAdm, notAccepted, "does not accept planeb.admission"},
	}
	for _, tc := range cases {
		got := promptJudgeStatusLine(tc.managed, tc.authority, tc.policy)
		if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q, want containing %q", tc.name, got, tc.want)
		}
	}
}

// TestManagedFamilyNotices pins F8 at daemon start: a backfilled
// planeb.admission is explained to the developer, other families are not
// given invented text.
func TestManagedFamilyNotices(t *testing.T) {
	got := managedFamilyNotices([]string{"node.features", "planeb.admission"})
	if len(got) != 1 || !strings.Contains(got[0], "read the prompts you type") {
		t.Fatalf("notices = %q", got)
	}
	if n := managedFamilyNotices([]string{"admission.input"}); len(n) != 0 {
		t.Fatalf("unexpected notice %q", n)
	}
}

// TestPlaneBNodeLaneActive pins F4: the proxy's cheap pre-check is false
// with no policy, a node_lane-off body or a mode-off body.
func TestPlaneBNodeLaneActive(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"no policy", "", false},
		{"node_lane off", `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}}}`, false},
		{"mode off", `{"admission":{"mode":"off"},"node_lane":true}`, false},
		{"node_lane on", `{"admission":{"mode":"observe","prefilter":{"deny":["x"]}},"node_lane":true}`, true},
	}
	for _, tc := range cases {
		lane := newPlaneBNodeLane()
		if tc.body != "" {
			lane.publish(orgclient.PolicyResourceResult{Version: 1, Spec: mustSpec(t, tc.body)}, nil)
		}
		if got := lane.active(); got != tc.want {
			t.Errorf("%s: active = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPlaneBGuardStatusLines is one row per posture of the `observer guard
// status` prompt judge line (P-228 design P1b, fix round 1).
func TestPlaneBGuardStatusLines(t *testing.T) {
	det := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`)
	judged := mustSpec(t, `{"admission":{"mode":"enforce","strict":true,"criteria":[{"id":"c","type":"custom","definition":"d"}]},"judge_upstream_id":"u","node_lane":true,"scope":"all_calls"}`)
	gatewayOnly := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}}}`)
	on := planeBStatusFacts{Managed: true, HoldsEnforce: true, Accepted: true, HavePolicy: true, Version: 4, Spec: det, EngineLinked: true}
	with := func(mut func(*planeBStatusFacts)) planeBStatusFacts { f := on; mut(&f); return f }
	cases := []struct {
		name string
		f    planeBStatusFacts
		want []string
	}{
		{"individual node", planeBStatusFacts{}, []string{"off (not a managed node"}},
		{"no enforce.admission", with(func(f *planeBStatusFacts) { f.HoldsEnforce = false }), []string{"does not hold enforce.admission"}},
		{"family not accepted", with(func(f *planeBStatusFacts) { f.Accepted = false }), []string{"not in [org_client.policy] accept_families"}},
		{"unreadable cache", with(func(f *planeBStatusFacts) { f.HavePolicy, f.PolicyProblem = false, "bad signature" }), []string{"cannot be read: bad signature"}},
		{"no policy yet", with(func(f *planeBStatusFacts) { f.HavePolicy = false }), []string{"no organization policy received yet"}},
		{"gateway only", with(func(f *planeBStatusFacts) { f.Spec = gatewayOnly }), []string{"AI gateway only"}},
		{"on, deterministic", on, []string{"on (policy v4, scope user_prompts, node_lane on, mode enforce, strict false)", "deterministic layers only"}},
		{"on, judged", with(func(f *planeBStatusFacts) { f.Spec = judged }), []string{"scope all_calls", "strict true", "purpose coding_admission"}},
		{"on, engine missing", with(func(f *planeBStatusFacts) { f.EngineLinked = false }), []string{"no admission engine"}},
		{"counts", with(func(f *planeBStatusFacts) { f.Counts = map[string]int{"flag": 3, "deny": 1} }), []string{"Prompt judge (24h): deny=1 flag=3"}},
		{"on: hook lane ignores local guard switches, fails open", on, []string{"every prompt-gate hook asks it, whatever the local [guard]", "the prompt goes through"}},
		{"on: strict enforced preauthorized fails closed", with(func(f *planeBStatusFacts) { f.Spec = judged; f.Preauthorized = true }), []string{"the prompt is refused (strict, enforced)"}},
	}
	for _, tc := range cases {
		got := strings.Join(planeBGuardStatusLines(tc.f), "\n")
		for _, w := range tc.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: lines %q lack %q", tc.name, got, w)
			}
		}
	}
}

// TestPlaneBNodeLaneOutageCostsOneJudgeBudgetPerWindow pins N1 (fix round 2):
// during a relay outage, a tool loop under a non-strict policy does not wait
// the judge budget on every model call nor write a row per call: the
// judge-unavailable outcome is reused for the negative window and recorded
// once.
func TestPlaneBNodeLaneOutageCostsOneJudgeBudgetPerWindow(t *testing.T) {
	type m = map[string]any
	lane := newPlaneBNodeLane()
	now := time.Unix(1000, 0)
	lane.now = func() time.Time { return now }
	lane.cache = promptadmit.NewCache(0, 0, func() time.Time { return now })
	eng := &fakeCodingEngine{}
	lane.engine = eng.eval
	lane.judge = func(context.Context, string) (string, error) { return "", errors.New("relay down") }
	lane.managedFn = func() bool { return true }
	var mu sync.Mutex
	rows := 0
	lane.persist = func(context.Context, []guard.ActionVerdict) error {
		mu.Lock()
		rows++
		mu.Unlock()
		return nil
	}
	lane.publish(orgclient.PolicyResourceResult{
		Version: 1, BodyHash: "a", EnforceAllowed: true,
		Spec: mustSpec(t, `{"admission":{"mode":"enforce","criteria":[{"id":"j","type":"custom","definition":"bad"}]},"judge_upstream_id":"up","node_lane":true}`),
	}, nil)
	loop := promptBody(t,
		m{"role": "user", "content": "refactor the parser"},
		m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t", "name": "Bash", "input": m{}}}},
		m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t", "content": "ok"}}})
	for i := 0; i < 5; i++ {
		if o := lane.admit(context.Background(), planeBPromptInput{Provider: "anthropic", Body: loop}); o.Action != promptadmit.ActionFlag {
			t.Fatalf("call %d: %+v, want a flag (non-strict outage)", i, o)
		}
	}
	if len(eng.texts) != 1 {
		t.Fatalf("engine called %d times in one negative window, want 1", len(eng.texts))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := rows
		mu.Unlock()
		if n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	if rows != 1 {
		mu.Unlock()
		t.Fatalf("audit rows = %d in one negative window, want 1", rows)
	}
	mu.Unlock()
	now = now.Add(promptadmit.DefaultNegativeTTL + time.Second)
	_ = lane.admit(context.Background(), planeBPromptInput{Provider: "anthropic", Body: loop})
	if len(eng.texts) != 2 {
		t.Fatalf("after the window the judge must be asked again; calls=%d", len(eng.texts))
	}
}

// TestPlaneBNodeLaneUnknownShapeIsNeverSilent pins N3 on the node: a provider
// lane the classifier has no wire shape for is flagged, or refused under a
// strict enforce policy.
func TestPlaneBNodeLaneUnknownShapeIsNeverSilent(t *testing.T) {
	type m = map[string]any
	cases := []struct {
		name string
		body string
		want promptadmit.Action
	}{
		{"non-strict flags", `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true}`, promptadmit.ActionFlag},
		{"strict refuses", `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["zzz"]}},"node_lane":true}`, promptadmit.ActionBlock},
	}
	for _, tc := range cases {
		lane := newPlaneBNodeLane()
		lane.engine = (&fakeCodingEngine{}).eval
		lane.managedFn = func() bool { return true }
		lane.publish(orgclient.PolicyResourceResult{Version: 1, EnforceAllowed: true, Spec: mustSpec(t, tc.body)}, nil)
		o := lane.admit(context.Background(), planeBPromptInput{Provider: "a-future-provider", Body: promptBody(t, m{"role": "user", "content": "hi"})})
		if o.Action != tc.want || o.Basis != promptadmit.BasisUnknownShape {
			t.Errorf("%s: %+v, want %s", tc.name, o, tc.want)
		}
	}
}

// TestPlaneBNodeCapabilityNACKsWhatTheBuildCannotHonour pins N5 (fix round
// 2): the tokens the org server requires of a body (RequiredNodeCapabilities)
// are matched against what this node advertises through the existing subset
// check, so a build without the engine refuses (NACKs) a strict or judged
// node_lane body instead of accepting it and refusing every prompt.
func TestPlaneBNodeCapabilityNACKsWhatTheBuildCannotHonour(t *testing.T) {
	strictDet := mustSpec(t, `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["x"]}},"node_lane":true}`)
	judged := mustSpec(t, `{"admission":{"mode":"enforce","criteria":[{"id":"c","type":"custom","definition":"d"}]},"judge_upstream_id":"u","node_lane":true}`)
	plainDet := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`)
	engine := (&fakeCodingEngine{}).eval
	relay := func(context.Context, string) (string, error) { return "", nil }
	cases := []struct {
		name       string
		withEngine bool
		withJudge  bool
		spec       planebadmission.PolicySpec
		wantAccept bool
	}{
		{"no engine, strict deterministic: NACK", false, false, strictDet, false},
		{"no engine, judged: NACK", false, false, judged, false},
		{"no engine, plain deterministic: accepted (flags, F7)", false, false, plainDet, true},
		{"engine, strict deterministic: accepted", true, false, strictDet, true},
		{"engine without relay, judged: NACK", true, false, judged, false},
		{"engine and relay, judged: accepted", true, true, judged, true},
	}
	for _, tc := range cases {
		lane := newPlaneBNodeLane()
		if tc.withEngine {
			lane.engine = engine
		}
		if tc.withJudge {
			lane.judge = relay
		}
		got := capabilitiesSubsetLKG(planebadmission.RequiredNodeCapabilities(tc.spec), lane.liveCapabilities())
		if got != tc.wantAccept {
			t.Errorf("%s: accepted=%v, want %v (live %v)", tc.name, got, tc.wantAccept, lane.liveCapabilities())
		}
	}
}
