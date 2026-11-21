package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/promptjudgeipc"
)

// TestHookOrgPromptJudgeRows is one row per capability x posture x answer x
// failure case of the hook-process judge (lane adm-2).
func TestHookOrgPromptJudgeRows(t *testing.T) {
	promptGate := hookFailurePlan{Tool: "cursor", Event: "beforeSubmitPrompt", Cap: integration.HookCapPromptGate, HostTimeout: 30 * time.Second}
	toolGate := promptGate
	toolGate.Cap = integration.HookCapToolGate
	block := promptjudgeipc.Answer{Active: true, Action: "block", Basis: "deny", Reason: "off-topic"}
	cases := []struct {
		name                 string
		plan                 hookFailurePlan
		active, failClosed   bool
		answer               promptjudgeipc.Answer
		askErr               error
		wantAsked, wantBlock bool
		wantReason           string
		wantSpool            string
	}{
		{name: "not a prompt-gate binding: never asks", plan: toolGate, active: true, answer: block},
		{name: "judge inactive (individual node): never asks", plan: promptGate, answer: block},
		{name: "active, refused", plan: promptGate, active: true, answer: block, wantAsked: true, wantBlock: true, wantReason: promptJudgeRefusedPrefix + "off-topic"},
		{name: "active, allowed", plan: promptGate, active: true, answer: promptjudgeipc.Answer{Active: true, Action: "allow"}, wantAsked: true},
		{name: "active, flagged: goes through", plan: promptGate, active: true, answer: promptjudgeipc.Answer{Active: true, Action: "flag", Reason: "r"}, wantAsked: true},
		{name: "daemon says inactive (policy changed): goes through", plan: promptGate, active: true, answer: promptjudgeipc.Answer{}, wantAsked: true},
		{name: "unreachable, strict enforced: refused and spooled", plan: promptGate, active: true, failClosed: true, askErr: errors.New("connection refused"), wantAsked: true, wantBlock: true, wantReason: promptJudgeUnreachableReason, wantSpool: guardposture.OutcomeFailClosed},
		{name: "unreachable, not strict: goes through and spooled", plan: promptGate, active: true, askErr: errors.New("timeout"), wantAsked: true, wantSpool: guardposture.OutcomeFailOpen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			asked := false
			var gotBudget time.Duration
			spooled := ""
			d := promptJudgeDeps{
				posture: func() (bool, bool) { return tc.active, tc.failClosed },
				ask: func(_ context.Context, req promptjudgeipc.Request) (promptjudgeipc.Answer, error) {
					asked = true
					gotBudget = req.Budget
					if req.Prompt != "ship it" || req.SessionID != "s1" || req.Tool != "cursor" {
						t.Fatalf("request = %+v", req)
					}
					return tc.answer, tc.askErr
				},
				spool: func(_ hookFailurePlan, sid, outcome string) {
					if sid != "s1" {
						t.Fatalf("spool session %q", sid)
					}
					spooled = outcome
				},
			}
			got := hookOrgPromptJudge(tc.plan, hook.OrgPromptQuery{Tool: "cursor", SessionID: "s1", Prompt: "ship it"}, d)
			if asked != tc.wantAsked || got.Block != tc.wantBlock || got.Reason != tc.wantReason || spooled != tc.wantSpool {
				t.Fatalf("judgement=%+v asked=%v spooled=%q; want block=%v reason=%q asked=%v spool=%q", got, asked, spooled, tc.wantBlock, tc.wantReason, tc.wantAsked, tc.wantSpool)
			}
			if asked && (gotBudget <= 0 || gotBudget > promptjudgeipc.MaxBudget) {
				t.Fatalf("ask budget %v outside (0, %v]", gotBudget, promptjudgeipc.MaxBudget)
			}
			if got.Block && !strings.Contains(got.Reason, "organization") {
				t.Fatalf("a refusal must say it is the organization's: %q", got.Reason)
			}
		})
	}
}

// TestPromptJudgeAskBudget pins M2 (adm-2 fixes-1): the ask's wait comes
// from what is left on the invocation's watchdog, never from the host timeout
// alone, so time already spent in the invocation shortens it.
func TestPromptJudgeAskBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := []struct {
		name string
		plan hookFailurePlan
		want time.Duration
	}{
		{"watchdog with 28 s left: capped at MaxBudget", hookFailurePlan{Deadline: now.Add(28 * time.Second), HostTimeout: 30 * time.Second}, promptjudgeipc.MaxBudget},
		{"watchdog with 6 s left: 5 s, whatever the host timeout", hookFailurePlan{Deadline: now.Add(6 * time.Second), HostTimeout: 60 * time.Second}, 5 * time.Second},
		{"watchdog with 800 ms left: half of it", hookFailurePlan{Deadline: now.Add(800 * time.Millisecond)}, 400 * time.Millisecond},
		{"watchdog already due: fails at once", hookFailurePlan{Deadline: now.Add(-time.Second)}, time.Millisecond},
		{"no watchdog, no host timeout", hookFailurePlan{}, promptjudgeipc.MaxBudget},
		{"no watchdog, host 10 s", hookFailurePlan{HostTimeout: 10 * time.Second}, 7 * time.Second},
		{"no watchdog, host 2 s", hookFailurePlan{HostTimeout: 2 * time.Second}, 2 * time.Second / 3},
	}
	for _, tc := range cases {
		if got := promptJudgeAskBudget(tc.plan, now); got != tc.want {
			t.Errorf("%s: budget %v, want %v", tc.name, got, tc.want)
		}
		if !tc.plan.Deadline.IsZero() && tc.plan.Deadline.After(now) && !now.Add(promptJudgeAskBudget(tc.plan, now)).Before(tc.plan.Deadline) {
			t.Errorf("%s: the ask must end before the watchdog fires", tc.name)
		}
	}
}

// TestStrictPromptJudgeClosesThePromptGatesFailurePlan pins M2 (adm-2
// fixes-1) with the interim rule of fixes-2 N4 and lows L2: a strict,
// enforced org prompt judge closes a prompt gate's own failure plan. The
// FINAL plan follows the signed posture or, with none, the verified
// durable-state derivation (the fallback seam here); the INTERIM plan follows
// only the daemon's own signed answer, fresh or stale, never a cached body,
// so an individual node and a stale body under another org key are never
// closed by it.
func TestStrictPromptJudgeClosesThePromptGatesFailurePlan(t *testing.T) {
	prev := hookPromptJudgeFallbackFn
	t.Cleanup(func() { hookPromptJudgeFallbackFn = prev })
	const strictBody = `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["x"]}},"node_lane":true}`
	const lenientBody = `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`
	strictPosture := guardposture.Posture{Source: guardposture.SourceOrg, PromptJudgeActive: true, PromptJudgeFailClosed: true}
	stalePosture := strictPosture
	stalePosture.WrittenAt = time.Now().Add(-time.Hour)
	cases := []struct {
		name        string
		posture     *guardposture.Posture
		accept      bool   // planeb.admission accepted
		preauth     bool   // and preauthorized for enforce
		cached      string // a cached body ("" = none)
		orgKey      string // the cache directory's org key
		fallback    bool   // the verified durable-state derivation's answer
		c           integration.HookCap
		wantInterim bool
		wantFinal   bool
	}{
		{"strict judge, fresh posture, prompt gate: closed", &strictPosture, false, false, "", "", false, integration.HookCapPromptGate, true, true},
		{"strict judge, fresh posture, tool gate: unchanged", &strictPosture, false, false, "", "", false, integration.HookCapToolGate, false, false},
		{"non-strict judge, fresh posture: unchanged", &guardposture.Posture{Source: guardposture.SourceOrg, PromptJudgeActive: true}, false, false, "", "", false, integration.HookCapPromptGate, false, false},
		{"strict judge, stale posture (daemon stopped): interim keeps the signed answer", &stalePosture, true, true, strictBody, "current", true, integration.HookCapPromptGate, true, true},
		{"individual node, accepted and preauthorized, strict body cached: never closed (L2)", nil, true, true, strictBody, "current", false, integration.HookCapPromptGate, false, false},
		{"stale strict body under another org key: never closed (L2)", nil, true, true, strictBody, "an-old-org", false, integration.HookCapPromptGate, false, false},
		{"no posture, current strict body: the verified derivation closes the final plan", nil, true, true, strictBody, "current", true, integration.HookCapPromptGate, false, true},
		{"no posture, non-strict body: open", nil, true, true, lenientBody, "current", false, integration.HookCapPromptGate, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "observer.db")
			cfgBody := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n[guard]\nenabled = false\n\n[guard.rules]\norg_bundle = " +
				strconv.Quote(filepath.ToSlash(filepath.Join(dir, "org-policy-bundle.json"))) + "\n"
			if tc.accept {
				cfgBody += "\n[org_client.policy]\naccept_families = [\"" + policyfam.FamilyPlaneBAdmission + "\"]\n"
				if tc.preauth {
					cfgBody += "preauthorize_enforce = [\"" + policyfam.FamilyPlaneBAdmission + "\"]\n"
				}
			}
			cp := filepath.Join(dir, "config.toml")
			writeFileT(t, cp, cfgBody)
			if tc.cached != "" {
				cfg, err := config.Load(config.LoadOptions{GlobalPath: cp})
				if err != nil {
					t.Fatal(err)
				}
				envelope, err := json.Marshal(orgcontract.SignedPolicyResource{Family: policyfam.FamilyPlaneBAdmission, Body: tc.cached})
				if err != nil {
					t.Fatal(err)
				}
				body := filepath.Join(policyResourceCacheDir(cfg), tc.orgKey, "1", policyfam.FamilyPlaneBAdmission+".json")
				if err := os.MkdirAll(filepath.Dir(body), 0o700); err != nil {
					t.Fatal(err)
				}
				writeFileT(t, body, string(envelope))
			}
			if err := os.Chtimes(cp, time.Now().Add(-2*time.Hour), time.Now().Add(-2*time.Hour)); err != nil {
				t.Fatal(err)
			}
			if tc.posture != nil {
				writePosture(t, cp, *tc.posture)
			}
			hookPromptJudgeFallbackFn = func(config.Config) (bool, bool) { return tc.fallback, tc.fallback }
			if got := hookPostureFailsClosed(cp, cp, tc.c).FailsClosed; got != tc.wantFinal {
				t.Errorf("final plan fails closed = %v, want %v", got, tc.wantFinal)
			}
			if got := hookPreliminaryFailsClosed(cp, cp, tc.c); got != tc.wantInterim {
				t.Errorf("interim plan fails closed = %v, want %v", got, tc.wantInterim)
			}
		})
	}
}

// TestPromptJudgeStateFromFacts pins the no-daemon fallback: the same gate the
// daemon's lane applies.
func TestPromptJudgeStateFromFacts(t *testing.T) {
	det := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}},"node_lane":true}`)
	strict := mustSpec(t, `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["x"]}},"node_lane":true}`)
	gwOnly := mustSpec(t, `{"admission":{"mode":"enforce","prefilter":{"deny":["x"]}}}`)
	on := planeBStatusFacts{Managed: true, HoldsEnforce: true, Accepted: true, HavePolicy: true, Spec: det}
	with := func(mut func(*planeBStatusFacts)) planeBStatusFacts { f := on; mut(&f); return f }
	cases := []struct {
		name                 string
		f                    planeBStatusFacts
		preauth              bool
		wantActive, wantFail bool
	}{
		{"individual node", planeBStatusFacts{Spec: det}, true, false, false},
		{"no enforce.admission", with(func(f *planeBStatusFacts) { f.HoldsEnforce = false }), true, false, false},
		{"gateway only body", with(func(f *planeBStatusFacts) { f.Spec = gwOnly }), true, false, false},
		{"active, non-strict", on, true, true, false},
		{"active, strict, preauthorized", with(func(f *planeBStatusFacts) { f.Spec = strict }), true, true, true},
		{"active, strict, not preauthorized", with(func(f *planeBStatusFacts) { f.Spec = strict }), false, true, false},
	}
	for _, tc := range cases {
		f := tc.f
		f.Preauthorized = tc.preauth
		a, fc := promptJudgeStateFromFacts(f)
		if a != tc.wantActive || fc != tc.wantFail {
			t.Errorf("%s: active=%v fail_closed=%v, want %v %v", tc.name, a, fc, tc.wantActive, tc.wantFail)
		}
	}
}

// TestHookOrgPromptJudgeEndToEnd drives the production dependencies: the
// daemon's signed posture file says the judge is active, the hook reads it,
// dials the real owner-only endpoint the daemon's lane serves, and replies
// with the lane's refusal. With a posture that says inactive, nothing is
// dialed.
func TestHookOrgPromptJudgeEndToEnd(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	pinToolHomes(t)
	dir, err := os.MkdirTemp("", "pje")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dbPath := filepath.Join(dir, "observer.db")
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, "[observer]\ndb_path = "+strconv.Quote(dbPath)+"\n")
	if err := os.Chtimes(cp, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	lane, eng, _ := hookTestLane(t, hookDet, true)
	ln, _, err := promptjudgeipc.Listen(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = promptjudgeipc.Serve(ctx, ln, promptJudgeAnswerer(lane)) }()
	plan := hookFailurePlan{Tool: "droid", Event: "UserPromptSubmit", Cap: integration.HookCapPromptGate, HostTimeout: 30 * time.Second}
	var cfg config.Config
	cfg.Observer.DBPath = dbPath

	writePosture(t, cp, guardposture.Posture{Source: guardposture.SourceOrg, PromptJudgeActive: true})
	got := hookOrgPromptJudge(plan, hook.OrgPromptQuery{Tool: "droid", SessionID: "s1", Prompt: "please drop table users"}, productionPromptJudgeDeps(cp, cfg, io.Discard))
	if !got.Block || !strings.Contains(got.Reason, promptJudgeRefusedPrefix) {
		t.Fatalf("active posture: judgement %+v, want the lane's refusal", got)
	}
	if len(eng.texts) != 1 {
		t.Fatalf("engine judged %q", eng.texts)
	}

	writePosture(t, cp, guardposture.Posture{Source: guardposture.SourceOrg})
	if got := hookOrgPromptJudge(plan, hook.OrgPromptQuery{Tool: "droid", SessionID: "s2", Prompt: "please drop table users again"}, productionPromptJudgeDeps(cp, cfg, io.Discard)); got.Block {
		t.Fatalf("inactive posture: judgement %+v, want nothing asked", got)
	}
	if len(eng.texts) != 1 {
		t.Fatalf("an inactive posture must not reach the daemon; engine judged %q", eng.texts)
	}
}

// TestHookPromptJudgePostureSkipsTheDatabaseOnAnIndividualNode pins L1
// (adm-2 fixes-1): with no trusted posture (the daemon stopped), a node with
// no planeb.admission body cached, or one that does not accept the family,
// answers inactive from the config and one directory listing, never opening
// the database; a node with a cached body still derives from durable state.
func TestHookPromptJudgePostureSkipsTheDatabaseOnAnIndividualNode(t *testing.T) {
	dir := t.TempDir()
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, "")
	base := config.Config{}
	base.Observer.DBPath = filepath.Join(dir, "observer.db")
	accepting := base
	accepting.OrgClient.Policy.AcceptFamilies = []string{policyfam.FamilyPlaneBAdmission}
	cached := accepting
	cached.Observer.DBPath = filepath.Join(dir, "cached", "observer.db")
	body := filepath.Join(policyResourceCacheDir(cached), "orgkey", "3", policyfam.FamilyPlaneBAdmission+".json")
	if err := os.MkdirAll(filepath.Dir(body), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFileT(t, body, "{}")
	cases := []struct {
		name         string
		cfg          config.Config
		wantFallback bool
	}{
		{"individual: family not accepted", base, false},
		{"accepted, no body cached", accepting, false},
		{"accepted, body cached: derives from durable state", cached, true},
	}
	prev := hookPromptJudgeFallbackFn
	t.Cleanup(func() { hookPromptJudgeFallbackFn = prev })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			hookPromptJudgeFallbackFn = func(config.Config) (bool, bool) { called = true; return true, true }
			active, _ := hookPromptJudgePosture(cp, tc.cfg)
			if called != tc.wantFallback || active != tc.wantFallback {
				t.Fatalf("fallback called=%v active=%v, want %v", called, active, tc.wantFallback)
			}
		})
	}
}

// judgeHarness is a temp observer home whose config carries guardCfg, a
// fresh signed posture saying the org prompt judge is active, and the
// daemon's real prompt judge endpoint served by a managed test lane.
type judgeHarness struct {
	cp  string
	eng *fakeCodingEngine
}

func newJudgeHarness(t *testing.T, guardCfg string, posture guardposture.Posture) judgeHarness {
	t.Helper()
	dir, err := os.MkdirTemp("", "pjg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dbPath := filepath.Join(dir, "observer.db")
	seedNodeDB(t, dbPath)
	cp := filepath.Join(dir, "config.toml")
	writeFileT(t, cp, "[observer]\ndb_path = "+strconv.Quote(filepath.ToSlash(dbPath))+"\n\n"+guardCfg)
	if err := os.Chtimes(cp, time.Now().Add(-time.Hour), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	writePosture(t, cp, posture)
	lane, eng, _ := hookTestLane(t, hookDet, true)
	ln, _, err := promptjudgeipc.Listen(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = promptjudgeipc.Serve(ctx, ln, promptJudgeAnswerer(lane)) }()
	return judgeHarness{cp: cp, eng: eng}
}

// runPromptHook runs one prompt-gate entry point as a fresh invocation under
// plan, with payload on stdin, and returns its stdout, stderr and recorded
// exit codes.
func runPromptHook(t *testing.T, plan hookFailurePlan, run func(), payload string, exitCodes *[]int) (stdout, stderr string, codes []int) {
	t.Helper()
	resetHookInvocationState()
	setHookPlan(plan)
	var out strings.Builder
	prevOut := hookReplyOut
	hookReplyOut = &out
	defer func() { hookReplyOut = prevOut }()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = stdinW.Write([]byte(payload))
		_ = stdinW.Close()
	}()
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldErr := os.Stdin, os.Stderr
	os.Stdin, os.Stderr = stdinR, stderrW
	before := len(*exitCodes)
	run()
	os.Stdin, os.Stderr = oldIn, oldErr
	_ = stderrW.Close()
	errOut, _ := io.ReadAll(stderrR)
	return out.String(), string(errOut), append([]int(nil), (*exitCodes)[before:]...)
}

// TestPromptGateAsksTheJudgeWhateverTheLocalGuardSays pins H3 (adm-2 fixes-1,
// rows per entry point added by fixes-2): the organization's judge runs on a
// prompt gate even when the developer's local guard does not evaluate
// prompts ([guard] off or disabled, [guard.prompt] disabled or its hook lane
// off), on every entry point: Claude Code, the generic dialect path (every
// plugin shim and foreign reroute), Codex and Cursor.
func TestPromptGateAsksTheJudgeWhateverTheLocalGuardSays(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	pinToolHomes(t)
	const prompt = "please drop table users"
	guards := []struct{ name, cfg string }{
		{"[guard] mode off", "[guard]\nenabled = true\nmode = \"off\"\n"},
		{"[guard] disabled", "[guard]\nenabled = false\n"},
		{"[guard.prompt] disabled", "[guard]\nenabled = true\nmode = \"enforce\"\n\n[guard.prompt]\nenabled = false\n"},
		{"[guard.prompt] hook_lane off", "[guard]\nenabled = true\nmode = \"enforce\"\n\n[guard.prompt]\nenabled = true\nhook_lane = false\n"},
	}
	type entry struct {
		name string
		// adapter names the adapter whose receiver run drives, "" when the
		// entry point is not an adapter's own receiver; the row skips in a
		// build that compiles that adapter out.
		adapter string
		plan    hookFailurePlan
		payload string
		run     func(cp string)
		// refused reports whether the reply refused the prompt.
		refused func(stdout, stderr string, codes []int) bool
	}
	exitOf := func(codes []int) bool { return len(codes) == 1 && codes[0] == 2 }
	entries := []entry{
		{
			name:    "claude-code",
			plan:    hookFailurePlan{Tool: "claude-code", Event: "UserPromptSubmit", Cap: integration.HookCapPromptGate, HostTimeout: 30 * time.Second},
			payload: `{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"` + prompt + `"}`,
			run: func(cp string) {
				handleClaudeCodeUserPromptSubmitFrom(context.Background(), os.Stdin, "user-prompt-submit", cp)
			},
			refused: func(_, stderr string, codes []int) bool {
				return exitOf(codes) && strings.Contains(stderr, promptJudgeRefusedPrefix)
			},
		},
		{
			name:    "generic dialect path (droid)",
			plan:    hookFailurePlan{Tool: "droid", Event: "UserPromptSubmit", Cap: integration.HookCapPromptGate, HostTimeout: 30 * time.Second},
			payload: `{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"` + prompt + `"}`,
			run: func(cp string) {
				body, _ := io.ReadAll(os.Stdin)
				evaluatePromptSubmitBody("droid", "droid", hook.PromptDialectClaudeCode, "UserPromptSubmit", "UserPromptSubmit", cp, body, false, hookStdout)
			},
			refused: func(_, stderr string, codes []int) bool {
				return exitOf(codes) && strings.Contains(stderr, promptJudgeRefusedPrefix)
			},
		},
		{
			name:    "codex",
			adapter: "codex",
			plan:    hookFailurePlan{Tool: "codex", Event: "UserPromptSubmit", Cap: integration.HookCapPromptGate, HostTimeout: 30 * time.Second},
			payload: `{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/w","prompt":"` + prompt + `"}`,
			run:     func(cp string) { hookReceivers["codex"](context.Background(), "UserPromptSubmit", cp) },
			refused: func(stdout, _ string, _ []int) bool {
				return strings.Contains(stdout, `"decision":"block"`) && strings.Contains(stdout, promptJudgeRefusedPrefix)
			},
		},
		{
			name:    "cursor",
			adapter: "cursor",
			plan:    hookFailurePlan{Tool: "cursor", Event: "beforeSubmitPrompt", Cap: integration.HookCapPromptGate, HostTimeout: 30 * time.Second},
			payload: `{"conversation_id":"c1","generation_id":"g1","hook_event_name":"beforeSubmitPrompt","workspace_roots":["/w"],"prompt":"` + prompt + `"}`,
			run:     func(cp string) { hookReceivers["cursor"](context.Background(), "beforeSubmitPrompt", cp) },
			refused: func(stdout, _ string, _ []int) bool {
				return strings.Contains(stdout, `"continue":false`) && strings.Contains(stdout, promptJudgeRefusedPrefix)
			},
		},
	}
	var exitCodes []int
	prevExit := hookOSExit
	hookOSExit = func(code int) { exitCodes = append(exitCodes, code) }
	t.Cleanup(func() { hookOSExit = prevExit })
	t.Cleanup(resetHookInvocationState)
	for _, e := range entries {
		for _, gc := range guards {
			t.Run(e.name+"/"+gc.name, func(t *testing.T) {
				if e.adapter != "" {
					requireAdapter(t, e.adapter)
				}
				h := newJudgeHarness(t, gc.cfg, guardposture.Posture{Source: guardposture.SourceOrg, PromptJudgeActive: true})
				stdout, stderr, codes := runPromptHook(t, e.plan, func() { e.run(h.cp) }, e.payload, &exitCodes)
				if !e.refused(stdout, stderr, codes) {
					t.Fatalf("not refused by the org judge: exit %v\nstdout %q\nstderr %q", codes, stdout, stderr)
				}
				h.eng.mu.Lock()
				defer h.eng.mu.Unlock()
				if len(h.eng.texts) != 1 || h.eng.texts[0] != prompt {
					t.Fatalf("engine judged %q, want the prompt once", h.eng.texts)
				}
			})
		}
	}
}

// TestJudgeOnlyPathRefusesAWrongShapePayload pins N3 (adm-2 fixes-2; call
// site rows added by lows L3): on the judge-only path of every prompt-gate
// entry point (the generic dialect path, Claude Code, Codex, Cursor) a
// prompt payload that is valid JSON of the wrong shape (nothing could be
// asked) refuses where the invocation's failure plan already fails closed (a
// strict enforced judge), exactly as on the guarded path; where the plan is
// open (an individual node) it goes through as before.
func TestJudgeOnlyPathRefusesAWrongShapePayload(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	pinToolHomes(t)
	var exitCodes []int
	prevExit := hookOSExit
	hookOSExit = func(code int) { exitCodes = append(exitCodes, code) }
	t.Cleanup(func() { hookOSExit = prevExit })
	t.Cleanup(resetHookInvocationState)
	const claudeShape = `{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":42}`
	entries := []struct {
		name string
		tool string
		// adapter names the adapter whose receiver run drives ("" for an
		// entry point that is not one); the row skips in a build that
		// compiles that adapter out.
		adapter string
		event   string
		dialect string
		payload string
		run     func(cp string)
	}{
		{"generic dialect path (droid)", "droid", "", "UserPromptSubmit", hook.PromptDialectClaudeCode, claudeShape, func(cp string) {
			body, _ := io.ReadAll(os.Stdin)
			evaluatePromptSubmitBody("droid", "droid", hook.PromptDialectClaudeCode, "UserPromptSubmit", "UserPromptSubmit", cp, body, false, hookStdout)
		}},
		{"claude-code", "claude-code", "", "UserPromptSubmit", hook.PromptDialectClaudeCode, claudeShape, func(cp string) {
			handleClaudeCodeUserPromptSubmitFrom(context.Background(), os.Stdin, "user-prompt-submit", cp)
		}},
		{"codex", "codex", "codex", "UserPromptSubmit", hook.PromptDialectTopLevelBlock, `{"session_id":"s1","hook_event_name":"UserPromptSubmit","cwd":"/w","prompt":42}`, func(cp string) {
			hookReceivers["codex"](context.Background(), "UserPromptSubmit", cp)
		}},
		{"cursor", "cursor", "cursor", "beforeSubmitPrompt", hook.PromptDialectCursor, `{"conversation_id":"c1","generation_id":"g1","hook_event_name":"beforeSubmitPrompt","workspace_roots":["/w"],"prompt":42}`, func(cp string) {
			hookReceivers["cursor"](context.Background(), "beforeSubmitPrompt", cp)
		}},
	}
	refusedBy := func(stdout string, codes []int) bool {
		if len(codes) > 0 && codes[0] != 0 {
			return true
		}
		return strings.Contains(stdout, `"continue":false`) || strings.Contains(stdout, `"decision":"block"`)
	}
	for _, e := range entries {
		for _, failClosed := range []bool{true, false} {
			name := e.name + "/plan open: goes through"
			if failClosed {
				name = e.name + "/strict judge (plan closed): refused"
			}
			t.Run(name, func(t *testing.T) {
				if e.adapter != "" {
					requireAdapter(t, e.adapter)
				}
				if !hook.PromptPayloadUndecodable(e.dialect, []byte(e.payload)) {
					t.Fatalf("fixture %s is not a wrong-shape payload for dialect %s", e.payload, e.dialect)
				}
				h := newJudgeHarness(t, "[guard]\nenabled = false\n", guardposture.Posture{Source: guardposture.SourceOrg, PromptJudgeActive: true, PromptJudgeFailClosed: failClosed})
				plan := hookFailurePlan{Tool: e.tool, Event: e.event, Cap: integration.HookCapPromptGate, Dialect: e.dialect, Gated: true, FailClosed: failClosed, HostTimeout: 30 * time.Second}
				stdout, stderr, codes := runPromptHook(t, plan, func() { e.run(h.cp) }, e.payload, &exitCodes)
				if refused := refusedBy(stdout, codes); refused != failClosed {
					t.Fatalf("refused=%v, want %v (exit %v stdout %q stderr %q)", refused, failClosed, codes, stdout, stderr)
				}
				h.eng.mu.Lock()
				defer h.eng.mu.Unlock()
				if len(h.eng.texts) != 0 {
					t.Fatalf("a wrong-shape payload must not reach the engine; judged %q", h.eng.texts)
				}
			})
		}
	}
}
