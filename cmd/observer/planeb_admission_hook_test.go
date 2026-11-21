package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/promptadmit"
	"github.com/marmutapp/superbased-observer/internal/promptjudgeipc"
)

// hookTestLane is a managed lane with a fake engine and an audit counter.
func hookTestLane(t *testing.T, body string, managed bool) (*planeBNodeLane, *fakeCodingEngine, func() int) {
	t.Helper()
	lane := newPlaneBNodeLane()
	eng := &fakeCodingEngine{}
	lane.engine = eng.eval
	lane.managedFn = func() bool { return managed }
	var mu sync.Mutex
	rows := 0
	lane.persist = func(context.Context, []guard.ActionVerdict) error {
		mu.Lock()
		rows++
		mu.Unlock()
		return nil
	}
	if body != "" {
		lane.publish(orgclient.PolicyResourceResult{Version: 1, BodyHash: "h", EnforceAllowed: true, Spec: mustSpec(t, body)}, nil)
	}
	count := func() int {
		time.Sleep(100 * time.Millisecond) // audit writes are asynchronous
		mu.Lock()
		defer mu.Unlock()
		return rows
	}
	return lane, eng, count
}

const hookDet = `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true}`

// TestAdmitHookRows is one row per hook-lane posture and verdict (adm-2).
func TestAdmitHookRows(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		managed    bool
		prompt     string
		oversize   bool
		wantActive bool
		wantAction promptadmit.Action
		wantTexts  []string
	}{
		{name: "individual node: inactive, nothing judged", body: hookDet, prompt: "please drop table users", wantAction: promptadmit.ActionAllow},
		{name: "managed, no policy: inactive", managed: true, prompt: "please drop table users", wantAction: promptadmit.ActionAllow},
		{name: "managed, node_lane off: inactive", body: `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}}}`, managed: true, prompt: "x", wantAction: promptadmit.ActionAllow},
		{name: "managed deny refuses", body: hookDet, managed: true, prompt: "please drop table users", wantActive: true, wantAction: promptadmit.ActionBlock, wantTexts: []string{"please drop table users"}},
		{name: "managed clean prompt allows", body: hookDet, managed: true, prompt: "add a test", wantActive: true, wantAction: promptadmit.ActionAllow, wantTexts: []string{"add a test"}},
		{name: "blank prompt is not judged", body: hookDet, managed: true, prompt: "   ", wantActive: true, wantAction: promptadmit.ActionAllow},
		{name: "all_calls judges the hook prompt too", body: `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true,"scope":"all_calls"}`, managed: true, prompt: "please drop table users", wantActive: true, wantAction: promptadmit.ActionBlock, wantTexts: []string{"please drop table users"}},
		{name: "oversize, non-strict: flagged unevaluated", body: hookDet, managed: true, oversize: true, wantActive: true, wantAction: promptadmit.ActionFlag},
		{name: "oversize, strict: refused", body: `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["zzz"]}},"node_lane":true}`, managed: true, oversize: true, wantActive: true, wantAction: promptadmit.ActionBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lane, eng, _ := hookTestLane(t, tc.body, tc.managed)
			o, active := lane.admitHook(context.Background(), planeBPromptInput{SessionID: "s1", Tool: "cursor"}, tc.prompt, tc.oversize)
			if active != tc.wantActive || o.Action != tc.wantAction {
				t.Fatalf("admitHook = %+v active=%v, want %s active=%v", o, active, tc.wantAction, tc.wantActive)
			}
			if strings.Join(eng.texts, "|") != strings.Join(tc.wantTexts, "|") {
				t.Fatalf("engine judged %q, want %q", eng.texts, tc.wantTexts)
			}
		})
	}
}

// TestHookThenProxyJudgesOnce is one row per hook+proxy wire shape and per
// dedupe rule (adm-2 fixes-1, H1 and L2): a hook verdict stands in for the
// proxy lane only when ONE text block of the request's fresh user turn has
// the hook prompt's exact digest, in the same session, under user_prompts,
// and only once. engineCalls counts every judgement (the hook's included).
func TestHookThenProxyJudgesOnce(t *testing.T) {
	type m = map[string]any
	const deny = "please drop table users"
	const reminder = "<system-reminder>context</system-reminder>"
	const allCalls = `{"admission":{"mode":"enforce","prefilter":{"deny":["zzz"]}},"node_lane":true,"scope":"all_calls"}`
	anthropic := promptBody
	responses := func(t *testing.T, items ...any) []byte { return hookTestJSON(t, m{"model": "m", "input": items}) }
	gemini := func(t *testing.T, contents ...any) []byte { return hookTestJSON(t, m{"contents": contents}) }
	blocks := func(texts ...string) []any {
		out := make([]any, 0, len(texts))
		for _, x := range texts {
			out = append(out, m{"type": "text", "text": x})
		}
		return out
	}
	type req struct {
		provider string
		session  string
		body     func(t *testing.T) []byte
	}
	cases := []struct {
		name        string
		policy      string
		hook        string
		reqs        []req
		engineCalls int
		judged      []string
		wantAction  promptadmit.Action
		// enforce publishes the policy with enforce allowed (preauthorized),
		// so a deny is a Block; the other rows run without it (a Flag), so
		// the proxy sees the request.
		enforce bool
	}{
		{
			name: "anthropic (claude-code): prompt block beside a reminder block, then its loop", hook: deny,
			reqs: []req{
				{"anthropic", "sess-1", func(t *testing.T) []byte {
					return anthropic(t, m{"role": "user", "content": blocks(reminder, deny)})
				}},
				{"anthropic", "sess-1", func(t *testing.T) []byte {
					return anthropic(t, m{"role": "user", "content": blocks(reminder, deny)},
						m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t", "name": "Bash", "input": m{}}}},
						m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t", "content": "ok"}}})
				}},
			},
			engineCalls: 2, judged: []string{deny, reminder}, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "openai chat string content (opencode, kimi-code, qwen-code, cline-cli)", hook: deny,
			reqs: []req{{"openai", "sess-1", func(t *testing.T) []byte {
				return promptBody(t, m{"role": "system", "content": "sys"}, m{"role": "user", "content": deny})
			}}},
			engineCalls: 1, judged: []string{deny}, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "openai chat content parts", hook: deny,
			reqs: []req{{"openai", "sess-1", func(t *testing.T) []byte {
				return promptBody(t, m{"role": "user", "content": blocks(reminder, deny)})
			}}},
			engineCalls: 2, judged: []string{deny, reminder}, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "openai responses items (codex, copilot-cli)", hook: deny,
			reqs: []req{{"openai", "sess-1", func(t *testing.T) []byte {
				return responses(t, m{"role": "user", "content": []any{
					m{"type": "input_text", "text": "<environment_context>x</environment_context>"},
					m{"type": "input_text", "text": deny},
				}})
			}}},
			engineCalls: 2, judged: []string{deny, "<environment_context>x</environment_context>"}, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "gemini parts (gemini-cli)", hook: deny,
			reqs: []req{{"google", "sess-1", func(t *testing.T) []byte {
				return gemini(t, m{"role": "user", "parts": []any{m{"text": "ctx"}, m{"text": deny}}})
			}}},
			engineCalls: 2, judged: []string{deny, "ctx"}, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "containment never matches: an allowed 'ok' does not cover a later prompt that contains it", hook: "ok",
			reqs: []req{{"anthropic", "sess-1", func(t *testing.T) []byte {
				return anthropic(t, m{"role": "user", "content": blocks("ok, now " + deny)})
			}}},
			engineCalls: 2, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "one block joined with added text is not equal: judged by the proxy", hook: deny,
			reqs: []req{{"anthropic", "sess-1", func(t *testing.T) []byte {
				return anthropic(t, m{"role": "user", "content": reminder + "\n" + deny})
			}}},
			engineCalls: 2, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "all_calls: a hook verdict never stands in for the trailing segment", policy: allCalls, hook: deny,
			reqs: []req{{"anthropic", "sess-1", func(t *testing.T) []byte {
				return anthropic(t, m{"role": "user", "content": blocks(reminder, deny)})
			}}},
			engineCalls: 2, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "another session does not reuse it", hook: deny,
			reqs: []req{{"anthropic", "sess-2", func(t *testing.T) []byte {
				return anthropic(t, m{"role": "user", "content": blocks(reminder, deny)})
			}}},
			engineCalls: 2, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "consumed once: a second turn carrying the same block is judged", hook: "list the files",
			reqs: []req{
				{"anthropic", "sess-1", func(t *testing.T) []byte {
					return anthropic(t, m{"role": "user", "content": blocks("list the files")})
				}},
				{"anthropic", "sess-1", func(t *testing.T) []byte {
					return anthropic(t, m{"role": "user", "content": blocks("list the files")},
						m{"role": "assistant", "content": "done"},
						m{"role": "user", "content": blocks("then "+deny, "list the files")})
				}},
			},
			engineCalls: 2, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "a sibling block alone is denied: the turn is denied though the hook allowed its prompt", hook: "list the files",
			reqs: []req{{"anthropic", "sess-1", func(t *testing.T) []byte {
				return anthropic(t, m{"role": "user", "content": blocks("attached: "+deny, "list the files")})
			}}},
			engineCalls: 2, judged: []string{"list the files", "attached: " + deny}, wantAction: promptadmit.ActionFlag,
		},
		{
			name: "enforced and preauthorized: a sibling block alone denied blocks the turn", hook: "list the files", enforce: true,
			reqs: []req{{"anthropic", "sess-1", func(t *testing.T) []byte {
				return anthropic(t, m{"role": "user", "content": blocks("attached: "+deny, "list the files")})
			}}},
			engineCalls: 2, judged: []string{"list the files", "attached: " + deny}, wantAction: promptadmit.ActionBlock,
		},
		{
			name: "several sibling blocks are judged once, joined in turn order", hook: "list the files",
			reqs: []req{{"google", "sess-1", func(t *testing.T) []byte {
				return gemini(t, m{"role": "user", "parts": []any{m{"text": "file a"}, m{"text": "list the files"}, m{"text": "file b"}}})
			}}},
			engineCalls: 2, judged: []string{"list the files", "file a\nfile b"}, wantAction: promptadmit.ActionAllow,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := tc.policy
			if policy == "" {
				policy = hookDet
			}
			lane, eng, _ := hookTestLane(t, "", true)
			// A deny under a non-preauthorized enforce is a flag: forwarded,
			// so the proxy does see the same prompt.
			lane.publish(orgclient.PolicyResourceResult{Version: 2, BodyHash: "h2", EnforceAllowed: tc.enforce, Spec: mustSpec(t, policy)}, nil)
			if _, active := lane.admitHook(context.Background(), planeBPromptInput{SessionID: "sess-1", Tool: "t"}, tc.hook, false); !active {
				t.Fatal("hook lane inactive")
			}
			var last promptadmit.Outcome
			for _, r := range tc.reqs {
				last = lane.admit(context.Background(), planeBPromptInput{Provider: r.provider, Body: r.body(t), SessionID: r.session})
			}
			if last.Action != tc.wantAction {
				t.Fatalf("last proxy outcome = %+v, want %s", last, tc.wantAction)
			}
			eng.mu.Lock()
			defer eng.mu.Unlock()
			if len(eng.texts) != tc.engineCalls {
				t.Fatalf("engine judged %q (%d), want %d judgements", eng.texts, len(eng.texts), tc.engineCalls)
			}
			if tc.judged != nil && strings.Join(eng.texts, "|") != strings.Join(tc.judged, "|") {
				t.Fatalf("engine judged %q, want %q", eng.texts, tc.judged)
			}
		})
	}
}

// TestHookRemembersOnlyDefinitiveVerdicts pins N2 (adm-2 fixes-2): only a
// judgement the engine actually made stands in for the proxy lane; a judge
// that could not answer in the hook's shorter budget, or an oversize prompt,
// is not remembered, so the proxy lane judges with its own budget.
func TestHookRemembersOnlyDefinitiveVerdicts(t *testing.T) {
	const judged = `{"admission":{"mode":"enforce","criteria":[{"id":"j","type":"custom","definition":"bad"}]},"judge_upstream_id":"up","node_lane":true}`
	cases := []struct {
		name       string
		body       string
		prompt     string
		oversize   bool
		wantBasis  promptadmit.Basis
		remembered bool
	}{
		{"deterministic deny is remembered", hookDet, "please drop table users", false, promptadmit.BasisDeny, true},
		{"allow is remembered", hookDet, "add a test", false, promptadmit.BasisAllow, true},
		{"judge unavailable is not", judged, "add a test", false, promptadmit.BasisJudgeUnavailable, false},
		{"oversize is not", hookDet, "", true, basisPromptTooLarge, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lane, _, _ := hookTestLane(t, tc.body, true) // no judge bound: a judged criterion is unavailable
			o, active := lane.admitHook(context.Background(), planeBPromptInput{SessionID: "s"}, tc.prompt, tc.oversize)
			if !active || o.Basis != tc.wantBasis {
				t.Fatalf("hook outcome %+v active=%v, want basis %s", o, active, tc.wantBasis)
			}
			lane.mu.Lock()
			n := len(lane.hookVerdicts)
			lane.mu.Unlock()
			if (n == 1) != tc.remembered {
				t.Fatalf("hook record holds %d entries, want remembered=%v", n, tc.remembered)
			}
		})
	}
}

// hookTestJSON marshals v for a test body.
func hookTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPromptJudgeAnswererOverTheEndpoint drives the real owner-only endpoint:
// the hook's ask reaches the lane and gets its verdict back.
func TestPromptJudgeAnswererOverTheEndpoint(t *testing.T) {
	if !localipc.Supported() {
		t.Skip("no local IPC transport on this platform")
	}
	lane, _, _ := hookTestLane(t, hookDet, true)
	dir, err := os.MkdirTemp("", "pjd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	dbPath := filepath.Join(dir, "observer.db")
	ln, ep, err := promptjudgeipc.Listen(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = promptjudgeipc.Serve(ctx, ln, promptJudgeAnswerer(lane)) }()
	a, err := promptjudgeipc.Ask(context.Background(), ep, promptjudgeipc.Request{Tool: "cursor", SessionID: "s", Prompt: "please drop table users", Budget: 2 * time.Second})
	if err != nil || !a.Block() || a.Reason == "" {
		t.Fatalf("answer = %+v err=%v, want a block with a reason", a, err)
	}
	individual, _, _ := hookTestLane(t, hookDet, false)
	cancel()
	ln2, ep2, err := promptjudgeipc.Listen(filepath.Join(dir, "other", "observer.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	t.Cleanup(cancel2)
	go func() { _ = promptjudgeipc.Serve(ctx2, ln2, promptJudgeAnswerer(individual)) }()
	if a, err := promptjudgeipc.Ask(context.Background(), ep2, promptjudgeipc.Request{Prompt: "please drop table users", Budget: 2 * time.Second}); err != nil || a.Active {
		t.Fatalf("individual node answer = %+v err=%v, want inactive", a, err)
	}
}

// TestGuardPostureCarriesThePromptJudge pins the posture fields the hook
// reads (adm-2): active only on a managed node with a node_lane body, fail
// closed only when strict and enforced, and set even when the local guard is
// off.
func TestGuardPostureCarriesThePromptJudge(t *testing.T) {
	prev := processPlaneBLane
	t.Cleanup(func() { processPlaneBLane = prev })
	cases := []struct {
		name                 string
		body                 string
		managed              bool
		wantActive, wantFail bool
	}{
		{"individual node", hookDet, false, false, false},
		{"managed, non-strict", hookDet, true, true, false},
		{"managed, strict enforce", `{"admission":{"mode":"enforce","strict":true,"prefilter":{"deny":["zzz"]}},"node_lane":true}`, true, true, true},
		{"managed, strict observe", `{"admission":{"mode":"observe","strict":true,"prefilter":{"deny":["zzz"]}},"node_lane":true}`, true, true, false},
	}
	for _, tc := range cases {
		lane, _, _ := hookTestLane(t, tc.body, tc.managed)
		processPlaneBLane = lane
		p := computeGuardPosture(config.GuardConfig{Enabled: false}, nil, time.Now())
		if p.PromptJudgeActive != tc.wantActive || p.PromptJudgeFailClosed != tc.wantFail {
			t.Errorf("%s: posture active=%v fail_closed=%v, want %v %v", tc.name, p.PromptJudgeActive, p.PromptJudgeFailClosed, tc.wantActive, tc.wantFail)
		}
	}
}

// TestPlaneBNodeLaneLoopVerdictCappedAtMaxAge pins L1 (adm-2): on the node, a
// tool loop in use keeps its opening prompt's verdict past the cache TTL
// (each continuation refreshes it), but never past DefaultMaxAge after it
// was judged; then the opening prompt is judged again.
func TestPlaneBNodeLaneLoopVerdictCappedAtMaxAge(t *testing.T) {
	type m = map[string]any
	lane, eng, _ := hookTestLane(t, hookDet, true)
	start := time.Unix(1_700_000_000, 0)
	now := start
	lane.now = func() time.Time { return now }
	lane.cache = promptadmit.NewCache(0, 0, func() time.Time { return now })
	opening := promptBody(t, m{"role": "user", "content": "refactor the parser"})
	loop := promptBody(t,
		m{"role": "user", "content": "refactor the parser"},
		m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t", "name": "Bash", "input": m{}}}},
		m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t", "content": "ok"}}})
	admit := func(b []byte) {
		_ = lane.admit(context.Background(), planeBPromptInput{Provider: "anthropic", Body: b, SessionID: "s"})
	}
	admit(opening)
	for now.Sub(start) < promptadmit.DefaultMaxAge-promptadmit.DefaultCacheTTL {
		now = now.Add(promptadmit.DefaultCacheTTL / 2)
		admit(loop)
	}
	if len(eng.texts) != 1 {
		t.Fatalf("the loop was re-judged inside the maximum age: engine calls %d", len(eng.texts))
	}
	now = start.Add(promptadmit.DefaultMaxAge + time.Minute)
	admit(loop)
	if len(eng.texts) != 2 {
		t.Fatalf("past the maximum age the opening prompt must be judged again: engine calls %d", len(eng.texts))
	}
}

// TestPlaneBNodeLaneUnknownShapeIsRecordedOnce pins L2 (adm-2): an unknown
// provider lane's not-evaluated outcome is written to guard_events, once per
// cache life, not once per request.
func TestPlaneBNodeLaneUnknownShapeIsRecordedOnce(t *testing.T) {
	type m = map[string]any
	lane, _, rows := hookTestLane(t, hookDet, true)
	body := promptBody(t, m{"role": "user", "content": "hi"})
	for i := 0; i < 3; i++ {
		if o := lane.admit(context.Background(), planeBPromptInput{Provider: "a-future-provider", Body: body, SessionID: "s"}); o.Basis != promptadmit.BasisUnknownShape {
			t.Fatalf("outcome %+v", o)
		}
	}
	if n := rows(); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
}

// TestHookVerdictMapHoldsDigestsOnly pins that the in-memory hook record
// keeps neither the prompt nor the raw session id, and stays bounded (adm-2
// fixes-1, M1).
func TestHookVerdictMapHoldsDigestsOnly(t *testing.T) {
	lane, _, _ := hookTestLane(t, hookDet, true)
	const prompt, session = "a very recognisable prompt", "a-very-recognisable-session"
	if _, active := lane.admitHook(context.Background(), planeBPromptInput{SessionID: session}, prompt, false); !active {
		t.Fatal("inactive")
	}
	lane.mu.Lock()
	for k, v := range lane.hookVerdicts {
		dump := k + "|" + v.digest + "|" + v.polKey
		if strings.Contains(dump, "recognisable") {
			t.Fatalf("hook record holds raw text: %q", dump)
		}
	}
	lane.mu.Unlock()
	for i := 0; i < maxHookVerdicts+10; i++ {
		_, _ = lane.admitHook(context.Background(), planeBPromptInput{SessionID: strings.Repeat("s", i+1)}, "p", false)
	}
	lane.mu.Lock()
	n := len(lane.hookVerdicts)
	lane.mu.Unlock()
	if n > maxHookVerdicts {
		t.Fatalf("hook record holds %d entries, cap %d", n, maxHookVerdicts)
	}
}
