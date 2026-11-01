package guard

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// stopFor builds a HookBudgetLookup that stops tool (or every tool when tool
// is "") under ruleID.
func stopFor(tool, ruleID, reason string) HookBudgetLookup {
	return func(got string, _ time.Time) (HookBudgetStop, bool) {
		if tool != "" && tool != got {
			return HookBudgetStop{}, false
		}
		return HookBudgetStop{RuleID: ruleID, Reason: reason}, true
	}
}

// TestT519HookBudgetStopsEveryPreSendSeam is the red/green table for the hook
// path's budget stop (T-519, D-030 / D-031): an exhausted managed budget the
// daemon published stops the next prompt and the next tool call on every seam
// that can block, through the seam's own deny shape, and nothing else.
func TestT519HookBudgetStopsEveryPreSendSeam(t *testing.T) {
	t.Parallel()
	const reason = "organization daily budget (you, blocking) reached: daily spend $0.42 exceeds the $0.30 budget"
	preSend := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	cases := []struct {
		name string
		mode string
		// lookup is the published decision (nil = none wired).
		lookup HookBudgetLookup
		tool   string
		kind   policy.EventKind
		caps   policy.Capabilities
		// prompt evaluates through EvaluatePrompt (the prompt-submit seam);
		// otherwise EvaluateHook (the pre-tool seam).
		prompt    bool
		promptCap PromptSeamCaps
		wantRule  string
		// wantPerm is the wire permission the seam emits.
		wantPerm string
		why      string
	}{
		{
			name: "prompt-submit seam that blocks: deny", mode: "enforce",
			lookup: stopFor("", "B-602", reason), tool: "cursor", kind: policy.KindUserPrompt,
			prompt: true, promptCap: PromptSeamCaps{Reenter: true, Block: true},
			wantRule: "B-602", wantPerm: "deny",
			why: "Cursor beforeSubmitPrompt: a hard deny blocks, never re-enter (Sol A2-11)",
		},
		{
			name: "prompt-submit seam that warns too: still a block", mode: "enforce",
			lookup: stopFor("", "B-622", reason), tool: "claude-code", kind: policy.KindUserPrompt,
			prompt: true, promptCap: PromptSeamCaps{Warn: true, Reenter: true, Block: true},
			wantRule: "B-622", wantPerm: "deny",
			why: "Claude Code UserPromptSubmit: deny's ladder starts at block",
		},
		{
			name: "warn-only prompt seam: degrades to a warning", mode: "enforce",
			lookup: stopFor("", "B-602", reason), tool: "devin", kind: policy.KindUserPrompt,
			prompt: true, promptCap: PromptSeamWarnOnly,
			wantRule: "B-602", wantPerm: "allow",
			why: "a seam that cannot stop the prompt says so (D-030 ladder), the degrade is recorded",
		},
		{
			name: "pre-tool seam: deny", mode: "enforce",
			lookup: stopFor("", "B-602", reason), tool: "cursor", kind: policy.KindShellExec, caps: preSend,
			wantRule: "B-602", wantPerm: "deny",
			why: "Cursor preToolUse / beforeShellExecution",
		},
		{
			name: "no pre-send seam: nothing is stopped here", mode: "enforce",
			lookup: stopFor("", "B-602", reason), tool: "freebuff", kind: policy.KindShellExec, caps: policy.Capabilities{},
			wantRule: "", wantPerm: "allow",
			why: "a post-hoc channel cannot stop the call; the watcher flags it once per session (D-031)",
		},
		{
			name: "observe mode never blocks", mode: "observe",
			lookup: stopFor("", "B-602", reason), tool: "cursor", kind: policy.KindShellExec, caps: preSend,
			wantRule: "", wantPerm: "allow",
			why: "D2: the guard never blocks outside enforce; the warning service tells the developer",
		},
		{
			name: "no decision published: allow", mode: "enforce",
			lookup: nil, tool: "cursor", kind: policy.KindShellExec, caps: preSend,
			wantRule: "", wantPerm: "allow",
			why: "the pre-fix behaviour, kept where nothing is published",
		},
		{
			name: "per-tool stop: the capped tool is stopped", mode: "enforce",
			lookup: stopFor("cursor", "B-626", "daily cursor spend $1.10 exceeds the $1.00 budget"), tool: "cursor",
			kind: policy.KindShellExec, caps: preSend,
			wantRule: "B-626", wantPerm: "deny",
			why: "an org per-tool cap stops that tool",
		},
		{
			name: "per-tool stop: another tool is not", mode: "enforce",
			lookup: stopFor("cursor", "B-626", "daily cursor spend $1.10 exceeds the $1.00 budget"), tool: "codex",
			kind: policy.KindShellExec, caps: preSend,
			wantRule: "", wantPerm: "allow",
			why: "a per-tool cap never stops a different tool",
		},
		{
			name: "required budget never verified: fail closed", mode: "enforce",
			lookup: stopFor("", "B-625", "no verified organization budget has been applied here"), tool: "cursor",
			kind: policy.KindUserPrompt, prompt: true, promptCap: PromptSeamCaps{Reenter: true, Block: true},
			wantRule: "B-625", wantPerm: "deny",
			why: "the managed fail-closed row the proxy and the process controller already apply",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := guardCfg()
			cfg.Mode = tc.mode
			g := newTestGuard(t, cfg, nil)
			g.SetRequestAccessBase("http://127.0.0.1:8081")
			if tc.lookup != nil {
				g.SetHookBudgetLookup(tc.lookup)
			}
			ev := policy.Event{
				Kind: tc.kind, Tool: tc.tool, SessionID: "s-1", Caps: tc.caps,
				Target: "ls -la", ActionType: "run_command", Now: time.Now().UTC(),
			}
			var rule, perm, msg string
			if tc.prompt {
				pv := g.EvaluatePrompt(ev).WithAction(tc.promptCap, "hook")
				em := PromptEmission(pv)
				rule, perm, msg = pv.Verdict.RuleID, em.Permission, pv.Verdict.Reason
				if tc.wantRule != "" && !pv.RecordWorthy() {
					t.Errorf("a budget stop must be recorded")
				}
			} else {
				av, _ := g.EvaluateHook(ev)
				em := ResolveEmission(av.Verdict, ev.Caps)
				rule, perm, msg = av.Verdict.RuleID, em.Permission, av.Verdict.Reason
				if tc.wantRule != "" && av.Category != string(policy.CategoryBudget) {
					t.Errorf("category = %q, want budget", av.Category)
				}
				if tc.wantRule != "" && (av.OrgLocked || av.Overridable) {
					t.Errorf("a budget stop must not render as an org-locked or overridable rule")
				}
			}
			if tc.wantRule == "" && isBudgetRuleID(rule) {
				t.Fatalf("rule = %q, want no budget verdict - %s", rule, tc.why)
			}
			if tc.wantRule != "" && rule != tc.wantRule {
				t.Fatalf("rule = %q, want %q - %s", rule, tc.wantRule, tc.why)
			}
			if perm != tc.wantPerm {
				t.Fatalf("permission = %q, want %q - %s", perm, tc.wantPerm, tc.why)
			}
			if tc.wantRule != "" && !strings.Contains(msg, tc.wantRule) {
				t.Errorf("message %q does not name the rule", msg)
			}
		})
	}
}

// TestT519HookBudgetStopIsNotSoftenedByApprovals pins that a local approval
// (or any grant) cannot let a prompt or tool call through an exhausted managed
// budget: a budget increase is its own grant type, folded into the cap.
func TestT519HookBudgetStopIsNotSoftenedByApprovals(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetApprovalLookup(func(string, string, string) bool { return true })
	g.SetHookBudgetLookup(stopFor("", "B-602", "daily spend $0.42 exceeds the $0.30 budget"))
	av, _ := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, Tool: "cursor", SessionID: "s",
		ActionType: "run_command", Target: "ls", Caps: policy.Capabilities{PreExecution: true, CanBlock: true},
	})
	if av.Verdict.Decision != policy.DecisionDeny || av.Verdict.RuleID != "B-602" {
		t.Fatalf("verdict = %+v, want the B-602 deny", av.Verdict)
	}
}

// TestT519HookBudgetStricterPolicyDenyWins pins the merge rule: stricter wins.
// A policy verdict that already denies keeps its own rule; anything weaker (an
// ask, a flag) is raised to the budget deny. Either way the call is denied.
func TestT519HookBudgetStricterPolicyDenyWins(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	g.SetHookBudgetLookup(stopFor("", "B-602", "daily spend $0.42 exceeds the $0.30 budget"))
	av, _ := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, Tool: "cursor", SessionID: "s",
		ActionType: "run_command", Target: "rm -rf ~/projects", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	})
	if av.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("verdict = %+v, want a deny (the stricter of the policy verdict and the budget stop)", av.Verdict)
	}
}

// TestT519HookBudgetMessage pins what the developer reads: the budget, the
// spend, and how to get more in the unit the rule measures; B-625 points at the
// node's verification instead of at a budget request.
func TestT519HookBudgetMessage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, rule, base string
		want, notWant    []string
	}{
		{
			name: "usd cap with a dashboard", rule: "B-602", base: "http://127.0.0.1:8081",
			// WINNODE2 16d: no URL in band, even with a dashboard origin; the
			// desktop notification carries it (RequestAccessLink).
			want: []string{
				"Organization budget B-602", "until the period resets", BudgetIncreaseRequestLabel, "--usd <amount>",
			},
			notWant: []string{"--tokens", "http://", BudgetIncreaseRequestPath},
		},
		{
			name: "token cap without a dashboard", rule: "B-623",
			want:    []string{"Organization budget B-623", BudgetIncreaseRequestLabel, "--tokens <amount>"},
			notWant: []string{"http://", "--usd"},
		},
		{name: "per-tool usd cap", rule: "B-626", want: []string{"--usd <amount>"}},
		{
			name: "required budget", rule: "B-625", base: "http://127.0.0.1:8081",
			want:    []string{"verifies its organization budget", "observer org status"},
			notWant: []string{"request budget", BudgetIncreaseRequestLabel},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := HookBudgetMessage(HookBudgetStop{RuleID: tc.rule, Reason: "the cap is spent."}, tc.base)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("message %q missing %q", msg, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("message %q must not contain %q", msg, w)
				}
			}
			if strings.ContainsRune(msg, 0x2013) || strings.ContainsRune(msg, 0x2014) {
				t.Errorf("message %q carries an en or em dash", msg)
			}
			if strings.Contains(msg, "..") {
				t.Errorf("message %q doubles a full stop", msg)
			}
		})
	}
}

// TestT529DenyLinkOpensTheBudgetRequest pins the deny line's link against the
// node dashboard that has to open it (T-529): the route exists, every query
// key is one the Requests page consumes (web/src/lib/requestEntry.ts
// ENTRY_PARAMS), and the link is the stable budget deep link whose `new=`
// kind opens a budget_increase request (NEW_KINDS). The web side pins the same
// constant from requestEntry.test.ts, so neither half can drift alone.
func TestT529DenyLinkOpensTheBudgetRequest(t *testing.T) {
	t.Parallel()
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", "web", "src", filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read web source %s: %v", rel, err)
		}
		return string(b)
	}
	entry := read("lib/requestEntry.ts")

	m := regexp.MustCompile(`export const ENTRY_PARAMS = \[([^\]]*)\]`).FindStringSubmatch(entry)
	if m == nil {
		t.Fatal("requestEntry.ts: ENTRY_PARAMS not found")
	}
	accepted := map[string]bool{}
	for _, k := range regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(m[1], -1) {
		accepted[k[1]] = true
	}
	m = regexp.MustCompile(`const NEW_KINDS: Record<string, string> = \{([^}]*)\}`).FindStringSubmatch(entry)
	if m == nil {
		t.Fatal("requestEntry.ts: NEW_KINDS not found")
	}
	kinds := map[string]string{}
	for _, kv := range regexp.MustCompile(`([a-z_]+): "([a-z_]+)"`).FindAllStringSubmatch(m[1], -1) {
		kinds[kv[1]] = kv[2]
	}

	u, err := url.Parse(BudgetIncreaseRequestPath)
	if err != nil {
		t.Fatalf("parse %q: %v", BudgetIncreaseRequestPath, err)
	}
	// Routes live in the generated page registry since MP-DASH (T-591):
	// App.tsx renders every PAGE_ROUTES row as a <Route path={r.path}>, and
	// lib/components.gen.ts carries the rows. The link's path must be a row
	// there that mounts the Requests page, and App.tsx must still render the
	// registry (T-698).
	if u.Path != "/requests" {
		t.Fatalf("path %q is not the node dashboard's requests route", u.Path)
	}
	reqRow := regexp.MustCompile(`path: "requests",\s*component: "[a-z.]+",\s*Page: lazy\(\(\) => import\("@/pages/Requests"\)`)
	if !reqRow.MatchString(read("lib/components.gen.ts")) {
		t.Fatalf("lib/components.gen.ts: no PAGE_ROUTES row mounts pages/Requests at path %q", strings.TrimPrefix(u.Path, "/"))
	}
	if app := read("App.tsx"); !strings.Contains(app, "PAGE_ROUTES.map(") || !strings.Contains(app, `path={r.path}`) {
		t.Fatal("App.tsx no longer renders PAGE_ROUTES as routes; the requests row would not be reachable")
	}
	q := u.Query()
	for k := range q {
		if !accepted[k] {
			t.Errorf("query key %q is not an entry param the Requests page reads %v", k, accepted)
		}
	}
	if got := kinds[q.Get("new")]; got != "budget_increase" {
		t.Errorf("new=%q opens %q, want the stable budget deep link (new=budget opens budget_increase)", q.Get("new"), got)
	}
	if q.Has("type") {
		t.Errorf("%q uses the older type= form; the deny line carries the stable new=budget link", BudgetIncreaseRequestPath)
	}
	// The hook-path stop carries no budget id (a budget-admission.json Stop is
	// rule, reason, tool and valid_until), so the link stays id-less and the
	// page opens on the budget that ran out.
	if q.Has("budget") {
		t.Errorf("%q names a budget the hook-path stop does not know", BudgetIncreaseRequestPath)
	}
	// The link rides the human surfaces only (WINNODE2 16d): the desktop
	// notification of a budget stop carries it, the in-band line does not.
	link := RequestAccessLink(ActionVerdict{
		RequestBase: "http://127.0.0.1:8081", Category: string(policy.CategoryBudget), Verdict: policy.Verdict{RuleID: "B-602"},
	})
	if link != "http://127.0.0.1:8081/requests?new=budget" {
		t.Errorf("budget request link = %q, want the budget deep link", link)
	}
	if msg := HookBudgetMessage(HookBudgetStop{RuleID: "B-602", Reason: "spent"}, "http://127.0.0.1:8081"); strings.Contains(msg, "http") {
		t.Errorf("deny line %q carries a URL", msg)
	}
}
