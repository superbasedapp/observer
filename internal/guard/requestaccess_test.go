package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// longSession is the longest session id shape the hook lanes carry (a
// UUID); the deny line must still fit the dashboard's 200-byte error
// display with it.
const longSession = "0f6b9d2e-6c1a-4f53-9a8e-2b7d1c4e9f10"

// TestRequestAccessLine pins the G4 sentence (design §1.3) as revised by
// WINNODE2 16d: an org-locked block names the rule and tells the developer
// how to ask (the Observer dashboard's Requests page, or the CLI command),
// with NO URL, because the agent reads it in band and an agent treated the
// localhost link as an undocumented service; never more than 200 bytes (the
// node dashboard shows the first 200 of an error), one line, hyphens only,
// US spelling. The link itself is RequestAccessLink, for human surfaces.
func TestRequestAccessLine(t *testing.T) {
	t.Parallel()
	base := "http://127.0.0.1:8081"
	cases := []struct {
		name string
		av   ActionVerdict
		want []string
	}{
		{
			name: "the dashboard page and the command",
			av:   ActionVerdict{Kind: policy.KindShellExec, OrgLocked: true, RequestBase: base, Verdict: policy.Verdict{RuleID: "R-171"}},
			want: []string{
				"observer: R-171 blocked this command; your organization locks this rule.",
				"Observer dashboard, Requests page",
				"observer request access --rule R-171",
			},
		},
		{
			name: "a long kind noun still fits with the command",
			av:   ActionVerdict{Kind: policy.KindConfigChange, OrgLocked: true, RequestBase: base, Verdict: policy.Verdict{RuleID: "R-171"}},
			want: []string{"Observer dashboard, Requests page", "observer request access --rule R-171"},
		},
		{
			name: "no dashboard origin: the same instruction",
			av:   ActionVerdict{Kind: policy.KindFileAccess, OrgLocked: true, Verdict: policy.Verdict{RuleID: "R-152"}},
			want: []string{"Observer dashboard, Requests page", "observer request access --rule R-152"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := HumanBlockLine(tc.av, longSession)
			if len(got) > RequestAccessMaxBytes {
				t.Fatalf("line is %d bytes, over %d: %q", len(got), RequestAccessMaxBytes, got)
			}
			if strings.ContainsAny(got, "\n\r—–") || strings.Contains(got, "organisation") {
				t.Fatalf("copy rule broken: %q", got)
			}
			if strings.Contains(got, "http") || strings.Contains(got, "127.0.0.1") || strings.Contains(got, "/requests?") {
				t.Fatalf("an in-band line carries a URL an agent might call: %q", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("line %q missing %q", got, w)
				}
			}
		})
	}
}

// TestRequestAccessLink: the request form's link, for the human surfaces
// only, prefilled with the rule and the session (escaped), or the budget
// increase form for a budget stop; empty without a dashboard origin.
func TestRequestAccessLink(t *testing.T) {
	t.Parallel()
	base := "http://127.0.0.1:8081"
	locked := ActionVerdict{
		Kind: policy.KindShellExec, OrgLocked: true, RequestBase: base,
		Verdict: policy.Verdict{RuleID: "R-1&x=<y>"}, Input: ActionInput{SessionID: "s 3"},
	}
	if got := RequestAccessLink(locked); got != base+"/requests?rule=R-1%26x%3D%3Cy%3E&session=s+3" {
		t.Fatalf("org-locked link = %q", got)
	}
	budget := ActionVerdict{RequestBase: base, Category: string(policy.CategoryBudget), Verdict: policy.Verdict{RuleID: "B-602"}}
	if got := RequestAccessLink(budget); got != base+BudgetIncreaseRequestPath {
		t.Fatalf("budget link = %q", got)
	}
	locked.RequestBase = ""
	if got := RequestAccessLink(locked); got != "" {
		t.Fatalf("no origin: link = %q", got)
	}
	if got := RequestAccessLink(ActionVerdict{RequestBase: base, Verdict: policy.Verdict{RuleID: "R-1"}}); got != "" {
		t.Fatalf("nothing to request: link = %q", got)
	}
}

// TestRequestAccessLineFitsEveryKind: whatever the event kind, the line fits
// and still offers a way to ask, with no URL.
func TestRequestAccessLineFitsEveryKind(t *testing.T) {
	t.Parallel()
	kinds := []policy.EventKind{policy.EventKind("brand_new_kind")}
	for k := range blockedWhatByKind {
		kinds = append(kinds, k)
	}
	for _, k := range kinds {
		for _, base := range []string{"", "http://127.0.0.1:8081", "http://[::1]:65535"} {
			av := ActionVerdict{Kind: k, OrgLocked: true, RequestBase: base, Verdict: policy.Verdict{RuleID: "R-1234"}}
			got := HumanBlockLine(av, longSession)
			if len(got) > RequestAccessMaxBytes || !strings.Contains(got, "Ask your admin") || strings.Contains(got, "http") {
				t.Errorf("kind %s base %q: %d bytes %q", k, base, len(got), got)
			}
		}
	}
}

// TestRequestAccessStampedByTheGuard: the guard stamps its configured
// dashboard origin on every verdict it builds, so the desktop notification
// links the request form, while the hook reply names the dashboard page.
func TestRequestAccessStampedByTheGuard(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 11, orgOverridableBundleTOML)
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	g, err := New(Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile: fsMap(map[string]string{orgBundlePath: env}), OrgKeyPinHash: pin,
	})
	if err != nil {
		t.Fatal(err)
	}
	g.SetRequestAccessBase("http://127.0.0.1:9999")
	av, _ := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Target: "rm -rf ~", SessionID: "sA",
		ProjectRoot: "/home/u/proj", Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	})
	if av.RequestBase != "http://127.0.0.1:9999" {
		t.Fatalf("RequestBase = %q", av.RequestBase)
	}
	em := HumanizeEmission(Emission{Permission: "deny", Enforced: true, Reason: "rule reason"}, av, "sA")
	if !strings.HasPrefix(em.Reason, "observer: ") || !strings.Contains(em.Reason, "Requests page") || strings.Contains(em.Reason, "http") {
		t.Fatalf("emission does not lead with the request line, or carries a URL: %q", em.Reason)
	}
	if !strings.HasPrefix(RequestAccessLink(av), "http://127.0.0.1:9999/requests?rule=") {
		t.Fatalf("link = %q", RequestAccessLink(av))
	}
}

// TestPromptRequestAccessHint: an org-locked prompt block offers the same
// request path (the prompt gate's own house message appends it), no URL.
func TestPromptRequestAccessHint(t *testing.T) {
	t.Parallel()
	pv := PromptVerdict{
		Verdict: policy.Verdict{RuleID: "R-172", Decision: policy.DecisionDeny},
		Outcome: PromptOutcomeBlocked, OrgLocked: true, RequestBase: "http://127.0.0.1:8081",
	}
	got := PromptRequestAccessHint(pv, "s-9")
	if !strings.Contains(got, "Requests page") || strings.Contains(got, "http") || len(got) > RequestAccessMaxBytes {
		t.Fatalf("hint %q", got)
	}
	pv.OrgLocked = false
	if PromptRequestAccessHint(pv, "s-9") != "" {
		t.Fatal("an unlocked prompt block must not offer a request")
	}
}

// TestProxyPromptHouseMessage_OrgLockedOffersRequestAccess: the proxy
// lane's prompt block offers the same request line as the hook lane, inside
// the first 200 bytes, with no URL.
func TestProxyPromptHouseMessage_OrgLockedOffersRequestAccess(t *testing.T) {
	t.Parallel()
	pv := PromptVerdict{
		Verdict:   policy.Verdict{RuleID: "R-172", Decision: policy.DecisionDeny, Reason: "secret in prompt"},
		Outcome:   PromptOutcomeBlocked,
		Detectors: "github_pat", OrgLocked: true, RequestBase: "http://127.0.0.1:8081",
	}
	got := proxyPromptHouseMessage(pv, "s9")
	ask := "Observer dashboard, Requests page"
	i := strings.Index(got, ask)
	if i < 0 || i+len(ask) > RequestAccessMaxBytes || !strings.Contains(got, "secret in prompt") || strings.Contains(got, "http") {
		t.Fatalf("message %q", got)
	}
}
