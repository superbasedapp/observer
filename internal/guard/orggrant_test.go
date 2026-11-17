package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// fakeGrants is a scripted OrgGrantClaim: it records every query and
// answers from a fixed result, counting consumptions.
type fakeGrants struct {
	mu       sync.Mutex
	res      OrgGrantResult
	queries  []OrgGrantQuery
	consumed int
}

func (f *fakeGrants) claim(q OrgGrantQuery) OrgGrantResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if q.Consume && f.res.OK {
		f.consumed++
	}
	return f.res
}

func enforceGuard(t *testing.T) *Guard {
	t.Helper()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g, err := New(Options{
		Config: cfg, Home: "/home/u",
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var (
	askCaps      = policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	denyOnlyCaps = policy.Capabilities{PreExecution: true, CanBlock: true}
)

func rmEvent(caps policy.Capabilities) policy.Event {
	return policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command", Tool: "claude-code",
		Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/home/u/proj", Caps: caps,
	}
}

func exemptResult(id int64) OrgGrantResult {
	return OrgGrantResult{OK: true, GrantID: id, Effect: OrgGrantEffectExempt, ExpiresAtNs: time.Date(2026, 10, 4, 18, 0, 0, 0, time.UTC).UnixNano(), UsesLeft: -1}
}

// TestOrgGrant_VocabularyMatchesAccessGrant pins the guard's own copies of
// the access-grant vocabulary (guard never imports the node's grant
// package) against the canonical constants.
func TestOrgGrant_VocabularyMatchesAccessGrant(t *testing.T) {
	pairs := [][2]string{
		{OrgGrantLaneTool, accessgrant.LaneTool},
		{OrgGrantLanePrompt, accessgrant.LanePrompt},
		{OrgGrantLaneProxy, accessgrant.LaneProxy},
		{OrgGrantEffectExempt, orgcontract.AccessGrantEffectExempt},
		{OrgGrantEffectSoften, orgcontract.AccessGrantEffectSoften},
		{policy.DecisionAsk.String(), accessgrant.DecisionAsk},
		{policy.DecisionDeny.String(), accessgrant.DecisionDeny},
	}
	for _, p := range pairs {
		if p[0] != p[1] {
			t.Errorf("guard %q != accessgrant %q", p[0], p[1])
		}
	}
}

// TestOrgGrant_ExemptLiftsAndRecords: an exempt grant turns an enforced
// deny into an allow-by-grant (FLAG), recorded with the grant id and the
// org_grant marker, consuming exactly one use; the query names the rule,
// the lane, the command class, the operand hash and the project hash.
func TestOrgGrant_ExemptLiftsAndRecords(t *testing.T) {
	t.Parallel()
	g := enforceGuard(t)
	fg := &fakeGrants{res: exemptResult(12)}
	g.SetOrgGrantClaim(fg.claim)
	av, worthy := g.EvaluateHook(rmEvent(askCaps))
	if !worthy || av.Verdict.Decision != policy.DecisionFlag {
		t.Fatalf("verdict = %+v, want flag (allowed by grant)", av.Verdict)
	}
	if av.DegradedFrom != DegradedFromOrgGrant || av.GrantID != 12 {
		t.Fatalf("degraded_from=%q grant=%d, want org_grant / 12", av.DegradedFrom, av.GrantID)
	}
	if !strings.Contains(av.Verdict.Reason, "G-12") || !strings.Contains(av.Verdict.Reason, "2026-10-04 18:00 UTC") {
		t.Errorf("reason does not name the grant and its end: %q", av.Verdict.Reason)
	}
	if fg.consumed != 1 {
		t.Fatalf("consumed %d uses, want exactly 1", fg.consumed)
	}
	sum := sha256.Sum256([]byte("rm -rf ~"))
	q := fg.queries[len(fg.queries)-1]
	want := OrgGrantQuery{
		RuleID: "R-101", Lane: OrgGrantLaneTool, CommandClass: av.Category + "/" + string(policy.KindShellExec),
		OperandHash: hex.EncodeToString(sum[:]), ProjectRootHash: HashProjectRoot("/home/u/proj"),
		Decision: "deny", Consume: true,
	}
	if q != want {
		t.Fatalf("query = %+v\nwant    %+v", q, want)
	}
	if em := ResolveEmission(av.Verdict, askCaps); em.Permission != "allow" {
		t.Fatalf("emission = %+v, want allow", em)
	}
}

// TestOrgGrant_OrderAndInputs walks the precedence table (design §3.2).
func TestOrgGrant_OrderAndInputs(t *testing.T) {
	t.Parallel()
	t.Run("org grant wins over a local approval", func(t *testing.T) {
		g := enforceGuard(t)
		g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
		g.SetOrgGrantClaim((&fakeGrants{res: exemptResult(3)}).claim)
		av, _ := g.EvaluateHook(rmEvent(askCaps))
		if av.DegradedFrom != DegradedFromOrgGrant || av.GrantID != 3 {
			t.Fatalf("got %q / %d", av.DegradedFrom, av.GrantID)
		}
	})
	t.Run("no grant falls through to the local approval", func(t *testing.T) {
		g := enforceGuard(t)
		g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
		g.SetOrgGrantClaim((&fakeGrants{}).claim)
		av, _ := g.EvaluateHook(rmEvent(askCaps))
		if av.DegradedFrom != "approved" || av.GrantID != 0 {
			t.Fatalf("got %q / %d", av.DegradedFrom, av.GrantID)
		}
	})
	t.Run("unverified cache enforces and says so", func(t *testing.T) {
		g := enforceGuard(t)
		g.SetOrgGrantClaim((&fakeGrants{res: OrgGrantResult{Unverified: true}}).claim)
		av, _ := g.EvaluateHook(rmEvent(askCaps))
		if av.Verdict.Decision != policy.DecisionDeny || av.GrantID != 0 {
			t.Fatalf("got %+v", av.Verdict)
		}
		if !strings.Contains(av.Verdict.Reason, "could not be verified") {
			t.Errorf("reason: %q", av.Verdict.Reason)
		}
	})
	t.Run("observe mode never asks", func(t *testing.T) {
		cfg := guardCfg()
		g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
		if err != nil {
			t.Fatal(err)
		}
		fg := &fakeGrants{res: exemptResult(3)}
		g.SetOrgGrantClaim(fg.claim)
		_, _ = g.EvaluateHook(rmEvent(askCaps))
		if len(fg.queries) != 0 {
			t.Fatalf("a flag verdict consulted the grants %d times", len(fg.queries))
		}
	})
	t.Run("the post-hoc watcher lane never consumes a grant", func(t *testing.T) {
		g := enforceGuard(t)
		fg := &fakeGrants{res: exemptResult(3)}
		g.SetOrgGrantClaim(fg.claim)
		out := g.EvaluateActions([]ActionInput{{
			ActionID: 1, SessionID: "sA", ProjectRoot: "/home/u/proj", Tool: "claude-code",
			ActionType: "run_command", Target: "rm -rf ~", Timestamp: time.Now(), Success: true,
		}})
		if len(fg.queries) != 0 {
			t.Fatalf("the watcher lane consulted grants: %+v", fg.queries)
		}
		for _, av := range out {
			if av.GrantID != 0 {
				t.Fatalf("watcher row carries a grant: %+v", av)
			}
		}
	})
}

// TestOrgGrant_LockedRule: on a rule the org bundle locks, the query says so;
// a grant the claim refuses for the lock leaves the hard deny with the
// request text, and a lock-override grant lifts it and clears the lock
// stamp (the org itself spoke).
func TestOrgGrant_LockedRule(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 11, orgOverridableBundleTOML)
	mk := func(res OrgGrantResult) (*Guard, *fakeGrants) {
		cfg := guardCfgOrg()
		cfg.Mode = "enforce"
		g, err := New(Options{
			Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
			ReadFile: fsMap(map[string]string{orgBundlePath: env}), OrgKeyPinHash: pin,
		})
		if err != nil {
			t.Fatal(err)
		}
		fg := &fakeGrants{res: res}
		g.SetOrgGrantClaim(fg.claim)
		return g, fg
	}
	g, fg := mk(OrgGrantResult{LockRefused: true})
	av, _ := g.EvaluateHook(rmEvent(askCaps))
	if !fg.queries[0].RuleLocked {
		t.Fatal("the query did not carry the org lock")
	}
	if av.Verdict.Decision != policy.DecisionDeny || !av.OrgLocked || av.GrantID != 0 {
		t.Fatalf("lock-refused grant: %+v locked=%v", av.Verdict, av.OrgLocked)
	}
	if !strings.Contains(av.Verdict.Reason, "locked-rule approval") {
		t.Errorf("reason does not say why the grant did not apply: %q", av.Verdict.Reason)
	}
	g2, _ := mk(exemptResult(21))
	av2, _ := g2.EvaluateHook(rmEvent(askCaps))
	if av2.Verdict.Decision != policy.DecisionFlag || av2.GrantID != 21 || av2.OrgLocked {
		t.Fatalf("lock-override grant: %+v grant=%d locked=%v", av2.Verdict, av2.GrantID, av2.OrgLocked)
	}
}

// TestOrgGrant_Soften: a soften grant turns a deny into an ask. On a channel
// that can ask, the ask is the use. On a deny-only channel the call is
// blocked with the confirm text and NO use is counted; the developer's
// confirmation (a local approval for the rule) then lets the retry through,
// and THAT counts the use.
func TestOrgGrant_Soften(t *testing.T) {
	t.Parallel()
	soften := OrgGrantResult{OK: true, GrantID: 30, Effect: OrgGrantEffectSoften, UsesLeft: 1}
	t.Run("native ask", func(t *testing.T) {
		g := enforceGuard(t)
		fg := &fakeGrants{res: soften}
		g.SetOrgGrantClaim(fg.claim)
		av, _ := g.EvaluateHook(rmEvent(askCaps))
		if av.Verdict.Decision != policy.DecisionAsk || av.GrantID != 30 || av.DegradedFrom != DegradedFromOrgGrantSoften {
			t.Fatalf("got %+v grant=%d from=%q", av.Verdict, av.GrantID, av.DegradedFrom)
		}
		if fg.consumed != 1 {
			t.Fatalf("consumed %d, want 1", fg.consumed)
		}
		if em := ResolveEmission(av.Verdict, askCaps); em.Permission != "ask" {
			t.Fatalf("emission %+v, want a native ask", em)
		}
	})
	t.Run("deny-only host, then the confirmed retry", func(t *testing.T) {
		g := enforceGuard(t)
		confirmed := false
		g.SetApprovalLookup(func(string, string, string) (bool, error) { return confirmed, nil })
		fg := &fakeGrants{res: soften}
		g.SetOrgGrantClaim(fg.claim)
		av, _ := g.EvaluateHook(rmEvent(denyOnlyCaps))
		if av.Verdict.Decision != policy.DecisionAsk || av.GrantID != 0 || fg.consumed != 0 {
			t.Fatalf("presentation: %+v grant=%d consumed=%d", av.Verdict, av.GrantID, fg.consumed)
		}
		em := ExplainDegradedAsk(ResolveEmission(av.Verdict, denyOnlyCaps), av, "sA")
		if em.Permission != "deny" || !strings.Contains(em.Reason, "observer guard approve R-101 --session sA") {
			t.Fatalf("deny-only emission: %+v", em)
		}
		confirmed = true
		av2, _ := g.EvaluateHook(rmEvent(denyOnlyCaps))
		if av2.Verdict.Decision != policy.DecisionFlag || av2.GrantID != 30 || fg.consumed != 1 {
			t.Fatalf("confirmed retry: %+v grant=%d consumed=%d", av2.Verdict, av2.GrantID, fg.consumed)
		}
	})
}

// TestOrgGrant_Prompt: an exempt grant lifts a prompt block to a warning
// (one use); a soften grant turns a block into the ask-once confirm, and
// only the confirming re-entry counts the use.
func TestOrgGrant_Prompt(t *testing.T) {
	t.Parallel()
	ev := promptEvent("s1", nil, []policy.PIIFinding{creditCardFinding("h1")})
	t.Run("exempt", func(t *testing.T) {
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		fg := &fakeGrants{res: exemptResult(40)}
		g.SetOrgGrantClaim(fg.claim)
		pv := g.EvaluatePrompt(ev)
		if pv.Verdict.Decision != policy.DecisionFlag || pv.GrantID != 40 || fg.consumed != 1 {
			t.Fatalf("got %+v consumed=%d", pv, fg.consumed)
		}
		if fg.queries[0].Lane != OrgGrantLanePrompt {
			t.Fatalf("lane = %q", fg.queries[0].Lane)
		}
		av := g.ActionVerdictFromPrompt(pv, ResolveEmission(pv.Verdict, ev.Caps), ActionInput{SessionID: "s1"})
		if av.GrantID != 40 {
			t.Fatalf("bridge dropped the grant: %+v", av)
		}
	})
	t.Run("soften", func(t *testing.T) {
		store := newMemPromptStore()
		g := newTestGuard(t, promptCfg("enforce", "block", nil), nil)
		g.SetPromptReconsiderStore(store.funcs())
		fg := &fakeGrants{res: OrgGrantResult{OK: true, GrantID: 41, Effect: OrgGrantEffectSoften, UsesLeft: 1}}
		g.SetOrgGrantClaim(fg.claim)
		first := g.EvaluatePrompt(ev)
		if first.Verdict.Decision != policy.DecisionAsk || first.GrantID != 0 || fg.consumed != 0 {
			t.Fatalf("first: %+v consumed=%d", first, fg.consumed)
		}
		second := g.EvaluatePrompt(ev)
		if second.Outcome != PromptOutcomeConfirmed || second.Verdict.Decision != policy.DecisionFlag || second.GrantID != 41 || fg.consumed != 1 {
			t.Fatalf("re-entry: %+v consumed=%d", second, fg.consumed)
		}
	})
}

// TestOrgGrant_MissSaysWhy walks the "no grant applied" table (grantNoteRules):
// whenever a grant question changes nothing for a reason other than "no
// grant covers this call", the verdict stays enforced AND its reason says
// why. A silent miss is what sent a developer holding a perpetual grant back
// to request the same grant again (operator report 2026-11-13).
func TestOrgGrant_MissSaysWhy(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 400)
	cases := []struct {
		name string
		res  OrgGrantResult
		want string // "" = the reason carries no org-grants note
		not  string
	}{
		{"no grant at all", OrgGrantResult{}, "", "[org grants:"},
		{"the grant list could not be read", OrgGrantResult{Failed: "context deadline exceeded"}, "could not be consulted (context deadline exceeded)", ""},
		{"a long failure text is bounded", OrgGrantResult{Failed: long}, strings.Repeat("x", maxGrantFailureLen) + "...)", long},
		{"a failure outranks every other detail", OrgGrantResult{Failed: "busy", Unverified: true, ScopeMissID: 8}, "could not be consulted (busy)", "G-8"},
		{"the cache does not verify", OrgGrantResult{Unverified: true}, "could not be verified", ""},
		{"the grant lacks the lock override", OrgGrantResult{LockRefused: true}, "locked-rule approval", ""},
		{"a grant for the rule is pinned to another scope", OrgGrantResult{ScopeMissID: 8}, "G-8 covers this rule only for another project, command or lane", ""},
	}
	for _, c := range cases {
		g := enforceGuard(t)
		fg := &fakeGrants{res: c.res}
		g.SetOrgGrantClaim(fg.claim)
		av, _ := g.EvaluateHook(rmEvent(askCaps))
		if av.Verdict.Decision != policy.DecisionDeny || av.GrantID != 0 || av.DegradedFrom != "" {
			t.Errorf("%s: verdict = %+v grant=%d degraded=%q, want the deny to stand", c.name, av.Verdict, av.GrantID, av.DegradedFrom)
		}
		if fg.consumed != 0 {
			t.Errorf("%s: a use was counted", c.name)
		}
		if c.want != "" && !strings.Contains(av.Verdict.Reason, c.want) {
			t.Errorf("%s: reason %q does not say %q", c.name, av.Verdict.Reason, c.want)
		}
		if c.not != "" && strings.Contains(av.Verdict.Reason, c.not) {
			t.Errorf("%s: reason %q must not carry %q", c.name, av.Verdict.Reason, c.not)
		}
	}
}

// TestOrgGrant_SessionSharesThePeekAndTheClaim: with a session wired (the
// hook process), the peek and the claim of one verdict go through ONE
// conversation, ended once, and the grant still applies; a verdict whose
// peek finds nothing ends its conversation too.
func TestOrgGrant_SessionSharesThePeekAndTheClaim(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		res          OrgGrantResult
		wantQuestion int
		wantGrant    int64
	}{
		{name: "granted: peek and claim, one conversation", res: exemptResult(12), wantQuestion: 2, wantGrant: 12},
		{name: "no grant: the peek only, one conversation", res: OrgGrantResult{}, wantQuestion: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			g := enforceGuard(t)
			fg := &fakeGrants{res: tc.res}
			sessions, ended := 0, 0
			g.SetOrgGrantSession(func() (OrgGrantClaim, func()) {
				sessions++
				return fg.claim, func() { ended++ }
			})
			av, _ := g.EvaluateHook(rmEvent(askCaps))
			if av.GrantID != tc.wantGrant {
				t.Errorf("grant = %d, want %d", av.GrantID, tc.wantGrant)
			}
			if sessions != 1 || ended != 1 || len(fg.queries) != tc.wantQuestion {
				t.Errorf("sessions %d ended %d questions %d, want 1, 1, %d", sessions, ended, len(fg.queries), tc.wantQuestion)
			}
		})
	}
}
