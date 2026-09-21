package guard

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// orgOverridableBundle is a signed org bundle that escalates R-110 to
// a hard deny and R-150 to a deny the org marked OVERRIDABLE.
const orgOverridableBundleTOML = `
[[override]]
rule = "R-110"
decision = "deny"
enforce = true

[[override]]
rule = "R-150"
decision = "deny"
enforce = true
overridable = true
`

// TestEmissionDecision_OverridableDenySoftensToAsk pins the Track B
// emission table: one row per (decision, overridable, CanAsk,
// CanBlock). An overridable deny is emitted as an ask wherever the
// channel can prompt and degrades through the EXISTING ask rows
// everywhere else; a hard deny and every verdict on a node with no
// org bundle are untouched.
func TestEmissionDecision_OverridableDenySoftensToAsk(t *testing.T) {
	t.Parallel()
	full := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	noAsk := policy.Capabilities{PreExecution: true, CanBlock: true}
	postHoc := policy.Capabilities{}

	cases := []struct {
		name         string
		decision     policy.Decision
		overridable  bool
		caps         policy.Capabilities
		wantPerm     string
		wantDegraded string
		wantEnforced bool
	}{
		// Hard (non-overridable) rows: byte-identical to pre-wave.
		{"hard deny, ask channel", policy.DecisionDeny, false, full, "deny", "", true},
		{"hard deny, no-ask blocker", policy.DecisionDeny, false, noAsk, "deny", "", true},
		{"hard deny, post-hoc", policy.DecisionDeny, false, postHoc, "allow", "deny", false},
		{"hard ask, ask channel", policy.DecisionAsk, false, full, "ask", "", true},
		{"hard ask, no-ask blocker", policy.DecisionAsk, false, noAsk, "deny", "ask", true},
		{"hard ask, post-hoc", policy.DecisionAsk, false, postHoc, "allow", "ask", false},
		{"hard flag, ask channel", policy.DecisionFlag, false, full, "allow", "", false},
		{"hard allow, ask channel", policy.DecisionAllow, false, full, "allow", "", false},

		// Org-granted overridable rows.
		{"overridable deny asks on a prompting channel", policy.DecisionDeny, true, full, "ask", "", true},
		{"overridable deny stays deny on a no-ask blocker", policy.DecisionDeny, true, noAsk, "deny", "ask", true},
		{"overridable deny degrades post-hoc", policy.DecisionDeny, true, postHoc, "allow", "ask", false},
		// Overridable is only ever consulted for a DENY: an ask, flag
		// or allow resolves exactly as it always did.
		{"overridable ask unchanged", policy.DecisionAsk, true, full, "ask", "", true},
		{"overridable flag unchanged", policy.DecisionFlag, true, full, "allow", "", false},
		{"overridable allow unchanged", policy.DecisionAllow, true, full, "allow", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			em := ResolveEmission(policy.Verdict{
				Decision: tc.decision, RuleID: "R-X", Overridable: tc.overridable,
				Reason: "what happened.", Advice: "What to do.",
			}, tc.caps)
			if em.Permission != tc.wantPerm || em.DegradedFrom != tc.wantDegraded || em.Enforced != tc.wantEnforced {
				t.Errorf("emission = %+v, want perm=%s degraded=%q enforced=%v",
					em, tc.wantPerm, tc.wantDegraded, tc.wantEnforced)
			}
		})
	}
}

// TestParseOrgBundle_OverridableOnlyFromOrgLayer pins the authority:
// the org layer grants overridability, the user and project layers get
// a load issue and grant nothing.
func TestParseOrgBundle_OverridableOnlyFromOrgLayer(t *testing.T) {
	t.Parallel()
	body := `
[[override]]
rule = "R-110"
decision = "deny"
overridable = true
`
	for _, layer := range []string{layerOrg, layerUser, layerProject} {
		t.Run(layer, func(t *testing.T) {
			t.Parallel()
			pf, err := parsePolicyFile([]byte(body), layer)
			if err != nil {
				t.Fatalf("parsePolicyFile(%s): %v", layer, err)
			}
			if !pf.overrides[0].Overridable {
				t.Fatalf("%s: parser dropped the key (it must parse everywhere, merge decides)", layer)
			}
			var org, user, project *policyFile
			switch layer {
			case layerOrg:
				org = pf
			case layerUser:
				user = pf
			default:
				project = pf
			}
			_, overrides, issues := mergeLayers(org, user, project)
			granted := false
			for _, ov := range overrides {
				if ov.RuleID == "R-110" && ov.Overridable {
					granted = true
				}
			}
			if layer == layerOrg {
				if !granted {
					t.Fatalf("org layer must grant overridability, got overrides=%+v", overrides)
				}
				if len(issues) != 0 {
					t.Fatalf("org layer must lint clean, got %v", issues)
				}
				return
			}
			if granted {
				t.Fatalf("%s layer must NOT grant overridability", layer)
			}
			if len(issues) == 0 || !strings.Contains(issues[0], "`overridable` ignored") {
				t.Fatalf("%s layer must report a lint issue, got %v", layer, issues)
			}
		})
	}
}

// TestLint_OverridableOnUserLayerIsAnIssue pins that `observer guard
// lint` reports the same thing the loader records.
func TestLint_OverridableOnUserLayerIsAnIssue(t *testing.T) {
	t.Parallel()
	body := []byte("[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\noverridable = true\n")
	if problems := Lint(body, layerOrg); len(problems) != 0 {
		t.Fatalf("org layer must lint clean, got %v", problems)
	}
	problems := Lint(body, layerUser)
	if len(problems) == 0 || !strings.Contains(strings.Join(problems, "\n"), "`overridable` ignored") {
		t.Fatalf("user layer lint = %v, want an overridable issue", problems)
	}
}

// TestOrgOverrideStatus covers the one owner of the question across
// the three shapes: granted, locked, and no bundle at all.
func TestOrgOverrideStatus(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 9, orgOverridableBundleTOML)
	g := orgGuard(t, map[string]string{orgBundlePath: env}, pin)

	if ov, locked := g.OrgOverrideStatus("R-150"); !ov || locked {
		t.Fatalf("R-150 = (overridable=%v locked=%v), want (true,false)", ov, locked)
	}
	if ov, locked := g.OrgOverrideStatus("R-110"); ov || !locked {
		t.Fatalf("R-110 = (overridable=%v locked=%v), want (false,true)", ov, locked)
	}
	if ov, locked := g.OrgOverrideStatus(""); ov || locked {
		t.Fatalf("empty rule id = (%v,%v), want (false,false)", ov, locked)
	}
	posture := g.OrgOverridePosture()
	if !posture.OrgApplies || !posture.Overridable["R-150"] || posture.Overridable["R-110"] {
		t.Fatalf("OrgOverridePosture = %+v", posture)
	}
	if !posture.Named["R-110"] || !posture.Named["R-150"] {
		t.Fatalf("posture.Named must carry every rule the bundle names: %+v", posture.Named)
	}

	// No bundle: the whole mechanism is inert.
	plain := newTestGuard(t, guardCfg(), nil)
	if ov, locked := plain.OrgOverrideStatus("R-110"); ov || locked {
		t.Fatalf("un-enrolled node = (%v,%v), want (false,false)", ov, locked)
	}
	if p := plain.OrgOverridePosture(); p.OrgApplies || p.Overridable != nil || p.Named != nil {
		t.Fatalf("un-enrolled OrgOverridePosture = %+v, want the zero posture", p)
	}
}

// TestOrgLockedVerdict is the pure predicate table.
func TestOrgLockedVerdict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		decision    policy.Decision
		ruleID      string
		overridable bool
		orgLocks    bool
		want        bool
	}{
		{"rule not locked here", policy.DecisionDeny, "R-1", false, false, false},
		{"locked + not granted + deny", policy.DecisionDeny, "R-1", false, true, true},
		{"locked + not granted + ask", policy.DecisionAsk, "R-1", false, true, true},
		{"locked + granted", policy.DecisionDeny, "R-1", true, true, false},
		{"locked + flag never locked", policy.DecisionFlag, "R-1", false, true, false},
		{"locked + no rule id", policy.DecisionDeny, "", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := orgLockedVerdict(policy.Verdict{
				Decision: tc.decision, RuleID: tc.ruleID, Overridable: tc.overridable,
			}, tc.orgLocks)
			if got != tc.want {
				t.Errorf("orgLockedVerdict = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestHumanBlockLine covers the two sentences and the silence.
func TestHumanBlockLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		av          ActionVerdict
		sessionID   string
		wantContain []string
		wantAbsent  []string
		wantEmpty   bool
	}{
		{
			name: "overridable names the grant command",
			av: ActionVerdict{
				Kind: policy.KindShellExec, Overridable: true,
				Verdict: policy.Verdict{RuleID: "R-171"},
			},
			sessionID: "sess-1",
			wantContain: []string{
				"observer: R-171 blocked this command.",
				"The organization allows an override:",
				"observer guard approve R-171 --session sess-1",
			},
		},
		{
			// P2-7: a lane with no session id has nothing to scope a
			// grant to, so the line must NOT print a command the
			// developer cannot complete.
			name: "overridable with no session id points at the dashboard",
			av: ActionVerdict{
				Kind: policy.KindAPIRequest, Overridable: true,
				Verdict: policy.Verdict{RuleID: "R-172"},
			},
			wantContain: []string{
				"blocked this request.",
				"no session id",
				"Observer dashboard Security page",
			},
			wantAbsent: []string{"observer guard approve", "<session-id>", "--session"},
		},
		{
			name: "org locked says ask your admin",
			av: ActionVerdict{
				Kind: policy.KindFileAccess, OrgLocked: true,
				Verdict: policy.Verdict{RuleID: "R-152"},
			},
			sessionID:   "sess-2",
			wantContain: []string{"blocked this file access.", "locked by your organization; ask your admin."},
		},
		{
			name: "unknown kind falls back",
			av: ActionVerdict{
				Kind: policy.EventKind("something_new"), OrgLocked: true,
				Verdict: policy.Verdict{RuleID: "R-1"},
			},
			wantContain: []string{"blocked this action."},
		},
		{
			name:      "no org bundle stays silent",
			av:        ActionVerdict{Kind: policy.KindShellExec, Verdict: policy.Verdict{RuleID: "R-110"}},
			wantEmpty: true,
		},
		{
			name:      "no rule id stays silent",
			av:        ActionVerdict{Kind: policy.KindShellExec, Overridable: true},
			wantEmpty: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := HumanBlockLine(tc.av, tc.sessionID)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("want empty, got %q", got)
				}
				return
			}
			for _, want := range tc.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("line %q missing %q", got, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("line %q must not contain %q", got, absent)
				}
			}
			if strings.Contains(got, "organisation") {
				t.Errorf("user-facing copy uses the US spelling: %q", got)
			}
			if strings.ContainsAny(got, "—–") {
				t.Errorf("line must use hyphens only: %q", got)
			}
		})
	}
}

// TestHumanizeEmission leads a blocking reason with the human line and
// leaves everything else alone.
func TestHumanizeEmission(t *testing.T) {
	t.Parallel()
	av := ActionVerdict{
		Kind: policy.KindShellExec, Overridable: true,
		Verdict: policy.Verdict{RuleID: "R-171", Decision: policy.DecisionDeny},
	}
	blocking := Emission{Permission: "deny", Enforced: true, Reason: "agent text."}
	got := HumanizeEmission(blocking, av, "s1")
	if !strings.HasPrefix(got.Reason, "observer: R-171 blocked this command.") {
		t.Fatalf("human line must LEAD: %q", got.Reason)
	}
	if !strings.HasSuffix(got.Reason, "agent text.") {
		t.Fatalf("agent text must follow: %q", got.Reason)
	}
	// Non-blocking emission: untouched.
	allow := Emission{Permission: "allow", Reason: "agent text."}
	if HumanizeEmission(allow, av, "s1").Reason != "agent text." {
		t.Fatal("a non-blocking emission must not gain a human line")
	}
	// No org bundle: untouched.
	plainAV := ActionVerdict{Kind: policy.KindShellExec, Verdict: policy.Verdict{RuleID: "R-171"}}
	if HumanizeEmission(blocking, plainAV, "s1").Reason != "agent text." {
		t.Fatal("an individual node's reason must stay byte-identical")
	}
}

// TestAlertsRegardlessOfSeverity is the one-row exception table.
func TestAlertsRegardlessOfSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		av   ActionVerdict
		want bool
	}{
		{"enforced overridable deny", ActionVerdict{
			Enforced: true, Overridable: true,
			Verdict: policy.Verdict{Decision: policy.DecisionDeny},
		}, true},
		{"unenforced overridable deny", ActionVerdict{
			Overridable: true, Verdict: policy.Verdict{Decision: policy.DecisionDeny},
		}, false},
		{"enforced hard deny keeps the gate", ActionVerdict{
			Enforced: true, Verdict: policy.Verdict{Decision: policy.DecisionDeny},
		}, false},
		{"enforced overridable ask keeps the gate", ActionVerdict{
			Enforced: true, Overridable: true,
			Verdict: policy.Verdict{Decision: policy.DecisionAsk},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := alertsRegardlessOfSeverity(tc.av); got != tc.want {
				t.Errorf("alertsRegardlessOfSeverity = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestApprovals_OrgLockGate pins Track B item 3 on the EVALUATION
// side: under an org bundle a pre-existing grant is INERT for a rule
// the organization did not mark overridable, and the refusal is
// recorded on the verdict instead of silently applied.
func TestApprovals_OrgLockGate(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 11, orgOverridableBundleTOML)
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	g, err := New(Options{
		Config:            cfg,
		Home:              "/home/u",
		KnownProjectRoots: []string{"/home/u/proj"},
		ReadFile:          fsMap(map[string]string{orgBundlePath: env}),
		OrgKeyPinHash:     pin,
	})
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	// Every rule has a grant: only an org-granted one may use it.
	g.SetApprovalLookup(func(string, string, string) bool { return true })

	// R-101 is a built-in deny the org bundle never marked
	// overridable, so the bundle's mere presence locks it.
	av, _ := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	})
	if av.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("org-locked verdict = %v, want the grant to be inert (deny)", av.Verdict.Decision)
	}
	if av.DegradedFrom == "approved" {
		t.Error("an org-locked rule must never report an applied approval")
	}
	if !strings.Contains(av.Verdict.Reason, "org_locked") {
		t.Errorf("reason must record the refusal: %q", av.Verdict.Reason)
	}
	if !av.OrgLocked || av.Overridable {
		t.Errorf("stamp = (overridable=%v locked=%v), want (false,true)", av.Overridable, av.OrgLocked)
	}
	// The same grant on the SAME node still works for the rule the
	// organization DID mark overridable.
	if ov, locked := g.OrgOverrideStatus("R-150"); !ov || locked {
		t.Fatalf("R-150 = (overridable=%v locked=%v), want the org grant to stand", ov, locked)
	}
}

// TestNoOrgBundle_ByteIdenticalEmission is the individual-node
// invariant: with NO org bundle loaded every Track B field is zero and
// the emission path is exactly the pre-wave one.
func TestNoOrgBundle_ByteIdenticalEmission(t *testing.T) {
	t.Parallel()
	cfg := guardCfg()
	cfg.Mode = "enforce"
	g := newTestGuard(t, cfg, nil)
	caps := policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true}
	av, worthy := g.EvaluateHook(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/home/u/proj",
		Caps: caps,
	})
	if !worthy || av.Verdict.Decision != policy.DecisionDeny {
		t.Fatalf("verdict = %+v, want an enforced deny", av.Verdict)
	}
	if av.Overridable || av.OrgLocked || av.Verdict.Overridable {
		t.Fatalf("individual node stamped Track B state: %+v", av)
	}
	em := ResolveEmission(av.Verdict, caps)
	if em.Permission != "deny" || em.DegradedFrom != "" {
		t.Fatalf("emission = %+v, want the pre-wave hard deny", em)
	}
	if HumanizeEmission(em, av, "sA").Reason != em.Reason {
		t.Fatal("individual-node reason must stay byte-identical")
	}
	if HumanBlockLine(av, "sA") != "" {
		t.Fatal("individual node must produce no human line")
	}
}

// TestOrgLockBlastRadius is the adversarial-review P2-8 table: how far
// an org bundle's lock reaches is a TENANCY question crossed with
// whether the bundle NAMES the rule, and only then with the per-rule
// `overridable` grant.
//
// The bundle (orgOverridableBundleTOML) names exactly R-110 (hard) and
// R-150 (overridable); R-101 is a built-in the bundle never mentions.
func TestOrgLockBlastRadius(t *testing.T) {
	t.Parallel()
	// tenancy: nil = unresolved (a hook process), else the answer the
	// composition wired.
	individual := func() bool { return false }
	managed := func() bool { return true }

	cases := []struct {
		name            string
		tenancy         func() bool
		ruleID          string
		wantOverridable bool
		wantLocked      bool
	}{
		// Managed: the organization is authoritative over the whole
		// catalog, named or not.
		{"managed, named hard rule", managed, "R-110", false, true},
		{"managed, named overridable rule", managed, "R-150", true, false},
		{"managed, rule the bundle never names", managed, "R-101", false, true},

		// Individual: the bundle is a FLOOR over what it names.
		{"individual, named hard rule", individual, "R-110", false, true},
		{"individual, named overridable rule", individual, "R-150", true, false},
		{"individual, rule the bundle never names", individual, "R-101", false, false},

		// Unresolved tenancy keeps the widest (pre-fix) lock rather
		// than widening what a developer may approve.
		{"unresolved, named hard rule", nil, "R-110", false, true},
		{"unresolved, named overridable rule", nil, "R-150", true, false},
		{"unresolved, rule the bundle never names", nil, "R-101", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, 12, orgOverridableBundleTOML)
			g := orgGuard(t, map[string]string{orgBundlePath: env}, pin)
			g.SetManagedTenancy(tc.tenancy)

			ov, locked := g.OrgOverrideStatus(tc.ruleID)
			if ov != tc.wantOverridable || locked != tc.wantLocked {
				t.Fatalf("OrgOverrideStatus(%s) = (overridable=%v locked=%v), want (%v,%v)",
					tc.ruleID, ov, locked, tc.wantOverridable, tc.wantLocked)
			}
			// The bulk posture must agree with the single-row answer
			// row for row - it is the same owner, one snapshot.
			pov, plocked := g.OrgOverridePosture().For(tc.ruleID)
			if pov != ov || plocked != locked {
				t.Fatalf("posture.For(%s) = (%v,%v), disagrees with OrgOverrideStatus (%v,%v)",
					tc.ruleID, pov, plocked, ov, locked)
			}
		})
	}
}

// TestApprovals_BlastRadiusAtEvaluation is the same table one layer
// down: a local grant for a rule the org bundle never names APPLIES on
// an individual node and is INERT on a managed one.
func TestApprovals_BlastRadiusAtEvaluation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		tenancy     func() bool
		wantDecided policy.Decision
		wantApplied bool
	}{
		{"individual node keeps its own approvals", func() bool { return false }, policy.DecisionFlag, true},
		{"managed node is org-authoritative", func() bool { return true }, policy.DecisionDeny, false},
		{"unresolved tenancy stays conservative", nil, policy.DecisionDeny, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, 13, orgOverridableBundleTOML)
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			g, err := New(Options{
				Config:            cfg,
				Home:              "/home/u",
				KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile:          fsMap(map[string]string{orgBundlePath: env}),
				OrgKeyPinHash:     pin,
				ManagedTenancy:    tc.tenancy,
			})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			g.SetApprovalLookup(func(string, string, string) bool { return true })

			// R-101 (rm -rf ~) is a built-in the bundle never names.
			av, _ := g.EvaluateHook(policy.Event{
				Kind: policy.KindShellExec, ActionType: "run_command",
				Target: "rm -rf ~", SessionID: "sA", ProjectRoot: "/home/u/proj",
				Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
			})
			if av.Verdict.Decision != tc.wantDecided {
				t.Fatalf("decision = %v, want %v (reason %q)", av.Verdict.Decision, tc.wantDecided, av.Verdict.Reason)
			}
			if applied := av.DegradedFrom == "approved"; applied != tc.wantApplied {
				t.Fatalf("approval applied = %v, want %v", applied, tc.wantApplied)
			}
			if av.OrgLocked == tc.wantApplied {
				t.Fatalf("OrgLocked = %v, want %v", av.OrgLocked, !tc.wantApplied)
			}
		})
	}
}

// TestApprovals_ProjectScopeOnALaneWithNoProjectRoot pins the
// adversarial-review P2-7 fix: the proxy lane builds its events from a
// request body and carries no ProjectRoot, so without the injected
// session-to-project resolver a scope='project' grant can never match
// there. The resolver is consulted ONLY when the event has no root of
// its own.
func TestApprovals_ProjectScopeOnALaneWithNoProjectRoot(t *testing.T) {
	t.Parallel()
	const root = "/home/u/proj"
	wantHash := HashProjectRoot(root)

	newGuard := func(t *testing.T, resolver SessionProjectRootLookup) (*Guard, *[]string) {
		t.Helper()
		cfg := guardCfg()
		cfg.Mode = "enforce"
		g := newTestGuard(t, cfg, nil)
		seen := &[]string{}
		g.SetApprovalLookup(func(_, _, rootHash string) bool {
			*seen = append(*seen, rootHash)
			return rootHash == wantHash
		})
		if resolver != nil {
			g.SetSessionProjectRootLookup(resolver)
		}
		return g, seen
	}

	// A proxy-shaped event: a session id, no ProjectRoot.
	proxyEvent := func() *policy.Event {
		return &policy.Event{Kind: policy.KindAPIRequest, SessionID: "sA"}
	}
	blocking := policy.Verdict{Decision: policy.DecisionDeny, RuleID: "R-172"}

	t.Run("unwired resolver still asks with an empty hash", func(t *testing.T) {
		t.Parallel()
		g, seen := newGuard(t, nil)
		v, approved := g.applyApprovals(blocking, proxyEvent())
		if approved || v.Decision != policy.DecisionDeny {
			t.Fatalf("want the pre-fix behaviour (no match), got (%v, approved=%v)", v.Decision, approved)
		}
		if len(*seen) != 1 || (*seen)[0] != "" {
			t.Fatalf("lookup hashes = %v, want one empty hash", *seen)
		}
	})

	t.Run("wired resolver matches a project grant", func(t *testing.T) {
		t.Parallel()
		calls := 0
		g, seen := newGuard(t, func(sessionID string) string {
			calls++
			if sessionID != "sA" {
				t.Errorf("resolver got session %q", sessionID)
			}
			return root
		})
		v, approved := g.applyApprovals(blocking, proxyEvent())
		if !approved || v.Decision != policy.DecisionFlag {
			t.Fatalf("want the grant to apply, got (%v, approved=%v)", v.Decision, approved)
		}
		if calls != 1 || len(*seen) != 1 || (*seen)[0] != wantHash {
			t.Fatalf("calls=%d hashes=%v, want one resolve to %s", calls, *seen, wantHash)
		}
	})

	t.Run("an event with its own root never consults the resolver", func(t *testing.T) {
		t.Parallel()
		g, _ := newGuard(t, func(string) string {
			t.Error("hook-lane event must not consult the session resolver")
			return ""
		})
		ev := proxyEvent()
		ev.ProjectRoot = root
		if _, approved := g.applyApprovals(blocking, ev); !approved {
			t.Fatal("the event's own root must resolve the grant")
		}
	})

	t.Run("a non-blocking verdict never consults anything", func(t *testing.T) {
		t.Parallel()
		g, seen := newGuard(t, func(string) string {
			t.Error("the allow path must not pay the resolve")
			return ""
		})
		if _, approved := g.applyApprovals(policy.Verdict{Decision: policy.DecisionFlag, RuleID: "R-172"}, proxyEvent()); approved {
			t.Fatal("a flag verdict is not an approval")
		}
		if len(*seen) != 0 {
			t.Fatalf("lookup ran on a non-blocking verdict: %v", *seen)
		}
	})
}
