package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// tamperEnvelope edits the bundle TOML inside a signed envelope and keeps
// its version and signature, which is the audit's b2 tamper: the signature
// no longer verifies.
func tamperEnvelope(t *testing.T, env string) string {
	t.Helper()
	out := strings.Replace(env, "R-110", "R-111", 1)
	if out == env {
		t.Fatal("tamperEnvelope: the envelope did not change")
	}
	return out
}

// rmRfEvent is the a3b chain's tool call.
func rmRfEvent() policy.Event {
	return policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "rm -rf /", SessionID: "sA", ProjectRoot: "/home/u/proj",
		Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
	}
}

// TestOrgBundleTamperFailsClosed pins T-844 (audit row a3b): a cached org
// bundle that exists but no longer verifies must not drop the org layer and
// with it the org lock on local approvals. Every row has a local approval
// for every rule (the developer's `observer guard approve R-101 --global`).
func TestOrgBundleTamperFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		// lock is the daemon's MAC'd org lock as config.Load hands it on
		// GuardConfig.Lock (zero = no valid lock).
		lock         func(env, pin string) config.GuardOrgLock
		tenancy      func() bool
		tamper       bool
		wantDecision policy.Decision
		wantLocked   bool
		wantLKG      bool
	}{
		{
			"managed, intact bundle: the approval is inert", managedLock, nil, false,
			policy.DecisionDeny, true, false,
		},
		{
			"managed, tampered bundle, last verified copy enforces", managedLock, nil, true,
			policy.DecisionDeny, true, true,
		},
		{
			"no lock, tampered bundle, tenancy unresolved: every rule locked", noLock, nil, true,
			policy.DecisionDeny, true, false,
		},
		{
			"no lock, tampered bundle, managed tenancy wired: every rule locked", noLock, func() bool { return true }, true,
			policy.DecisionDeny, true, false,
		},
		{
			"individual lock, tampered bundle: the local approval stands", individualLock, nil, true,
			policy.DecisionFlag, false, true,
		},
		{
			"individual tenancy, tampered bundle, no copy: the local approval stands", noLock, func() bool { return false }, true,
			policy.DecisionFlag, false, false,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env, pin := signedEnvelope(t, int64(900+i), orgOverridableBundleTOML)
			onDisk := env
			if tc.tamper {
				onDisk = tamperEnvelope(t, env)
			}
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			cfg.Lock = tc.lock(env, pin)
			opts := Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile: fsMap(map[string]string{orgBundlePath: onDisk}),
			}
			if tc.lock(env, pin).State == "" && !tc.tamper {
				opts.OrgKeyPinHash = pin
			}
			opts.ManagedTenancy = tc.tenancy
			g, err := New(opts)
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
			av, _ := g.EvaluateHook(rmRfEvent())
			if av.Verdict.Decision != tc.wantDecision {
				t.Fatalf("rm -rf / = %v (%s), want %v (issues %v)", av.Verdict.Decision, av.Verdict.Reason, tc.wantDecision, g.LoadIssues())
			}
			if av.OrgLocked != tc.wantLocked {
				t.Fatalf("OrgLocked = %v, want %v", av.OrgLocked, tc.wantLocked)
			}
			st := g.OrgLockStatus()
			if st.LastVerifiedInUse != tc.wantLKG || st.BundleTampered != tc.tamper {
				t.Fatalf("OrgLockStatus = %+v, want LKG=%v tampered=%v", st, tc.wantLKG, tc.tamper)
			}
			if _, locked := g.OrgOverrideStatus("R-101"); locked != tc.wantLocked {
				t.Fatalf("OrgOverrideStatus(R-101) locked = %v, want %v (the CLI approve refusal reads it)", locked, tc.wantLocked)
			}
		})
	}
}

func managedLock(env, pin string) config.GuardOrgLock {
	return config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: true, KeyPinHash: pin, Bundle: env}
}

func individualLock(env, pin string) config.GuardOrgLock {
	return config.GuardOrgLock{State: "valid", TenancyKnown: true, Managed: false, KeyPinHash: pin, Bundle: env}
}

func noLock(string, string) config.GuardOrgLock { return config.GuardOrgLock{} }

// TestOrgLockPinCatchesASelfConsistentForgery: with the lock's pin a hook
// process (which passes no pin of its own) refuses a bundle re-signed under
// a different key and falls back to the last verified copy.
func TestOrgLockPinCatchesASelfConsistentForgery(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 950, orgOverridableBundleTOML)
	forged, _ := signedEnvelope(t, 951, "# nothing locked\n")
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	cfg.Lock = managedLock(env, pin)
	g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(map[string]string{orgBundlePath: forged})})
	if err != nil {
		t.Fatal(err)
	}
	if st := g.OrgLockStatus(); !st.BundleTampered || !st.LastVerifiedInUse {
		t.Fatalf("OrgLockStatus = %+v, want the forgery refused and the copy in force", st)
	}
	for _, ps := range g.PolicyStates() {
		if ps.Layer == layerOrg && ps.Version != "950" {
			t.Fatalf("org layer version = %s, want the last verified 950", ps.Version)
		}
	}
}

// TestOrgLockInputsRecordsOnlyPinVerifiedEnvelopes: the daemon's lock writer
// records an envelope only when the guard verified it under a pin.
func TestOrgLockInputsRecordsOnlyPinVerifiedEnvelopes(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 960, "[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n")
	for _, tc := range []struct {
		name    string
		pin     string
		wantEnv bool
	}{{"pinned", pin, true}, {"signature only", "", false}} {
		g, err := New(Options{
			Config: guardCfgOrg(), Home: "/home/u", OrgKeyPinHash: tc.pin,
			ReadFile: fsMap(map[string]string{orgBundlePath: env}), ManagedTenancy: func() bool { return true },
		})
		if err != nil {
			t.Fatal(err)
		}
		in := g.OrgLockInputs()
		if (len(in.Envelope) > 0) != tc.wantEnv || !in.OrgLayer || !in.TenancyResolved || !in.Managed {
			t.Fatalf("%s: inputs = %+v", tc.name, in)
		}
		if !in.PromptFloor || !in.PromptFloorStops {
			t.Fatalf("%s: an org R-172 deny must report a stopping prompt floor: %+v", tc.name, in)
		}
	}
}

// TestOrgPromptReachIsManagedOnly pins the guard half of D-672 for the
// prompt lane: on a managed node an org-pinned prompt rule reaches past a
// local "off" (global or per-detector) and a local allow-pattern; on an
// individual node the local tuning stands.
func TestOrgPromptReachIsManagedOnly(t *testing.T) {
	t.Parallel()
	const orgDeny = "[[override]]\nrule = \"R-172\"\ndecision = \"deny\"\nenforce = true\n"
	cases := []struct {
		name      string
		tenancy   func() bool
		mode      string
		detectors map[string]string
		allow     []string
		want      policy.Decision
		wantRule  string
	}{
		{"managed, local global off", func() bool { return true }, "off", nil, nil, policy.DecisionDeny, "R-172"},
		{"managed, local detector off", func() bool { return true }, "ask-once", allSecretDetectorsOff(), nil, policy.DecisionDeny, "R-172"},
		{"managed, local allow-pattern", func() bool { return true }, "ask-once", nil, []string{"github_pat_.*"}, policy.DecisionDeny, "R-172"},
		{"individual, local global off", func() bool { return false }, "off", nil, nil, policy.DecisionAllow, ""},
		{"individual, local detector off", func() bool { return false }, "ask-once", allSecretDetectorsOff(), nil, policy.DecisionAllow, ""},
		{"individual, local allow-pattern", func() bool { return false }, "ask-once", nil, []string{"github_pat_.*"}, policy.DecisionAllow, ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := promptCfg("enforce", tc.mode, tc.detectors)
			cfg.Prompt.Allow = tc.allow
			cfg.Rules.TrustedProjectDir = trustedCfg().Rules.TrustedProjectDir
			cfg.Rules.OrgBundle = guardCfgOrg().Rules.OrgBundle
			env, pin := signedEnvelope(t, int64(970+i), orgDeny)
			g, err := New(Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				ReadFile: fsMap(map[string]string{orgBundlePath: env}), OrgKeyPinHash: pin, ManagedTenancy: tc.tenancy,
			})
			if err != nil {
				t.Fatal(err)
			}
			g.SetPromptReconsiderStore(newMemPromptStore().funcs())
			secrets, pii, _ := g.BuildPromptFindings("push with " + fakeFinePAT + " please")
			pv := g.EvaluatePrompt(policy.Event{
				Kind: policy.KindUserPrompt, Tool: "claude-code", SessionID: "s-reach",
				Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj",
				Secrets: secrets, PIIFindings: pii, Now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC),
			})
			if pv.Verdict.Decision != tc.want || pv.Verdict.RuleID != tc.wantRule {
				t.Fatalf("prompt = %s %s, want %s %s", pv.Verdict.RuleID, pv.Verdict.Decision, tc.wantRule, tc.want)
			}
		})
	}
}

// allSecretDetectorsOff sets every secret-class detector to a local "off"
// (several detectors can match one token).
func allSecretDetectorsOff() map[string]string {
	out := map[string]string{}
	for _, name := range scrub.DetectorNames() {
		if class, ok := scrub.DetectorClass(name); ok && class == scrub.ClassSecret {
			out[name] = "off"
		}
	}
	return out
}
