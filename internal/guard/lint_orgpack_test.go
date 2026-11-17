//go:build !sbo_omit_security

package guard

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// packRuleIDs returns every distinct security pillar rule id this build
// carries (the full composition, every component on).
func packRuleIDs(t *testing.T) []string {
	t.Helper()
	c, err := secrules.Compose(func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var ids []string
	for _, r := range c.Rules {
		if !seen[r.ID] {
			seen[r.ID] = true
			ids = append(ids, r.ID)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		t.Fatal("the full pack composed no rules")
	}
	return ids
}

// TestOrgLintAcceptsEveryPackRuleOverride pins audit CG-1: an org bundle
// override on ANY security pillar rule lints clean at the server's publish
// gate (Lint "org") and at a node's accept gate (AcceptOrgBundleTOML), even
// though neither host loads the pack, while an id no row carries is still
// refused at both and a relaxation still gets the one-way check.
func TestOrgLintAcceptsEveryPackRuleOverride(t *testing.T) {
	t.Parallel()
	bodies := map[string]string{
		"overridable":      "overridable = true\n",
		"enforce":          "enforce = true\n",
		"enforce off":      "enforce = false\noverridable = true\n",
		"deny enforced":    "decision = \"deny\"\nenforce = true\n",
		"deny overridable": "decision = \"deny\"\nenforce = true\noverridable = true\n",
	}
	override := func(id, body string) []byte {
		return []byte("[[override]]\nrule = \"" + id + "\"\n" + body)
	}
	for _, id := range packRuleIDs(t) {
		for name, body := range bodies {
			raw := override(id, body)
			if p := Lint(raw, layerOrg); len(p) != 0 {
				t.Errorf("Lint org %s %s: %v, want none", id, name, p)
			}
			if p, _ := AcceptOrgBundleTOML(raw); len(p) != 0 {
				t.Errorf("AcceptOrgBundleTOML %s %s: %v, want none", id, name, p)
			}
		}
	}
	refused := []struct {
		name, raw, want string
	}{
		{"unknown pillar id", string(override("S-799", "overridable = true\n")), "S-799"},
		{"relaxation of a pack rule", string(override("S-721", "decision = \"allow\"\n")), "would relax"},
	}
	for _, tc := range refused {
		if p := Lint([]byte(tc.raw), layerOrg); !strings.Contains(strings.Join(p, "\n"), tc.want) {
			t.Errorf("Lint org %s: %v, want a problem naming %q", tc.name, p, tc.want)
		}
		if p, _ := AcceptOrgBundleTOML([]byte(tc.raw)); !strings.Contains(strings.Join(p, "\n"), tc.want) {
			t.Errorf("AcceptOrgBundleTOML %s: %v, want a problem naming %q", tc.name, p, tc.want)
		}
	}
	// The full pack is the ORG layer's vocabulary only: the project layer
	// lints against this host, where Code security is not active.
	if p := Lint(override("S-793", "decision = \"deny\"\nenforce = true\n"), layerProject); !strings.Contains(strings.Join(p, "\n"), "Code security is not active") {
		t.Errorf("Lint project S-793: %v, want the inactive-module note", p)
	}
}

// TestOrgPackOverrideReachesTheVerdict pins the node half of CG-1: a bundle
// the accept gate takes, carrying overrides on pack rules, changes the
// verdict on a node whose pack is active and is a load note (never a
// failure) on a node whose pack is off.
func TestOrgPackOverrideReachesTheVerdict(t *testing.T) {
	t.Parallel()
	const bundle = "[[override]]\nrule = \"S-744\"\ndecision = \"deny\"\nenforce = true\noverridable = true\n"
	if p, _ := AcceptOrgBundleTOML([]byte(bundle)); len(p) != 0 {
		t.Fatalf("AcceptOrgBundleTOML: %v", p)
	}
	comp, err := secrules.Compose(func(id string) bool { return id == "security" || id == "security.deps" })
	if err != nil {
		t.Fatal(err)
	}
	ev := policy.Event{
		Kind: policy.KindShellExec, Tool: "claude-code", SessionID: "s-pack",
		Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Target: "npm install left-pad",
		Security: &policy.Security{
			Posture: policy.SecurityPostureClean, Packs: []string{"security", "security.deps"},
			Installs: []policy.InstallCheck{{Ecosystem: "npm", Name: "left-pad", Verdict: policy.InstallUnknownName}},
		},
		Now: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
	}
	for i, tc := range []struct {
		name        string
		pack        []policy.Rule
		bundle      string
		wantRule    string
		wantDec     policy.Decision
		wantOverrid bool
	}{
		{"pack on, no bundle", comp.Rules, "", "S-744", policy.DecisionFlag, false},
		{"pack on, org override", comp.Rules, bundle, "S-744", policy.DecisionDeny, true},
		{"pack off, org override", nil, bundle, "", policy.DecisionAllow, false},
	} {
		files := map[string]string{}
		pin := ""
		if tc.bundle != "" {
			env, p := signedEnvelope(t, int64(1200+i), tc.bundle)
			files[orgBundlePath], pin = env, p
		}
		g, err := New(Options{
			Config: guardCfgOrg(), Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
			ReadFile: fsMap(files), OrgKeyPinHash: pin, ManagedTenancy: func() bool { return true },
			PackRules: tc.pack,
		})
		if err != nil {
			t.Fatalf("%s: New: %v", tc.name, err)
		}
		v, err := g.Evaluate(ev)
		if err != nil {
			t.Fatalf("%s: Evaluate: %v", tc.name, err)
		}
		if v.RuleID != tc.wantRule || v.Decision != tc.wantDec || v.Overridable != tc.wantOverrid {
			t.Errorf("%s: verdict = %s %s overridable=%v, want %s %s overridable=%v",
				tc.name, v.RuleID, v.Decision, v.Overridable, tc.wantRule, tc.wantDec, tc.wantOverrid)
		}
	}
}
