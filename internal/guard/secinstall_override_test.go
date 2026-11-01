package guard

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// TestOrgBundleRaisesInstallUnknownRules closes S-744 and S-748 as by design
// (lane SEC-H2): neither has a node setting, and an org guard bundle's rule
// override of each reaches a managed node's decision. With the install
// gate's pack composed in and no org bundle, both flag in observe mode; an
// org bundle overriding each to deny makes the same install a deny.
func TestOrgBundleRaisesInstallUnknownRules(t *testing.T) {
	t.Parallel()
	comp, err := secrules.Compose(func(id string) bool { return id == "security" || id == "security.deps" })
	if err != nil {
		t.Fatal(err)
	}
	event := func(v policy.InstallVerdict) policy.Event {
		return policy.Event{
			Kind: policy.KindShellExec, Tool: "claude-code", SessionID: "s-install",
			Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", Target: "npm install left-pad",
			Security: &policy.Security{
				Posture: policy.SecurityPostureClean, Packs: []string{"security", "security.deps"},
				Installs: []policy.InstallCheck{{Ecosystem: "npm", Name: "left-pad", Verdict: v}},
			},
			Now: time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC),
		}
	}
	const orgDeny = "[[override]]\nrule = \"S-744\"\ndecision = \"deny\"\nenforce = true\n\n" +
		"[[override]]\nrule = \"S-748\"\ndecision = \"deny\"\nenforce = true\n"
	for i, tc := range []struct {
		name   string
		bundle string
		want   policy.Decision
	}{
		{"no org bundle", "", policy.DecisionFlag},
		{"org bundle raises both", orgDeny, policy.DecisionDeny},
	} {
		files := map[string]string{}
		pin := ""
		if tc.bundle != "" {
			env, p := signedEnvelope(t, int64(990+i), tc.bundle)
			files[orgBundlePath], pin = env, p
		}
		g, err := New(Options{
			Config: guardCfgOrg(), Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
			ReadFile: fsMap(files), OrgKeyPinHash: pin, ManagedTenancy: func() bool { return true },
			PackRules: comp.Rules,
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			rule    string
			verdict policy.InstallVerdict
		}{{"S-744", policy.InstallUnknownName}, {"S-748", policy.InstallOnlineUnknown}} {
			v, err := g.Evaluate(event(c.verdict))
			if err != nil {
				t.Fatal(err)
			}
			if v.RuleID != c.rule || v.Decision != tc.want {
				t.Errorf("%s: %s = %s %s, want %s", tc.name, c.rule, v.RuleID, v.Decision, tc.want)
			}
		}
	}
}
