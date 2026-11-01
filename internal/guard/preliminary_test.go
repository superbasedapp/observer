package guard

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestPreliminaryGateEnforcement pins the T-381 interim answer, one row per
// input combination: the config decides, except that a policy file which
// could raise enforcement counts as enforcing until the full derivation
// reads it.
func TestPreliminaryGateEnforcement(t *testing.T) {
	const home = "/h"
	base := func(mode string) config.GuardConfig {
		c := config.Default().Guard
		c.Enabled, c.Mode = true, mode
		c.Prompt.EnforceIndependent = false
		c.Rules.UserPolicy = "~/.observer/guard-policy.toml"
		c.Rules.OrgBundle = "~/.observer/org-policy-bundle.json"
		return c
	}
	user, org := home+"/.observer/guard-policy.toml", home+"/.observer/org-policy-bundle.json"
	cases := []struct {
		name               string
		cfg                config.GuardConfig
		files              []string
		wantTool, wantPrmt bool
	}{
		{"observe, no policy files: not enforcing", base("observe"), nil, false, false},
		{"enforce: the tool family enforces", base("enforce"), nil, true, true},
		{"observe + user policy: tool family pending", base("observe"), []string{user}, true, false},
		{"observe + org bundle: both families pending", base("observe"), []string{org}, true, true},
		{"guard off: nothing, files or not", func() config.GuardConfig { c := base("off"); return c }(), []string{user, org}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exists := func(p string) bool {
				for _, f := range tc.files {
					// The product joins the probe path natively.
					if f == filepath.ToSlash(p) {
						return true
					}
				}
				return false
			}
			got := PreliminaryGateEnforcement(tc.cfg, home, exists)
			if got.Tool != tc.wantTool || got.Prompt != tc.wantPrmt {
				t.Fatalf("PreliminaryGateEnforcement = %+v, want tool=%v prompt=%v", got, tc.wantTool, tc.wantPrmt)
			}
			if got.UserPolicyFailClosed {
				t.Error("the interim answer never carries the org's user-policy mode")
			}
		})
	}
	if got := PreliminaryGateEnforcement(base("observe"), home, nil); got.Tool {
		t.Error("a nil exists probe raised enforcement")
	}
}
