package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// managedLockFixture is one guard over an org bundle that names R-110 only,
// with local changes in every layer a machine writes for itself.
func managedLockFixture(t *testing.T, managed *bool) (*Guard, []string) {
	t.Helper()
	const orgBody = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n"
	env, pin := signedEnvelope(t, 520, orgBody)
	cfg := guardCfgOrg()
	cfg.Mode = "enforce"
	cfg.Rules.TrustedProjectDir = "~/.observer/guard-trusted"
	// R-101 and R-102 are built-ins the bundle does not name; U-1 is the
	// user file's own rule.
	cfg.Rules.Disable = []string{"R-101", "U-1"}
	const userBody = "[[override]]\nrule = \"R-102\"\ndecision = \"allow\"\n" +
		"[[override]]\nrule = \"R-103\"\ndecision = \"deny\"\n" +
		"[[rule]]\nid = \"U-1\"\ncategory = \"destructive\"\nseverity = \"high\"\ndecision = \"deny\"\n" +
		"[rule.match]\ncommand_regex = \"^touch /tmp/u1$\"\n"
	root := "/home/u/proj"
	trustedPath := TrustedProjectPolicyPath(cfg, "/home/u", root)
	files := map[string]string{
		orgBundlePath:                         env,
		"/home/u/.observer/guard-policy.toml": userBody,
		"/home/u/proj/.observer/guard-policy.toml": "[[override]]\nrule = \"R-104\"\ndecision = \"allow\"\n" +
			"[[override]]\nrule = \"R-102\"\ndecision = \"deny\"\n",
		strings.ReplaceAll(trustedPath, "\\", "/"): "disable = [\"R-103\"]\n",
	}
	opts := Options{
		Config: cfg, Home: "/home/u", KnownProjectRoots: []string{root},
		ReadFile: fsMap(files), OrgKeyPinHash: pin,
	}
	if managed != nil {
		m := *managed
		opts.ManagedTenancy = func() bool { return m }
	}
	g, err := New(opts)
	if err != nil {
		t.Fatalf("guard.New: %v", err)
	}
	return g, cfg.Rules.Disable
}

func ruleIDsOf(infos []policy.RuleInfo) map[string]bool {
	out := map[string]bool{}
	for _, i := range infos {
		out[i.ID] = true
	}
	return out
}

// TestManagedLockIgnoresLocalLoosenings: on a managed node with an org layer
// in force, a config disable and a user-file relaxation of a built-in the
// bundle does not name no longer apply (2026-11-12 ruling); a stricter user
// override and the user's own rule still do. An individual node and a
// process with no resolved tenancy keep today's behaviour.
func TestManagedLockIgnoresLocalLoosenings(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	cases := []struct {
		name        string
		managed     *bool
		wantR101    bool // R-101 still loaded despite the config disable
		wantIgnored []string
	}{
		{"managed", &yes, true, []string{"R-101"}},
		{"individual", &no, false, nil},
		{"tenancy unresolved", nil, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, disable := managedLockFixture(t, tc.managed)
			ids := ruleIDsOf(g.EffectiveRules())
			if ids["R-101"] != tc.wantR101 {
				t.Errorf("R-101 loaded = %v, want %v (issues %v)", ids["R-101"], tc.wantR101, g.LoadIssues())
			}
			if ids["U-1"] {
				t.Errorf("the user's own rule U-1 should stay disable-able")
			}
			got := g.ManagedIgnoredConfigDisables(disable)
			if strings.Join(got, ",") != strings.Join(tc.wantIgnored, ",") {
				t.Errorf("ManagedIgnoredConfigDisables = %v, want %v", got, tc.wantIgnored)
			}
			issues := strings.Join(g.LoadIssues(), "\n")
			if hit := strings.Contains(issues, "disable of R-101 ignored"); hit != tc.wantR101 {
				t.Errorf("issue for the ignored disable present = %v, want %v:\n%s", hit, tc.wantR101, issues)
			}
			relaxDropped := strings.Contains(issues, "user override on R-102 dropped")
			if relaxDropped != tc.wantR101 {
				t.Errorf("user relaxation of R-102 dropped = %v, want %v:\n%s", relaxDropped, tc.wantR101, issues)
			}
			if strings.Contains(issues, "user override on R-103 dropped") {
				t.Errorf("a stricter user override must stand:\n%s", issues)
			}
		})
	}
}

// TestManagedLockTrustedProjectDisable: the trusted per-project layer's
// disable of a built-in is dropped on a managed node.
func TestManagedLockTrustedProjectDisable(t *testing.T) {
	t.Parallel()
	yes := true
	g, _ := managedLockFixture(t, &yes)
	ids := ruleIDsOf(g.EffectiveRulesFor("/home/u/proj"))
	if !ids["R-103"] {
		t.Errorf("R-103 disabled by the trusted project layer on a managed node (issues %v)", g.LoadIssues())
	}
	if !strings.Contains(strings.Join(g.LoadIssues(), "\n"), "trusted project disable of R-103 dropped") {
		t.Errorf("no load issue for the dropped trusted disable: %v", g.LoadIssues())
	}
}

// TestLocalRuleChangesReport pins the gen9 report: every layer's changes,
// whether each loosens, whether the machine applies it, and the project hash
// on per-project layers.
func TestLocalRuleChangesReport(t *testing.T) {
	t.Parallel()
	hash := func(r string) string { s := sha256.Sum256([]byte(r)); return hex.EncodeToString(s[:]) }
	type key struct{ layer, kind, id string }
	type want struct{ loosens, applied bool }
	yes, no := true, false
	for _, tc := range []struct {
		name    string
		managed *bool
		want    map[key]want
	}{
		{"managed", &yes, map[key]want{
			{orgcontract.LocalRuleLayerMachine, "disable", "R-101"}:        {true, false},
			{orgcontract.LocalRuleLayerMachine, "disable", "U-1"}:          {true, true},
			{orgcontract.LocalRuleLayerUserFile, "override", "R-102"}:      {true, false},
			{orgcontract.LocalRuleLayerUserFile, "override", "R-103"}:      {false, true},
			{orgcontract.LocalRuleLayerUserFile, "rule", "U-1"}:            {false, true},
			{orgcontract.LocalRuleLayerTrustedProject, "disable", "R-103"}: {true, false},
			{orgcontract.LocalRuleLayerProjectFile, "override", "R-104"}:   {true, false},
			{orgcontract.LocalRuleLayerProjectFile, "override", "R-102"}:   {false, true},
		}},
		{"individual", &no, map[key]want{
			{orgcontract.LocalRuleLayerMachine, "disable", "R-101"}:        {true, true},
			{orgcontract.LocalRuleLayerMachine, "disable", "U-1"}:          {true, true},
			{orgcontract.LocalRuleLayerUserFile, "override", "R-102"}:      {true, true},
			{orgcontract.LocalRuleLayerUserFile, "override", "R-103"}:      {false, true},
			{orgcontract.LocalRuleLayerUserFile, "rule", "U-1"}:            {false, true},
			{orgcontract.LocalRuleLayerTrustedProject, "disable", "R-103"}: {true, true},
			{orgcontract.LocalRuleLayerProjectFile, "override", "R-104"}:   {true, false},
			{orgcontract.LocalRuleLayerProjectFile, "override", "R-102"}:   {false, true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := managedLockFixture(t, tc.managed)
			changes, truncated := g.LocalRuleChanges(g.cfg, []string{"/home/u/proj", ""}, hash)
			if truncated {
				t.Errorf("truncated = true")
			}
			if len(changes) != len(tc.want) {
				t.Errorf("got %d changes, want %d: %+v", len(changes), len(tc.want), changes)
			}
			for _, c := range changes {
				if !c.Valid() {
					t.Errorf("invalid change on the wire: %+v", c)
				}
				w, ok := tc.want[key{c.Layer, c.Kind, c.RuleID}]
				if !ok {
					t.Errorf("unexpected change %+v", c)
					continue
				}
				if c.Loosens != w.loosens || c.Applied != w.applied {
					t.Errorf("%s %s %s: loosens=%v applied=%v, want %v/%v", c.Layer, c.Kind, c.RuleID, c.Loosens, c.Applied, w.loosens, w.applied)
				}
				perProject := c.Layer == orgcontract.LocalRuleLayerProjectFile || c.Layer == orgcontract.LocalRuleLayerTrustedProject
				if perProject && c.ProjectRootHash != hash("/home/u/proj") {
					t.Errorf("%+v: project hash %q", c, c.ProjectRootHash)
				}
			}
		})
	}
}
