package guard

import "testing"

// TestOrgOverridePostureEnforced pins FU-235 (b): the posture lists the
// rules the ORG layer makes stop an action in the running mode, so the
// Security page and `observer guard status` can say "observe locally; N
// rules enforced by your organization" instead of a bare "observe".
func TestOrgOverridePostureEnforced(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mode   string
		bundle string
		want   []string
	}{
		{"no org bundle: nothing is org-enforced", "observe", "", nil},
		{"observe: org enforce=true rows stop, overridable included", "observe", orgOverridableBundleTOML, []string{"R-110", "R-150"}},
		{"enforce mode: the same org rows", "enforce", orgOverridableBundleTOML, []string{"R-110", "R-150"}},
		{
			"an org flag-only pin enforces nothing",
			"observe", "[[override]]\nrule = \"R-101\"\ndecision = \"flag\"\n", nil,
		},
		{
			"an org enforce=false cap enforces nothing",
			"enforce", "[[override]]\nrule = \"R-101\"\nenforce = false\n", nil,
		},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			files := map[string]string{}
			cfg := guardCfgOrg()
			cfg.Mode = tc.mode
			if tc.bundle != "" {
				env, _ := signedEnvelope(t, int64(2400+i), tc.bundle)
				files[orgBundlePath] = env
			}
			g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(files), ManagedTenancy: func() bool { return false }})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			got := g.OrgOverridePosture().Enforced
			if len(got) != len(tc.want) {
				t.Fatalf("Enforced = %v, want %v (issues %v)", got, tc.want, g.LoadIssues())
			}
			for j := range got {
				if got[j] != tc.want[j] {
					t.Fatalf("Enforced = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestOrgOverridePostureModeLine pins the status line the CLI and the
// Security page both render beside the mode, one row per shape.
func TestOrgOverridePostureModeLine(t *testing.T) {
	t.Parallel()
	many := []string{"R-101", "R-102", "R-103", "R-104", "R-105", "R-106", "R-107", "R-108", "R-109", "R-110"}
	cases := []struct {
		name string
		p    OrgOverridePosture
		mode string
		want string
	}{
		{"no org layer: nothing to add", OrgOverridePosture{}, "observe", ""},
		{
			"managed node, one enforced rule",
			OrgOverridePosture{OrgApplies: true, LocksEveryRule: true, Enforced: []string{"R-101"}},
			"observe",
			"observe locally; 1 rule enforced by your organization (R-101); your organization locks every rule on this node, so local exceptions do not apply",
		},
		{
			"individual node, named rules, none enforced",
			OrgOverridePosture{OrgApplies: true, Named: map[string]bool{"R-110": true, "R-150": true}},
			"observe",
			"observe locally; your organization's policy enforces no rule here; local exceptions do not apply to the 2 rules your organization names",
		},
		{
			"empty mode reads as the observe default",
			OrgOverridePosture{OrgApplies: true, Enforced: []string{"R-110", "R-150"}, Named: map[string]bool{"R-110": true}},
			"",
			"observe locally; 2 rules enforced by your organization (R-110, R-150); local exceptions do not apply to the 1 rule your organization names",
		},
		{
			"long list is bounded",
			OrgOverridePosture{OrgApplies: true, Enforced: many},
			"enforce",
			"enforce locally; 10 rules enforced by your organization (R-101, R-102, R-103, R-104, R-105, R-106, R-107, R-108, +2 more)",
		},
		{
			"unverifiable bundle",
			OrgOverridePosture{Unverifiable: true},
			"observe",
			"your organization's policy bundle does not verify and no verified copy is held, so local exceptions are refused for every rule until a verified bundle is back",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.ModeLine(tc.mode); got != tc.want {
				t.Fatalf("ModeLine =\n  %q\nwant\n  %q", got, tc.want)
			}
		})
	}
}
