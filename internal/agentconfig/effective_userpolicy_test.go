package agentconfig

import (
	"reflect"
	"testing"
)

// TestIBMBobPolicyFamiliesFromTheCatalogue (FU-105): one user-policy family
// per ibm-bob/policy key the catalogue records, so a policy name added to
// the catalogue is observed without a second list here.
func TestIBMBobPolicyFamiliesFromTheCatalogue(t *testing.T) {
	var want []string
	for _, r := range ibmBobSettings {
		if r.FileID == bobPolicy {
			want = append(want, "ibm-bob/policy."+r.Path.String())
		}
	}
	var got []string
	for _, f := range Families() {
		if f.Concern == ConcernUserPolicy {
			got = append(got, f.ID)
			if f.Tool != "ibm-bob" || f.Shape != bobPolicy || f.RuntimeRanks[RuntimeManagedPrefs] <= f.RuntimeRanks[RuntimeUserPrefs] {
				t.Errorf("%s: tool %s shape %s ranks %v; a managed value must outrank a user one", f.ID, f.Tool, f.Shape, f.RuntimeRanks)
			}
		}
	}
	if len(want) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("user-policy families = %v, want %v", got, want)
	}
}

// TestEvaluateLayersUserSetPolicy (FU-105): a Bob policy key in the user's
// own preferences domain is a user_policy_override whether or not the
// administrator also sets it; the admin's managed key alone, or the Linux
// root-owned policy file alone, is no finding.
func TestEvaluateLayersUserSetPolicy(t *testing.T) {
	user := func(keys ...string) RuntimeTree {
		m := map[string]any{}
		for _, k := range keys {
			m[k] = KeyPresent{}
		}
		return RuntimeTree{Tool: "ibm-bob", Layer: RuntimeUserPrefs, Tree: m}
	}
	mgd := func(keys ...string) RuntimeTree {
		rt := user(keys...)
		rt.Layer = RuntimeManagedPrefs
		return rt
	}
	cases := []struct {
		name    string
		files   []LayerFile
		runtime []RuntimeTree
		want    []briefFinding
	}{
		{name: "no user key", runtime: []RuntimeTree{mgd("GatewayUrl")}},
		{name: "the Linux policy file alone", files: []LayerFile{lf(t, "ibm-bob/policy", "", map[string]any{"GatewayUrl": "https://gw.example"})}},
		{
			name:    "a key the administrator did not set",
			runtime: []RuntimeTree{user("UpdateMode"), mgd("GatewayUrl")},
			want:    []briefFinding{{"ibm-bob/policy.UpdateMode", FindingUserPolicyOverride, "", classSet, "runtime:user_prefs"}},
		},
		{
			name:    "a key the administrator also sets (the managed value wins, still reported)",
			runtime: []RuntimeTree{user("GatewayUrl"), mgd("GatewayUrl")},
			want:    []briefFinding{{"ibm-bob/policy.GatewayUrl", FindingUserPolicyOverride, "", classSet, "runtime:managed_prefs"}},
		},
		{
			name:    "user keys only, no managed domain",
			runtime: []RuntimeTree{user("EnableTelemetry", "EnforcedHooks")},
			want: []briefFinding{
				{"ibm-bob/policy.EnforcedHooks", FindingUserPolicyOverride, "", classSet, "runtime:user_prefs"},
				{"ibm-bob/policy.EnableTelemetry", FindingUserPolicyOverride, "", classSet, "runtime:user_prefs"},
			},
		},
	}
	var fams []Family
	for _, f := range Families() {
		if f.Concern == ConcernUserPolicy {
			fams = append(fams, f)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, err := EvaluateLayers(LayerInput{Files: tc.files, Runtime: tc.runtime, Projects: []string{"/work/p"}, Families: fams})
			if err != nil {
				t.Fatal(err)
			}
			var got []briefFinding
			for _, f := range fs {
				got = append(got, briefFinding{f.Family, f.Code, f.Project, f.Class, f.Winning.String()})
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("findings = %+v, want %+v", got, tc.want)
			}
		})
	}
}
