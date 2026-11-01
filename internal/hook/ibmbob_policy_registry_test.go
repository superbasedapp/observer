package hook

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// fakeBobKey is an ibmBobRegistryKey over fixed names: the registry seam, so
// no test touches a real registry.
func fakeBobKey(names []string, found bool, problem string) ibmBobRegistryKey {
	return func() ([]string, bool, string) { return names, found, problem }
}

// TestIBMBobPolicyDomainsFromRegistry pins FU-115 (ruling AW-79): Bob 2.2.3
// on Windows applies EnforcedHooks from HKCU\Software\Policies\IBM\Bob as
// well as HKLM, so the HKCU key's policy names are the user-writable side
// (UserSource the HKCU key, reported user-set like the macOS user domain)
// and the HKLM key's the managed side. Names are matched without case (the
// registry's own rule) and reported in the catalogue's spelling; a value
// name that is not a Bob policy is ignored; a user key that cannot be listed
// is unknown, never "none"; a missing key contributes nothing.
func TestIBMBobPolicyDomainsFromRegistry(t *testing.T) {
	absent := fakeBobKey(nil, false, "")
	cases := []struct {
		name          string
		machine, user ibmBobRegistryKey
		want          IBMBobPolicyDomains
	}{
		{"neither key", absent, absent, IBMBobPolicyDomains{}},
		{
			"HKLM only", fakeBobKey([]string{"EnforcedHooks", "OtelConfiguration"}, true, ""), absent,
			IBMBobPolicyDomains{ManagedKeys: []string{"EnforcedHooks", "OtelConfiguration"}},
		},
		{
			"HKCU EnforcedHooks only (the live FU-115 shape)", absent, fakeBobKey([]string{"EnforcedHooks"}, true, ""),
			IBMBobPolicyDomains{UserSource: IBMBobHKCUPolicySource, UserKeys: []string{"EnforcedHooks"}},
		},
		{
			"both keys, case folded, a non-policy value ignored",
			fakeBobKey([]string{"enforcedhooks"}, true, ""),
			fakeBobKey([]string{"ENFORCEDHOOKS", "GatewayUrl", "WindowState"}, true, ""),
			IBMBobPolicyDomains{ManagedKeys: []string{"EnforcedHooks"}, UserSource: IBMBobHKCUPolicySource, UserKeys: []string{"EnforcedHooks", "GatewayUrl"}},
		},
		{
			"an unlistable HKCU key is unknown", absent, fakeBobKey(nil, true, "could not be opened"),
			IBMBobPolicyDomains{UserSource: IBMBobHKCUPolicySource, UserProblem: IBMBobHKCUPolicySource + " could not be opened"},
		},
		{"an unlistable HKLM key contributes nothing", fakeBobKey([]string{"EnforcedHooks"}, true, "could not be listed"), absent, IBMBobPolicyDomains{}},
		{
			"an empty HKCU key exists but sets nothing", absent, fakeBobKey(nil, true, ""),
			IBMBobPolicyDomains{UserSource: IBMBobHKCUPolicySource, UserKeys: []string{}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ibmBobPolicyDomainsFromRegistry(tc.machine, tc.user)
			norm := func(d IBMBobPolicyDomains) IBMBobPolicyDomains {
				if len(d.ManagedKeys) == 0 {
					d.ManagedKeys = nil
				}
				if len(d.UserKeys) == 0 {
					d.UserKeys = nil
				}
				return d
			}
			if !reflect.DeepEqual(norm(got), norm(tc.want)) {
				t.Fatalf("domains = %+v, want %+v", got, tc.want)
			}
			if got.UserSource != "" && !got.UserIsRegistry() {
				t.Fatal("an HKCU user source does not read as the registry")
			}
		})
	}
}

// TestIBMBobHKCUPolicyIsUserLevelNotEnforced pins the FU-115 consequence:
// an HKCU EnforcedHooks is a user-writable layer (RuntimeUserPrefs, the
// user_policy_override family input), never the managed one, and it never
// makes the per-node registration stand down (the stand-down reads the
// HKLM policy only; a test binary's HKLM reader is "no policy").
func TestIBMBobHKCUPolicyIsUserLevelNotEnforced(t *testing.T) {
	d := ibmBobPolicyDomainsFromRegistry(nil, fakeBobKey([]string{"EnforcedHooks"}, true, ""))
	trees := d.LayerTrees()
	want := []agentconfig.RuntimeTree{{Tool: "ibm-bob", Layer: agentconfig.RuntimeUserPrefs, Tree: map[string]any{"EnforcedHooks": agentconfig.KeyPresent{}}}}
	if !reflect.DeepEqual(trees, want) {
		t.Fatalf("trees = %#v, want the user layer only", trees)
	}
	if pol := ReadIBMBobPolicy(); pol.Found {
		t.Fatalf("the stand-down policy read %+v in a test binary", pol)
	}
	if (IBMBobPolicyDomains{UserSource: IBMBobUserPrefsPath("/Users/dev")}).UserIsRegistry() {
		t.Fatal("the macOS user domain reads as the registry")
	}
}
