package hook

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestIBMBobPolicyDomainsAt (FU-105) reads fixture domains as the darwin
// reader does, with the plist conversion replaced by identity (the fixtures
// are already JSON) and the root-ownership rule injected, so it runs on
// every OS.
func TestIBMBobPolicyDomainsAt(t *testing.T) {
	identity := func(b []byte) ([]byte, error) { return b, nil }
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name        string
		user        string // "" = absent; "<dir>" = a directory
		managed     string // "" = absent
		untrusted   bool   // the managed plist fails the ownership rule
		wantManaged []string
		wantUser    []string
		wantProblem string
	}{
		{name: "nothing deployed"},
		{name: "managed only", managed: `{"GatewayUrl":"https://gw.example"}`, wantManaged: []string{"GatewayUrl"}},
		{
			name: "user keys, non-policy keys ignored", user: `{"GatewayUrl":"https://u.example","UpdateMode":"none","NSWindow Frame main":"0 0 1 1"}`,
			wantUser: []string{"GatewayUrl", "UpdateMode"},
		},
		{
			name: "user key the admin also sets", managed: `{"GatewayUrl":"https://gw.example","EnforcedHooks":"{}"}`, user: `{"GatewayUrl":"https://u.example"}`,
			wantManaged: []string{"EnforcedHooks", "GatewayUrl"}, wantUser: []string{"GatewayUrl"},
		},
		{
			name: "an untrusted managed plist is not administrator policy", managed: `{"GatewayUrl":"x"}`, untrusted: true, user: `{"UpdateMode":"x"}`,
			wantUser: []string{"UpdateMode"},
		},
		{name: "a user domain with only app keys", user: `{"NSNavLastRootDirectory":"~"}`},
		{name: "a user domain that is not a dictionary", user: `[1]`, wantProblem: "not a property list dictionary"},
		{name: "a user domain that is not a regular file", user: "<dir>", wantProblem: "not a regular file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			var managed []string
			if tc.managed != "" {
				p := filepath.Join(t.TempDir(), "com.ibm.bob.plist")
				write(t, p, tc.managed)
				managed = append(managed, p)
			}
			managed = append(managed, filepath.Join(t.TempDir(), "absent", "com.ibm.bob.plist"))
			switch tc.user {
			case "":
			case "<dir>":
				if err := os.MkdirAll(IBMBobUserPrefsPath(home), 0o755); err != nil {
					t.Fatal(err)
				}
			default:
				write(t, IBMBobUserPrefsPath(home), tc.user)
			}
			owner := func(path string, _ os.FileInfo) string {
				if tc.untrusted {
					return path + " is not owned by root"
				}
				return ""
			}
			d := ibmBobPolicyDomainsAt(home, managed, identity, owner)
			if !reflect.DeepEqual(d.ManagedKeys, tc.wantManaged) || !reflect.DeepEqual(d.UserKeys, tc.wantUser) {
				t.Fatalf("managed %v user %v, want %v / %v", d.ManagedKeys, d.UserKeys, tc.wantManaged, tc.wantUser)
			}
			if !strings.Contains(d.UserProblem, tc.wantProblem) || (tc.wantProblem == "" && d.UserProblem != "") {
				t.Fatalf("problem %q, want %q", d.UserProblem, tc.wantProblem)
			}
			if (tc.user != "") != (d.UserSource != "") {
				t.Fatalf("user source %q for user fixture %q", d.UserSource, tc.user)
			}
		})
	}
}

// TestIBMBobPolicyDomainsLayerTrees: no user key means no tree (nothing for
// the evaluator to decide); otherwise the user tree, plus the managed one
// when the admin sets keys, each carrying key presence only, never a value.
func TestIBMBobPolicyDomainsLayerTrees(t *testing.T) {
	if got := (IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}}).LayerTrees(); got != nil {
		t.Fatalf("managed keys alone gave %v", got)
	}
	d := IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}, UserSource: "/u", UserKeys: []string{"GatewayUrl", "UpdateMode"}}
	got := d.LayerTrees()
	want := []agentconfig.RuntimeTree{
		{Tool: "ibm-bob", Layer: agentconfig.RuntimeUserPrefs, Tree: map[string]any{"GatewayUrl": agentconfig.KeyPresent{}, "UpdateMode": agentconfig.KeyPresent{}}},
		{Tool: "ibm-bob", Layer: agentconfig.RuntimeManagedPrefs, Tree: map[string]any{"GatewayUrl": agentconfig.KeyPresent{}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trees = %#v", got)
	}
	if !d.AdminAlsoSets("GatewayUrl") || d.AdminAlsoSets("UpdateMode") {
		t.Fatal("AdminAlsoSets")
	}
	// A test binary never reads the host's domains.
	if got := PolicyDomainLayers(t.TempDir(), true); got != nil {
		t.Fatalf("PolicyDomainLayers in a test = %v", got)
	}
	if got := ReadIBMBobPolicyDomains("", true); !reflect.DeepEqual(got, IBMBobPolicyDomains{}) {
		t.Fatalf("an empty home read %+v", got)
	}
}
