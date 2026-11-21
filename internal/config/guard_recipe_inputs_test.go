package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateGuardRecipeInputs_HostPatterns is CFG-5's host half: only a
// [guard.network] entry no network rule could ever honour is refused. The
// shapes the matcher normalises (space, a trailing dot, a scheme and path,
// a :port, brackets, a leading "*") pass, so an existing config keeps
// loading on upgrade.
func TestValidateGuardRecipeInputs_HostPatterns(t *testing.T) {
	cases := []struct {
		host string
		ok   bool
	}{
		{"github.com", true},
		{"*.example.com", true},
		{"*pastebin.com", true},
		{"10.0.0.0/8", true},
		{"fd00::/8", true},
		{"192.168.1.10", true},
		{"::1", true},
		{"[::1]", true},
		{"[::1]:443", true},
		{"fe80::1%eth0", true},
		{" github.com ", true},
		{"pastebin.com.", true},
		{"pastebin.com:443", true},
		{"1.2.3.4:443", true},
		{"https://pastebin.com", true},
		{"https://pastebin.com:8443/paste?x=1", true},
		{"https:", true},
		{"", false},
		{"   ", false},
		{".", false},
		{"https://", false},
		{"*", false},
		{"*.", false},
		{"*.*.example.com", false},
		{"**example.com", false},
		{"pastebin.*", false},
		{"past*bin.com", false},
		{"user@pastebin.com", false},
		{"https://user:pw@pastebin.com", false},
		{"pastebin.com/raw", false},
		{"10.0.0.0/33", false},
		{"two words", false},
	}
	for _, tc := range cases {
		for _, key := range []string{"allow_hosts", "deny_hosts"} {
			g := Default().Guard
			if key == "allow_hosts" {
				g.Network.AllowHosts = []string{tc.host}
			} else {
				g.Network.DenyHosts = []string{tc.host}
			}
			err := validateGuardRecipeInputs(g)
			if tc.ok && err != nil {
				t.Errorf("%s %q: err = %v, want ok", key, tc.host, err)
			}
			if !tc.ok && err == nil {
				t.Errorf("%s %q: accepted, want refused", key, tc.host)
			}
		}
	}
}

// TestValidateGuardRecipeInputs_ProdPatternCredentials is CFG-5's database
// half: a prod pattern carrying a credential is refused, and the message
// does not repeat it.
func TestValidateGuardRecipeInputs_ProdPatternCredentials(t *testing.T) {
	cases := []struct {
		pattern string
		ok      bool
	}{
		{"prod-db.internal", true},
		{"*.prod.example.com", true},
		{"postgres://app@prod-db/main", true},
		{"analytics_prod", true},
		{"postgres://app:s3cretpw@prod-db/main", false},
		{"app:s3cretpw@prod-db", false},
		{"host=prod-db password=s3cretpw", false},
		{"Server=prod;Pwd=s3cretpw", false},
		{"PASSWORD = s3cretpw", false},
	}
	for _, tc := range cases {
		g := Default().Guard
		g.Database.ProdPatterns = []string{tc.pattern}
		err := validateGuardRecipeInputs(g)
		if tc.ok && err != nil {
			t.Errorf("%q: err = %v, want ok", tc.pattern, err)
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("%q: accepted, want refused", tc.pattern)
			} else if strings.Contains(err.Error(), "s3cretpw") {
				t.Errorf("%q: the refusal repeats the credential: %v", tc.pattern, err)
			}
		}
	}
}

// TestValidateGuard_RecipeInputsWhileDisabled is CFG-5's third half: the
// recipe keys are refused even while the guard is turned off.
func TestValidateGuard_RecipeInputsWhileDisabled(t *testing.T) {
	cases := []struct {
		name string
		edit func(*GuardConfig)
	}{
		{"level", func(g *GuardConfig) { g.Level = "../../etc" }},
		{"host", func(g *GuardConfig) { g.Network.DenyHosts = []string{"*"} }},
		{"prod pattern", func(g *GuardConfig) { g.Database.ProdPatterns = []string{"a:b@c"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := Default().Guard
			g.Enabled = false
			tc.edit(&g)
			if err := validateGuard(g); err == nil {
				t.Fatal("validateGuard accepted a bad recipe key while the guard is disabled")
			}
		})
	}
	g := Default().Guard
	g.Enabled = false
	if err := validateGuard(g); err != nil {
		t.Fatalf("validateGuard(disabled defaults) = %v", err)
	}
}

// TestLoad_GuardNetworkShapesTheMatcherHonours pins the upgrade half of
// CFG-5: a config.toml whose [guard.network] lists hold a trailing dot, a
// scheme, a port or surrounding space still loads, guard on or off (a
// config.Load failure stops the daemon), while a value no rule can honour
// is refused even with the guard off.
func TestLoad_GuardNetworkShapesTheMatcherHonours(t *testing.T) {
	load := func(t *testing.T, body string) error {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		db := filepath.ToSlash(filepath.Join(dir, "observer.db"))
		full := "[observer]\ndb_path = '" + db + "'\n\n" + body
		if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: NoGovernanceSidecar})
		return err
	}
	honoured := `deny_hosts = ["pastebin.com.", "https://pastebin.com", " paste.ee ", "ghostbin.co:443"]` + "\n" +
		`allow_hosts = ["*github.com", "[::1]:8080"]` + "\n"
	for _, enabled := range []string{"true", "false"} {
		t.Run("loads/enabled="+enabled, func(t *testing.T) {
			if err := load(t, "[guard]\nenabled = "+enabled+"\n\n[guard.network]\n"+honoured); err != nil {
				t.Fatalf("Load = %v, want the config to load", err)
			}
		})
	}
	for _, bad := range []string{`"*"`, `"user@pastebin.com"`, `"pastebin.*"`, `"pastebin.com/raw"`} {
		t.Run("refused "+bad, func(t *testing.T) {
			err := load(t, "[guard]\nenabled = false\n\n[guard.network]\ndeny_hosts = ["+bad+"]\n")
			if err == nil || !strings.Contains(err.Error(), "guard.network.deny_hosts") {
				t.Fatalf("Load = %v, want a deny_hosts refusal", err)
			}
		})
	}
}
