package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityLicensesValidate walks the [security.licenses] checks, one
// case per rule.
func TestSecurityLicensesValidate(t *testing.T) {
	t.Parallel()
	many := make([]string, MaxSecurityLicensesEntries+1)
	for i := range many {
		many[i] = "MIT"
	}
	cases := []struct {
		name string
		c    SecurityLicensesConfig
		ok   bool
	}{
		{"default", DefaultSecurityLicensesConfig(), true},
		{"zero value", SecurityLicensesConfig{}, true},
		{"ids and classes", SecurityLicensesConfig{Deny: []string{"GPL-3.0-only", "strong_copyleft", "LicenseRef-proprietary"}, Allow: []string{"permissive", "MPL-2.0"}, Unknown: "flag"}, true},
		{"unknown off picker", SecurityLicensesConfig{Unknown: "deny"}, false},
		{"entry with a space", SecurityLicensesConfig{Deny: []string{"MIT License"}}, false},
		{"empty entry", SecurityLicensesConfig{Allow: []string{""}}, false},
		{"entry too long", SecurityLicensesConfig{Deny: []string{strings.Repeat("a", 65)}}, false},
		{"too many entries", SecurityLicensesConfig{Allow: many}, false},
	}
	for _, c := range cases {
		if err := validateSecurityLicenses(c.c); (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

// TestSecurityLicensesDefaultsAndPartialMerge: the defaults record nothing
// (empty lists, unknown ignored) and a file that sets one key keeps the
// others' defaults.
func TestSecurityLicensesDefaultsAndPartialMerge(t *testing.T) {
	t.Parallel()
	d := DefaultSecurityConfig().Licenses
	if len(d.Deny) != 0 || len(d.Allow) != 0 || d.Unknown != "ignore" {
		t.Fatalf("defaults %+v", d)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[security.licenses]\ndeny = [\"network_copyleft\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if l := cfg.Security.Licenses; len(l.Deny) != 1 || l.Deny[0] != "network_copyleft" || len(l.Allow) != 0 || l.Unknown != "ignore" {
		t.Fatalf("partial merge: %+v", l)
	}
}
