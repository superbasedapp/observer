package integration

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSandboxConfigHomeOnboardedAndSeed: the onboarding flag is read only as
// JSON true, and the seed copies only the listed scalar keys (Windows 11 Pro
// rerun 2026-10-25, D3).
func TestSandboxConfigHomeOnboardedAndSeed(t *testing.T) {
	c := SandboxConfigHome{OnboardedKey: "hasCompletedOnboarding", SeedKeys: []string{"hasCompletedOnboarding", "theme", "nested"}}
	for _, tc := range []struct {
		state string
		want  bool
	}{
		{`{"hasCompletedOnboarding": true}`, true},
		{`{"hasCompletedOnboarding": "true"}`, false},
		{`{"hasCompletedOnboarding": false}`, false},
		{`{}`, false},
		{`not json`, false},
		{``, false},
	} {
		if got := c.Onboarded([]byte(tc.state)); got != tc.want {
			t.Errorf("Onboarded(%q) = %v, want %v", tc.state, got, tc.want)
		}
	}
	seed, err := c.Seed([]byte(`{"hasCompletedOnboarding":true,"theme":"dark","nested":{"a":1},"oauthAccount":{"emailAddress":"x"},"primaryApiKey":"k","userID":"u"}`))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(seed, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["hasCompletedOnboarding"] != true || got["theme"] != "dark" {
		t.Fatalf("seed = %s, want only the onboarding flag and the theme", seed)
	}
	if _, err := c.Seed([]byte(`[1]`)); err == nil {
		t.Fatal("a state file that is not an object was seeded")
	}
}

// TestSandboxConfigHomeRowsAreWhole: every row that declares a config home
// names all of its parts, and its seed never lists a credential-shaped key.
func TestSandboxConfigHomeRowsAreWhole(t *testing.T) {
	seen := 0
	for _, c := range Capabilities() {
		ch := c.Sandbox.ConfigHome
		if ch == nil {
			continue
		}
		seen++
		if ch.Env == "" || ch.Dir == "" || ch.StateFile == "" || ch.RelocatedStateFile == "" || ch.OnboardedKey == "" || ch.Grounding == "" {
			t.Errorf("%s: config home %+v is incomplete", c.Tool, *ch)
		}
		if len(c.Sandbox.StateRW) == 0 {
			t.Errorf("%s: a config home on a row that is not sandbox-launchable", c.Tool)
		}
		for _, k := range ch.SeedKeys {
			for _, bad := range []string{"key", "token", "secret", "oauth", "account", "password", "credential"} {
				if containsFold(k, bad) {
					t.Errorf("%s: seed key %q looks like a credential", c.Tool, k)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no row declares a sandbox config home")
	}
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
