package integration

import (
	"strings"
	"testing"
)

// TestRemoteSeed (FX4 item 4, F-L3P4-8): a hosted box is seeded onboarded
// whatever this machine's state says; the seed keys come from this
// machine's state only as scalars; nothing else ever does; a row with no
// onboarded key seeds nothing.
func TestRemoteSeed(t *testing.T) {
	c := SandboxConfigHome{OnboardedKey: "hasCompletedOnboarding", SeedKeys: []string{"hasCompletedOnboarding", "theme"}}
	cases := []struct {
		name, state string
		want        string
	}{
		{"onboarded here", `{"hasCompletedOnboarding":true,"theme":"dark","userID":"u"}`, `{"hasCompletedOnboarding":true,"theme":"dark"}`},
		{"never started here", `{"theme":"light","oauthAccount":{"emailAddress":"dev@example.com"}}`, `{"hasCompletedOnboarding":true,"theme":"light"}`},
		{"false here", `{"hasCompletedOnboarding":false}`, `{"hasCompletedOnboarding":true}`},
		{"no state", ``, `{"hasCompletedOnboarding":true}`},
		{"not an object", `[1,2]`, `{"hasCompletedOnboarding":true}`},
		{"a theme that is not a scalar", `{"theme":{"x":1}}`, `{"hasCompletedOnboarding":true}`},
	}
	for _, tc := range cases {
		got, ok := c.RemoteSeed([]byte(tc.state))
		if !ok || string(got) != tc.want {
			t.Errorf("%s: %s %v, want %s", tc.name, got, ok, tc.want)
		}
		if strings.Contains(string(got), "userID") || strings.Contains(string(got), "example.com") {
			t.Errorf("%s: a non-seed key: %s", tc.name, got)
		}
	}
	if _, ok := (SandboxConfigHome{SeedKeys: []string{"theme"}}).RemoteSeed([]byte(`{"theme":"dark"}`)); ok {
		t.Error("a row with no onboarded key seeded")
	}
}

// TestApproveKey (FX4 fix round 1, F-P6B-2a): the approval merge keeps every
// other key, records the value by its last Suffix characters once, takes it
// out of the rejected list, and refuses a state or answers value that is
// not an object; the claude-code row declares where Claude Code records it.
func TestApproveKey(t *testing.T) {
	a := SandboxKeyApproval{Env: "ANTHROPIC_API_KEY", Key: "customApiKeyResponses", Suffix: 4}
	cases := []struct {
		name, state, want string
		err               bool
	}{
		{"empty state", "", `{"customApiKeyResponses":{"approved":["WXYZ"],"rejected":[]}}`, false},
		{"other keys kept", `{"theme":"dark","n":{"a":1}}`, `{"customApiKeyResponses":{"approved":["WXYZ"],"rejected":[]},"n":{"a":1},"theme":"dark"}`, false},
		{"once, and out of rejected", `{"customApiKeyResponses":{"approved":["WXYZ","OLD1"],"rejected":["WXYZ","BAD1"],"extra":true}}`, `{"customApiKeyResponses":{"approved":["WXYZ","OLD1"],"extra":true,"rejected":["BAD1"]}}`, false},
		{"state not an object", `[1]`, "", true},
		{"answers not an object", `{"customApiKeyResponses":"x"}`, "", true},
	}
	for _, tc := range cases {
		got, err := a.ApproveKey([]byte(tc.state), "sbo-sentinel-WXYZ")
		if (err != nil) != tc.err || (!tc.err && string(got) != tc.want) {
			t.Errorf("%s: %s %v, want %s", tc.name, got, err, tc.want)
		}
		if !tc.err && !a.Approved(got, "sbo-sentinel-WXYZ") {
			t.Errorf("%s: Approved is false after ApproveKey", tc.name)
		}
	}
	if a.Approved([]byte(`{"customApiKeyResponses":{"approved":["WXYZ"],"rejected":["WXYZ"]}}`), "WXYZ") {
		t.Error("a rejected value counts as approved")
	}
	c, ok := For("claude-code")
	if !ok || c.Sandbox.ConfigHome == nil || c.Sandbox.ConfigHome.KeyApproval == nil {
		t.Fatal("the claude-code row declares no key approval")
	}
	if k := c.Sandbox.ConfigHome.KeyApproval; k.Env != "ANTHROPIC_API_KEY" || k.Key != "customApiKeyResponses" || k.Suffix != 20 || k.Grounding == "" {
		t.Fatalf("claude-code key approval %+v", k)
	}
}
