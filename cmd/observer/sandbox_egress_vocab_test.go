package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// TestSandboxEgressConfigVocabularyMatchesPlanner pins that config validation
// accepts exactly the planner's tier table (plus the empty default), so a tier
// added in internal/sandbox cannot be unconfigurable and a config typo cannot
// reach the planner.
func TestSandboxEgressConfigVocabularyMatchesPlanner(t *testing.T) {
	check := func(v string) error {
		c := config.Default()
		c.Terminal.Sandbox.Egress = v
		return config.Validate(c)
	}
	for _, m := range append([]string{""}, sandbox.EgressModes()...) {
		if err := check(m); err != nil {
			t.Errorf("config rejects planner tier %q: %v", m, err)
		}
		if _, err := sandbox.ResolveEgress(m); err != nil {
			t.Errorf("planner rejects %q: %v", m, err)
		}
	}
	for _, bad := range []string{"shared", "HOST", "internet "} {
		if check(bad) == nil {
			t.Errorf("config accepted %q", bad)
		}
	}
	if config.Default().Terminal.Sandbox.Egress != string(sandbox.DefaultEgress) {
		t.Errorf("config default egress %q != planner default %q", config.Default().Terminal.Sandbox.Egress, sandbox.DefaultEgress)
	}
}

// TestSandboxHelperDispatch: only the two helper verbs are intercepted before
// cobra; everything else falls through untouched.
func TestSandboxHelperDispatch(t *testing.T) {
	for _, argv := range [][]string{{"observer"}, {"observer", "claude"}, {"observer", "sandbox"}, {"observer", "start"}} {
		if _, ok := sandboxHelperDispatch(argv); ok {
			t.Errorf("dispatch intercepted %v", argv)
		}
	}
	// A helper verb with bad args is intercepted and fails closed.
	for _, verb := range []string{sandbox.HostVerb, sandbox.GuestVerb} {
		code, ok := sandboxHelperDispatch([]string{"observer", verb, "--bogus"})
		if !ok || code == 0 {
			t.Errorf("%s with bad args: ok=%v code=%d, want intercepted + non-zero", verb, ok, code)
		}
	}
}
