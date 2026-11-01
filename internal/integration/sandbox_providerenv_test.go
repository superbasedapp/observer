package integration_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// providerEnvName is a variable NAME a ProviderEnv list may hold (the
// internal/sandboxenv.ValidName shape).
var providerEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// TestSandboxProviderEnvWellFormed pins the names-only contract of every
// row's Sandbox.ProviderEnv (WINFIX2 audit finding 1): a bare variable name,
// never OBSERVER_ (Observer sets its own), never a base-URL variable
// (Observer sets the route itself after the allow-list), no duplicate.
func TestSandboxProviderEnvWellFormed(t *testing.T) {
	for _, c := range integration.Capabilities() {
		seen := map[string]bool{}
		for i, k := range c.Sandbox.ProviderEnv {
			switch {
			case !providerEnvName.MatchString(k):
				t.Errorf("adapter %q: Sandbox.ProviderEnv[%d] = %q is not a variable name", c.Tool, i, k)
			case strings.HasPrefix(strings.ToUpper(k), "OBSERVER_"):
				t.Errorf("adapter %q: Sandbox.ProviderEnv[%d] = %q is Observer's own variable", c.Tool, i, k)
			case strings.HasSuffix(k, "_BASE_URL"):
				t.Errorf("adapter %q: Sandbox.ProviderEnv[%d] = %q is a route Observer sets itself", c.Tool, i, k)
			}
			if seen[k] {
				t.Errorf("adapter %q: Sandbox.ProviderEnv has a duplicate %q", c.Tool, k)
			}
			seen[k] = true
		}
		if len(c.Sandbox.ProviderEnv) > 0 && len(c.Sandbox.StateRW)+len(c.Sandbox.StateRO) == 0 {
			t.Errorf("adapter %q: Sandbox.ProviderEnv set on a row with no sandbox state (not sandbox-launchable)", c.Tool)
		}
	}
}

// TestSandboxProviderEnvCoversAuthEnv pins that a sandbox-launchable row's
// credential variables reach its box: every AuthEnv name is in its
// ProviderEnv, so the allow-list never silently takes away the key a
// developer launches the tool with.
func TestSandboxProviderEnvCoversAuthEnv(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if len(c.Sandbox.StateRW)+len(c.Sandbox.StateRO) == 0 {
			continue
		}
		have := map[string]bool{}
		for _, k := range c.Sandbox.ProviderEnv {
			have[k] = true
		}
		for _, k := range c.AuthEnv {
			if !have[k] {
				t.Errorf("adapter %q: AuthEnv %q is not in Sandbox.ProviderEnv, so a sandboxed run would not get it", c.Tool, k)
			}
		}
	}
}

// TestSandboxProviderEnvConfigHome pins that a row whose config home moves
// with a variable (SandboxConfigHome.Env) lets the user's own value of that
// variable reach the box: the run-local folder replaces it only when the
// user's folder does not exist.
func TestSandboxProviderEnvConfigHome(t *testing.T) {
	for _, c := range integration.Capabilities() {
		ch := c.Sandbox.ConfigHome
		if ch == nil || ch.Env == "" {
			continue
		}
		found := false
		for _, k := range c.Sandbox.ProviderEnv {
			found = found || k == ch.Env
		}
		if !found {
			t.Errorf("adapter %q: its config-home variable %s is not in Sandbox.ProviderEnv", c.Tool, ch.Env)
		}
	}
}
