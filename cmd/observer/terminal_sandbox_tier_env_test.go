//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// tierWrap is a wrap argv shaped like a local driver's: an outer prefix,
// then the host helper for tier with the relay on.
func tierWrap(t *testing.T, tier sandbox.Egress) []string {
	t.Helper()
	host, err := sandbox.RelayHostArgv("/usr/local/bin/observer", sandbox.NetRequest{
		Egress: tier, ProxyPort: 8820, HostSocketDir: "/tmp/observer-sbx-run1",
	}, nil, sandbox.RelayRequest{RunID: "AbCdEfGhIjKlMnOpQrStUv", HostObserverDir: "/home/dev/.observer"})
	if err != nil {
		t.Fatal(err)
	}
	// The host helper's argv ends at its "--"; the box command follows.
	return append(append([]string{"/usr/local/bin/observer", "sandbox-seatbelt-host", "--plan", "/p.json", "--"}, host...), "/usr/bin/bwrap")
}

// TestSandboxTierEnvEveryTier (P-094 residual, lane SHR-FOLLOWUPS): a local
// launch's child carries OBSERVER_SANDBOX_EGRESS with the tier its wrap's
// host helper runs, for every tier of the table; a wrap with no host helper
// carries none.
func TestSandboxTierEnvEveryTier(t *testing.T) {
	skipOnWindows(t, "the bwrap and oci relay argv takes a POSIX host socket directory")
	for _, m := range sandbox.EgressModes() {
		got := sandboxTierEnv(tierWrap(t, sandbox.Egress(m)))
		if len(got) != 1 || got[0] != sandbox.EnvEgress+"="+m {
			t.Errorf("tier %s: %q", m, got)
		}
	}
	if got := sandboxTierEnv([]string{"/usr/bin/bwrap", "--ro-bind", "/", "/", "--"}); got != nil {
		t.Errorf("a wrap with no host helper: %q", got)
	}
	if got := sandboxTierEnv(nil); got != nil {
		t.Errorf("no wrap: %q", got)
	}
}

// TestLaunchChildEnvCarriesTheTier: the dashboard launcher sets the tier
// beside the marker, after any inherited value, so the in-box notice under
// none is the tier's own; an unsandboxed launch sets neither.
func TestLaunchChildEnvCarriesTheTier(t *testing.T) {
	skipOnWindows(t, "the bwrap and oci relay argv takes a POSIX host socket directory")
	t.Setenv(sandbox.EnvEgress, "internet") // an inherited value never wins
	env := launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", Sandboxed: true, WrapArgv: tierWrap(t, sandbox.EgressNone)}, "tok")
	last := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, sandbox.EnvEgress+"="); ok {
			last = v
		}
	}
	if last != "none" || !slices.Contains(env, sandboxEnvMarker+"=1") {
		t.Fatalf("the launch's tier is %q (marker %v)", last, slices.Contains(env, sandboxEnvMarker+"=1"))
	}
	plain := launchChildEnv(termsvc.LaunchRequest{Tool: "claude-code", WrapArgv: tierWrap(t, sandbox.EgressNone)}, "tok")
	if slices.Contains(plain, sandbox.EnvEgress+"=none") || slices.Contains(plain, sandboxEnvMarker+"=1") {
		t.Fatal("an unsandboxed launch carries the tier or the marker")
	}
	// What the launcher inside the box then says (the child sees the last
	// value).
	t.Setenv(sandboxEnvMarker, "1")
	t.Setenv(sandbox.EnvEgress, last)
	if got := sandboxTierRouteNotice("claude-code", "http://127.0.0.1:8820"); !strings.Contains(got, "none") {
		t.Fatalf("the in-box notice under none: %q", got)
	}
}
