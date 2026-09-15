package main

import (
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launchseed_identity_test.go pins the two silent-miss classes
// launchSeedIdentity closes at the ONE seam every `observer <verb>` launcher
// funnels its launch seed through. Both were adapter-wide, not
// opencode-specific: a seed whose tool is a launcher LABEL rather than the
// canonical adapter key never matches any session, and a seed with an empty
// cwd matches a same-tool session in ANY project.

func TestLaunchSeedIdentity_CanonicalisesLauncherVerbs(t *testing.T) {
	t.Parallel()
	getwd := func() (string, error) { return "/wd", nil }

	cases := []struct {
		name string
		in   string
		want string
	}{
		// The bug that was already caught once and patched by hand at a single
		// call site (launch.go's seedTool override).
		{"gemini verb resolves to its adapter key", "gemini", "gemini-cli"},
		// The same shape at verbs that never got the hand patch.
		{"kilo verb resolves to its adapter key", "kilo", "kilo-code-cli"},
		{"kiro verb resolves to its adapter key", "kiro", "kiro-cli"},
		{"qwen verb resolves to its adapter key", "qwen", "qwen-code"},
		{"vibe verb resolves to its adapter key", "vibe", "mistral-code"},
		{"claude verb resolves to its adapter key", "claude", "claude-code"},
		// A verb that already equals its adapter key is a no-op.
		{"opencode verb is already canonical", "opencode", "opencode"},
		// An adapter key that is not any verb passes through untouched — the
		// canonicalisation may only ever correct a verb, never rewrite a tool.
		{"canonical key passes through", "claude-code", "claude-code"},
		{"unknown name passes through", "not-a-tool", "not-a-tool"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := launchSeedIdentity(tc.in, "/dir", getwd)
			if got != tc.want {
				t.Fatalf("launchSeedIdentity(%q) tool = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestLaunchSeedIdentity_CanonicalisationIsIdempotent is the drift gate for the
// mapping itself. Canonicalising is only safe while no adapter's canonical key
// is ALSO some OTHER adapter's launcher verb — otherwise a launcher passing its
// own correct tool name would be silently rewritten to a different adapter, and
// the launch seed would bind a HIGH-confidence bridge row to the wrong session.
// Walks the registry so a new adapter row is covered without editing this test.
func TestLaunchSeedIdentity_CanonicalisationIsIdempotent(t *testing.T) {
	t.Parallel()
	tools := integration.Tools()
	if len(tools) == 0 {
		t.Fatal("integration.Tools() is empty — the test premise is unverifiable")
	}
	for _, tool := range tools {
		tool := tool
		t.Run(tool, func(t *testing.T) {
			t.Parallel()
			got, _ := launchSeedIdentity(tool, "/dir", nil)
			if got != tool {
				t.Fatalf("launchSeedIdentity(%q) rewrote a canonical adapter key to %q — some other adapter declares %q as its launcher verb, so recordLaunchSeed would bind the wrong tool", tool, got, tool)
			}
		})
	}
}

// TestLaunchSeedIdentity_EveryLaunchVerbResolves pins the class the sweep
// found: every registry row that declares a launcher verb must resolve back to
// a tool key, so no launcher can record a seed the matcher cannot pair.
func TestLaunchSeedIdentity_EveryLaunchVerbResolves(t *testing.T) {
	t.Parallel()
	var verbs int
	for _, tool := range integration.Tools() {
		capab, ok := integration.For(tool)
		if !ok || !capab.Handoff.Launchable() {
			continue
		}
		verb := capab.Handoff.Launch.Subcommand
		if verb == "" {
			continue
		}
		verbs++
		got, _ := launchSeedIdentity(verb, "/dir", nil)
		if got != tool {
			t.Errorf("launchSeedIdentity(%q) = %q, want the declaring adapter key %q — a launcher passing its verb would record an unmatchable launch seed", verb, got, tool)
		}
	}
	if verbs == 0 {
		t.Fatal("no launcher verbs resolved from the registry — the test premise is unverifiable")
	}
}

func TestLaunchSeedIdentity_FreshLaunchFallsBackToLauncherCWD(t *testing.T) {
	t.Parallel()
	// A fresh launch (every dashboard "New Terminal" launch) leaves dir empty:
	// the child inherits the launcher's cwd. Without the fallback the seed
	// carries the empty wildcard and can pair with a same-tool session in any
	// project.
	_, cwd := launchSeedIdentity("opencode", "", func() (string, error) { return "/home/u/proj", nil })
	if cwd != "/home/u/proj" {
		t.Fatalf("cwd = %q, want the launcher's own working directory", cwd)
	}
}

func TestLaunchSeedIdentity_ExplicitDirWins(t *testing.T) {
	t.Parallel()
	// --continue-from sets dir to the SOURCE project root, which is not the
	// launcher's cwd. It must never be overwritten.
	_, cwd := launchSeedIdentity("opencode", "/explicit", func() (string, error) { return "/home/u/elsewhere", nil })
	if cwd != "/explicit" {
		t.Fatalf("cwd = %q, want the explicit --continue-from directory", cwd)
	}
}

func TestLaunchSeedIdentity_UnreadableCWDKeepsWildcard(t *testing.T) {
	t.Parallel()
	// Fail-open: an unreadable cwd must leave the pre-existing wildcard in
	// place rather than blocking the seed. A wildcard match still beats none.
	_, cwd := launchSeedIdentity("opencode", "", func() (string, error) { return "", errors.New("boom") })
	if cwd != "" {
		t.Fatalf("cwd = %q, want the empty wildcard preserved on a getwd failure", cwd)
	}
}

// TestLaunchSeedRunID is the launcher half of the 9f deterministic binding
// (migration 091). The run id reaches the launcher through an INHERITED
// environment variable, so the whole correctness of the feature rests on the
// guard: only the process holding the daemon's authenticated out-of-band
// channel may treat it as identity. A descendant that merely inherited the
// variable must record nothing and fall back to the heuristic.
func TestLaunchSeedRunID(t *testing.T) {
	t.Parallel()
	env := func(vals map[string]string) func(string) string {
		return func(k string) string { return vals[k] }
	}
	cases := []struct {
		name      string
		vals      map[string]string
		oobActive bool
		want      string
		why       string
	}{
		{
			name:      "the daemon's own launcher child records the run",
			vals:      map[string]string{envOOBRun: "run-A"},
			oobActive: true,
			want:      "run-A",
			why:       "it holds the authenticated channel, so it IS the process the daemon spawned for this run",
		},
		{
			name:      "a nested launch inherits the variable but not the channel",
			vals:      map[string]string{envOOBRun: "run-A"},
			oobActive: false,
			want:      "",
			why:       "binding here would attribute the nested child to the OUTER run's session — worse than the heuristic",
		},
		{
			name:      "a plain shell invocation has neither",
			vals:      map[string]string{},
			oobActive: false,
			want:      "",
			why:       "no run exists; a fabricated id would be worse than none",
		},
		{
			name:      "an authenticated channel with no run id claims nothing",
			vals:      map[string]string{},
			oobActive: true,
			want:      "",
			why:       "absence stays absence rather than becoming an empty-string binding",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := launchSeedRunID(env(tc.vals), tc.oobActive); got != tc.want {
				t.Errorf("launchSeedRunID() = %q, want %q (%s)", got, tc.want, tc.why)
			}
		})
	}
}

// TestLaunchSeedRunIDNilGetenv pins the fail-safe: a caller with no env lookup
// gets absence, never a panic on a best-effort path that must never block a
// tool launch.
func TestLaunchSeedRunIDNilGetenv(t *testing.T) {
	t.Parallel()
	if got := launchSeedRunID(nil, true); got != "" {
		t.Errorf("launchSeedRunID(nil, true) = %q, want \"\"", got)
	}
}
