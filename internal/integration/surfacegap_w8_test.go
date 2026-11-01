package integration

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestWave8SurfaceRows pins the per-surface route and hook rows surface-gap
// lane w8-registry added (gap review S-1, S-4, IDE-9, CLI-9; the 2026-10-27
// macOS IDE round MAC-5), one case per row, so a later edit cannot quietly
// restore the older claim.
func TestWave8SurfaceRows(t *testing.T) {
	routes := []struct {
		tool, kind, host string
		want             RouteStatus
		liveCheck        string
	}{
		{"kilo-code-cli", models.SurfaceIDE, "vscode", RouteStatusProbeRequired, "LC16, LC24"},
		{"kilo-code-cli", models.SurfaceIDE, "jetbrains-idea", RouteStatusProbeRequired, "LC16, LC24"},
		{"goose", models.SurfaceIDE, "vscode", RouteStatusProbeRequired, "LCR-62"},
		// MAC-1 read 2026-10-28: Xcode's Claude reads only its own
		// CodingAssistant/ClaudeAgentConfig home.
		{"claude-code", models.SurfaceIDE, "xcode", RouteStatusSettingsIgnored, "LCR-89"},
		{"gemini-cli", models.SurfaceIDE, "vscode", RouteStatusProbeRequired, "LC27, LC28"},
	}
	for _, tc := range routes {
		c, _ := For(tc.tool)
		row, m := c.RouteSurfaceFor(tc.kind, tc.host)
		if m == SurfaceMatchTool || row.EffectiveRoutability(c) != tc.want || row.LiveCheck != tc.liveCheck {
			t.Errorf("%s %s/%s: %q (match %s, live check %q), want %q from a declared row naming %q",
				tc.tool, tc.kind, tc.host, row.EffectiveRoutability(c), m, row.LiveCheck, tc.want, tc.liveCheck)
		}
	}
	// The CLI rows of the unstamped tools still judge their sessions.
	for _, tool := range []string{"goose", "gemini-cli"} {
		c, _ := For(tool)
		if u, ok := c.UnstampedSurface(); !ok || u.Kind != models.SurfaceCLI {
			t.Errorf("%s: unstamped sessions are no longer judged by the CLI row (%+v, %v)", tool, u, ok)
		}
	}

	hooks := []struct {
		tool, kind, host string
		want             HookSurfaceRun
	}{
		{"claude-code", models.SurfaceIDE, "jetbrains-idea", HookSurfaceSkipped},
		{"claude-code", models.SurfaceIDE, "jetbrains-pycharm", HookSurfaceSkipped},
		// The Claude Code JetBrains plugin (claude-jetbrains entrypoint,
		// generic host) runs the CLI and keeps the IDE kind row.
		{"claude-code", models.SurfaceIDE, "jetbrains", HookSurfaceRuns},
		{"claude-code", models.SurfaceIDE, "vscode", HookSurfaceRuns},
		// FU-153: the Kiro IDE runs ~/.kiro/hooks in a trusted workspace
		// only; Observer's own file there is not live-run.
		{"kiro-cli", models.SurfaceIDE, "kiro", HookSurfaceUnknown},
		{"kiro-cli", models.SurfaceDesktop, "kiro-crew", HookSurfaceSkipped},
		{"opencode", models.SurfaceDesktop, "", HookSurfaceUnknown},
		// MAC-1 read 2026-10-28: neither Xcode agent reads ~/.claude or
		// ~/.codex (Codex through its IDE kind row).
		{"claude-code", models.SurfaceIDE, "xcode", HookSurfaceSkipped},
		{"codex", models.SurfaceIDE, "xcode", HookSurfaceSkipped},
		// Every IDE surface the lane gave a route row has a hook row too, so
		// its tool gate reads unknown there, never gated by default.
		{"gemini-cli", models.SurfaceIDE, "vscode", HookSurfaceUnknown},
		{"goose", models.SurfaceIDE, "vscode", HookSurfaceUnknown},
		{"kilo-code-cli", models.SurfaceIDE, "jetbrains-idea", HookSurfaceUnknown},
	}
	for _, tc := range hooks {
		c, _ := For(tc.tool)
		got, m := c.Hook.SurfaceFor(tc.kind, tc.host)
		if got.Runs != tc.want || m == SurfaceMatchTool {
			t.Errorf("%s %s/%s: Runs %q (match %s), want %q from a declared row", tc.tool, tc.kind, tc.host, got.Runs, m, tc.want)
		}
	}
}

// TestSurfaceCaveatStatesEachFactOnce: the JetBrains Claude Agent fact is
// declared once per product host, and the admin caveat says it once.
func TestSurfaceCaveatStatesEachFactOnce(t *testing.T) {
	c, _ := For("claude-code")
	cav := c.Hook.SurfaceCaveat()
	if n := strings.Count(cav, "JetBrains AI Assistant (ACP)"); n != 1 {
		t.Errorf("claude-code caveat names the JetBrains Claude Agent %d times, want 1: %q", n, cav)
	}
}
