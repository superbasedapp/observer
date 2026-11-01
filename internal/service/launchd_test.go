package service

import (
	"strings"
	"testing"
)

func TestRenderLaunchAgent(t *testing.T) {
	got := RenderLaunchAgent(LaunchAgentOptions{
		ExecPath: "/Users/dev/.local/bin/observer",
		Args:     []string{"--config", "/Users/dev/my <cfg>/config.toml", "--port", "8821"},
		LogPath:  "/Users/dev/Library/Logs/SuperBased/observer.log",
		Path:     "/opt/homebrew/bin:/usr/bin:/bin",
	})
	for _, want := range []string{
		"<string>app.superbased.observer</string>",
		"<string>/Users/dev/.local/bin/observer</string>\n    <string>start</string>",
		"<string>/Users/dev/my &lt;cfg&gt;/config.toml</string>",
		"<key>PATH</key>\n    <string>/opt/homebrew/bin:/usr/bin:/bin</string>",
		"<key>RunAtLoad</key>\n  <true/>",
		"<key>SuccessfulExit</key>\n    <false/>",
		"<key>StandardErrorPath</key>\n  <string>/Users/dev/Library/Logs/SuperBased/observer.log</string>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("plist lacks %q:\n%s", want, got)
		}
	}
	if again := RenderLaunchAgent(LaunchAgentOptions{
		ExecPath: "/Users/dev/.local/bin/observer",
		Args:     []string{"--config", "/Users/dev/my <cfg>/config.toml", "--port", "8821"},
		LogPath:  "/Users/dev/Library/Logs/SuperBased/observer.log",
		Path:     "/opt/homebrew/bin:/usr/bin:/bin",
	}); again != got {
		t.Error("rendering is not deterministic")
	}
	if !strings.Contains(RenderLaunchAgent(LaunchAgentOptions{ExecPath: "/x"}), DefaultPath) {
		t.Error("an empty Path must fall back to DefaultPath")
	}
}

func TestLaunchAgentProgramArgumentsRoundTrip(t *testing.T) {
	args := []string{"/Applications/x y/observer", "start", "--config", "/a&b/<c>.toml"}
	plist := RenderLaunchAgent(LaunchAgentOptions{ExecPath: args[0], Args: args[2:], LogPath: "/l"})
	got, ok := LaunchAgentProgramArguments(plist)
	if !ok || strings.Join(got, "|") != strings.Join(args, "|") {
		t.Fatalf("round trip = %v (%v), want %v", got, ok, args)
	}
	if _, ok := LaunchAgentProgramArguments("<plist></plist>"); ok {
		t.Error("a plist without ProgramArguments must report ok=false")
	}
}

func TestLaunchdCommands(t *testing.T) {
	if got := LaunchdTarget(501); got != "gui/501/app.superbased.observer" {
		t.Errorf("LaunchdTarget = %q", got)
	}
	if got := LaunchAgentPath("/Users/dev"); got != "/Users/dev/Library/LaunchAgents/app.superbased.observer.plist" {
		t.Errorf("LaunchAgentPath = %q", got)
	}
	c := Launchctl("bootstrap", LaunchdDomain(501), "/p.plist")
	if c.Name != "launchctl" || strings.Join(c.Args, " ") != "bootstrap gui/501 /p.plist" {
		t.Errorf("Launchctl = %+v", c)
	}
	cases := []struct {
		follow bool
		lines  int
		want   string
	}{
		{false, 200, "-n 200 /l"},
		{true, 0, "-f /l"},
		{true, 50, "-n 50 -f /l"},
	}
	for _, tc := range cases {
		if got := strings.Join(TailLog("/l", tc.follow, tc.lines).Args, " "); got != tc.want {
			t.Errorf("TailLog(%v,%d) = %q, want %q", tc.follow, tc.lines, got, tc.want)
		}
	}
}
