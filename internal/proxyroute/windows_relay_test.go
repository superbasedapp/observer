package proxyroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/winrelay"
)

// forceRelayRoute runs the relay route switch in the given position for one
// test (restored on cleanup).
func forceRelayRoute(t *testing.T, on bool) {
	t.Helper()
	prev := relayRouteOn
	relayRouteOn = func() bool { return on }
	t.Cleanup(func() { relayRouteOn = prev })
}

func readWindowsClaudeBaseURL(t *testing.T, winHome string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(winHome, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s.Env["ANTHROPIC_BASE_URL"]
}

// TestRelayRouteIsSwitchedOffByDefault pins DEC-12 for CC-9: until LC6 and
// LC14 pass, the Windows Claude Code route keeps the WSL proxy target in
// every caller, because the writer itself decides it.
func TestRelayRouteIsSwitchedOffByDefault(t *testing.T) {
	if relayRouteOn() {
		t.Fatal("the relay route must stay off while winrelay's live-check gate waits")
	}
	if !winrelay.Gate().Waiting() {
		t.Fatal("winrelay's gate was cleared; switch-on is its own commit after LC6 and LC14")
	}
	r, winHome := newWindowsRegistrar(t, 8820)
	if res := r.RegisterClaudeCodeWindows(); res.Error != nil {
		t.Fatalf("RegisterClaudeCodeWindows: %v", res.Error)
	}
	if got := readWindowsClaudeBaseURL(t, winHome); got != "http://localhost:8820" {
		t.Fatalf("gated route wrote %q, want the WSL proxy target", got)
	}
}

// TestRelayRouteWhenSwitchedOn runs the switched-on branch: the Claude Code
// route points at the relay, codex keeps the WSL proxy, and a proxy on the
// relay's own port keeps the WSL proxy target.
func TestRelayRouteWhenSwitchedOn(t *testing.T) {
	forceRelayRoute(t, true)
	r, winHome := newWindowsRegistrar(t, 8820)
	if res := r.RegisterClaudeCodeWindows(); res.Error != nil || res.BaseURL != "http://127.0.0.1:8829/r/claude-code" {
		t.Fatalf("RegisterClaudeCodeWindows = %+v", res)
	}
	if got := readWindowsClaudeBaseURL(t, winHome); got != "http://127.0.0.1:8829/r/claude-code" {
		t.Fatalf("route = %q, want the relay URL", got)
	}
	if !IsObserverBaseURL("http://127.0.0.1:8829/r/claude-code") {
		t.Fatal("the relay URL must read as an Observer route (doctor, Leave, re-runs)")
	}
	if res := r.RegisterCodexWindows(); res.Error != nil || res.BaseURL != "http://localhost:8820/v1" {
		t.Fatalf("codex must keep the WSL proxy target (no relay lane): %+v", res)
	}
	if got := windowsClaudeRouteURL(winrelay.DefaultPort); got != windowsBaseURL(winrelay.DefaultPort) {
		t.Fatalf("a proxy on the relay's port must keep the proxy target, got %q", got)
	}
}
