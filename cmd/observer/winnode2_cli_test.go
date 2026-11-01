package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestWindowsBridgeBrowserHomes (WINNODE2 16c): the wsl.exe browser bridge
// exists only from a Linux (WSL) daemon; a native Windows daemon offers it
// for no home, so `observer init --all` prints no "WSL distro is unknown"
// lines there.
func TestWindowsBridgeBrowserHomes(t *testing.T) {
	all := []crossmount.HomeRoot{
		{Path: `C:\Users\developer`, OS: crossmount.OSWindows},
		{Path: `\\wsl.localhost\Ubuntu\home\dev`, OS: crossmount.OSLinux},
	}
	if got := windowsBridgeBrowserHomes("windows", all); len(got) != 0 {
		t.Fatalf("native Windows offers the bridge for %v", got)
	}
	got := windowsBridgeBrowserHomes("linux", []crossmount.HomeRoot{{Path: "/mnt/c/Users/dev", OS: crossmount.OSWindows}})
	if len(got) != 1 || got[0] != "/mnt/c/Users/dev" {
		t.Fatalf("WSL daemon: homes = %v", got)
	}
}

// TestProxyRoutingHintShellAndRoutedSettings (WINNODE2 16c): a Windows host
// is told the PowerShell spelling, never a bash export, and no hint is due
// when Claude Code's settings.json already routes to this proxy.
func TestProxyRoutingHintShellAndRoutedSettings(t *testing.T) {
	var win, posix bytes.Buffer
	printProxyRoutingHintFor(&win, 8820, "windows")
	printProxyRoutingHintFor(&posix, 8820, "linux")
	if strings.Contains(win.String(), "export ") || !strings.Contains(win.String(), `$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8820"`) {
		t.Fatalf("windows hint:\n%s", win.String())
	}
	if !strings.Contains(posix.String(), "export ANTHROPIC_BASE_URL=http://127.0.0.1:8820") {
		t.Fatalf("posix hint:\n%s", posix.String())
	}

	home := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if claudeRoutedTo(home, 8820) {
		t.Fatal("an empty home reads as routed")
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}}`
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if !claudeRoutedTo(home, 8820) {
		t.Fatal("settings.json carrying this proxy's URL does not read as routed")
	}
	if claudeRoutedTo(home, 8899) {
		t.Fatal("a route to another port reads as routed to this one")
	}
}

// TestDashboardHelpDescribesTheDashboard (WINNODE2 16c): the help no longer
// describes the retired single-file HTML page and its five endpoints.
func TestDashboardHelpDescribesTheDashboard(t *testing.T) {
	cmd := newDashboardCmd()
	for _, old := range []string{"single-file", "/api/discover, /api/patterns"} {
		if strings.Contains(cmd.Long+cmd.Short, old) {
			t.Fatalf("help still says %q:\n%s", old, cmd.Long)
		}
	}
	if !strings.Contains(cmd.Long, "same node dashboard") {
		t.Fatalf("help does not say what it serves:\n%s", cmd.Long)
	}
}

// TestPricingCoverageNeverABareCount (WINNODE2 16d): unpriced rows always
// come with what they are: the models, or that none can be named.
func TestPricingCoverageNeverABareCount(t *testing.T) {
	named := budgetPricingCoverageLine(budgetPricingCoverage{Coverage: "partial", UnpricedRows: 3, UnpricedModels: []string{"gemini-3.8-flash-n"}})
	if !strings.Contains(named, "unpriced_rows=3 unpriced_models=gemini-3.8-flash-n") {
		t.Fatalf("named: %q", named)
	}
	unnamed := budgetPricingCoverageLine(budgetPricingCoverage{Coverage: "partial", UnpricedRows: 2})
	if !strings.Contains(unnamed, "unpriced_rows=2 unpriced_models=none-named(invalid-rows)") {
		t.Fatalf("unnamed: %q", unnamed)
	}
}
