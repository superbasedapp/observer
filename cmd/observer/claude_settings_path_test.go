package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestClaudeUserSettingsPathRefusesRelative pins FU-131: a relative
// CLAUDE_CONFIG_DIR / ANTHROPIC_CONFIG_DIR is refused (no path, the variable
// named), never joined against Observer's own working directory and never
// replaced by the ~/.claude default; an absolute one wins; with neither set
// the home default applies.
func TestClaudeUserSettingsPathRefusesRelative(t *testing.T) {
	abs := "/opt/claude-cfg"
	if runtime.GOOS == "windows" {
		abs = `C:\claude-cfg`
	}
	home := func() (string, error) { return filepath.FromSlash("/home/dev"), nil }
	noHome := func() (string, error) { return "", errors.New("no home") }
	for _, tc := range []struct {
		name        string
		env         map[string]string
		home        func() (string, error)
		wantPath    string
		wantRefused string
	}{
		{"default", nil, home, filepath.Join(filepath.FromSlash("/home/dev"), ".claude", "settings.json"), ""},
		{"absolute CLAUDE_CONFIG_DIR", map[string]string{"CLAUDE_CONFIG_DIR": abs}, home, filepath.Join(abs, "settings.json"), ""},
		{"relative CLAUDE_CONFIG_DIR", map[string]string{"CLAUDE_CONFIG_DIR": "cfg"}, home, "", "CLAUDE_CONFIG_DIR"},
		{"relative ANTHROPIC_CONFIG_DIR", map[string]string{"ANTHROPIC_CONFIG_DIR": "./x"}, home, "", "ANTHROPIC_CONFIG_DIR"},
		{"CLAUDE_CONFIG_DIR wins over ANTHROPIC_CONFIG_DIR", map[string]string{"CLAUDE_CONFIG_DIR": "rel", "ANTHROPIC_CONFIG_DIR": abs}, home, "", "CLAUDE_CONFIG_DIR"},
		{"no home", nil, noHome, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			p, refused := claudeUserSettingsPath(getenv, tc.home)
			if p != tc.wantPath || refused != tc.wantRefused {
				t.Errorf("= (%q, %q), want (%q, %q)", p, refused, tc.wantPath, tc.wantRefused)
			}
		})
	}
}

// TestClaudeProxyBackendUnprovenUnderRelativeConfigDir: with the user
// scope unnameable, the launcher makes no positive backend claim.
func TestClaudeProxyBackendUnprovenUnderRelativeConfigDir(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "relative-dir")
	if claudeProxyBackendProven(nil, t.TempDir(), nil) {
		t.Error("claudeProxyBackendProven = true with an unnameable user settings file")
	}
}

// TestResolveClaudeRouteRelativeUserScope pins FU-131's resolver half: with
// a relative CLAUDE_CONFIG_DIR and no higher scope setting the key, the user
// scope is reported unreadable (the variable named, classified
// conservatively), never "no route"; a higher scope that sets the key still
// wins. The sandbox reader's half is in claude_settings_path_sandbox_test.go
// (that reader is built only with the sandboxed terminals).
func TestResolveClaudeRouteRelativeUserScope(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "relative-dir")
	cwd := t.TempDir()
	res := resolveClaudeEffectiveRoute("http://127.0.0.1:8820", cwd, nil)
	if res.userUnreadable != "CLAUDE_CONFIG_DIR" || res.class != claudeRouteObserver || res.scope != claudeScopeUser {
		t.Fatalf("resolution = %+v, want the unreadable user scope", res)
	}
	if routed, _ := claudeConfigRoutesToProxy("http://127.0.0.1:8820"); routed {
		t.Error("claudeConfigRoutesToProxy claims a proxy route it never read")
	}
	if err := os.MkdirAll(filepath.Join(cwd, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, ".claude", "settings.json"), []byte(`{"env":{"ANTHROPIC_BASE_URL":"https://gw.example"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := resolveClaudeEffectiveRoute("http://127.0.0.1:8820", cwd, nil); res.class != claudeRouteThirdParty || res.userUnreadable != "" {
		t.Errorf("a project-scope route must still win: %+v", res)
	}
}
