//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// onboardTestClaude writes an onboarded ~/.claude.json into a test home.
func onboardTestClaude(t *testing.T, home string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"hasCompletedOnboarding":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSandboxConfigHomeFor: a tool whose first run was never finished is
// refused with the remedy; an onboarded tool keeps its own config folder
// when the home has one or its variable already moves it, and otherwise
// gets a run-local folder seeded with the row's non-secret keys only
// (Windows 11 Pro rerun 2026-10-25, D3).
func TestSandboxConfigHomeFor(t *testing.T) {
	spec, _ := integration.For("claude-code")
	c := spec.Sandbox.ConfigHome
	if c == nil {
		t.Fatal("claude-code declares no sandbox config home")
	}
	home := filepath.FromSlash("/h")
	full := `{"hasCompletedOnboarding":true,"theme":"dark","oauthAccount":{"emailAddress":"a@b"},"primaryApiKey":"sk-x","userID":"u"}`
	files := func(m map[string]string) func(string) ([]byte, error) {
		return func(p string) ([]byte, error) {
			if v, ok := m[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		}
	}
	noEnv := func(string) string { return "" }
	none := func(string) bool { return false }
	state := filepath.Join(home, ".claude.json")
	for _, tc := range []struct {
		name    string
		env     func(string) string
		read    map[string]string
		exists  func(string) bool
		refused bool
		plan    bool
	}{
		{name: "no state file", env: noEnv, read: map[string]string{}, exists: none, refused: true},
		{name: "first run not done", env: noEnv, read: map[string]string{state: `{"theme":"dark"}`}, exists: none, refused: true},
		{name: "onboarded, own folder", env: noEnv, read: map[string]string{state: full}, exists: func(p string) bool { return p == filepath.Join(home, ".claude") }},
		{name: "onboarded, no folder", env: noEnv, read: map[string]string{state: full}, exists: none, plan: true},
		{name: "moved, onboarded", env: func(k string) string {
			if k == "CLAUDE_CONFIG_DIR" {
				return filepath.FromSlash("/cfg")
			}
			return ""
		}, read: map[string]string{filepath.Join(filepath.FromSlash("/cfg"), ".claude.json"): full}, exists: none},
		{name: "moved, home onboarded only", env: func(k string) string {
			if k == "CLAUDE_CONFIG_DIR" {
				return filepath.FromSlash("/cfg")
			}
			return ""
		}, read: map[string]string{state: full}, exists: none, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sandboxConfigHomeFor(c, "claude-code", home, tc.env, files(tc.read), tc.exists)
			if tc.refused {
				if !errors.Is(err, errToolNotOnboarded) || !strings.Contains(err.Error(), "onboard claude-code once outside the sandbox") {
					t.Fatalf("err = %v, want the not-onboarded refusal with its remedy", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (got != nil) != tc.plan {
				t.Fatalf("plan = %+v, want a run-local folder %v", got, tc.plan)
			}
			if got == nil {
				return
			}
			if got.Env != "CLAUDE_CONFIG_DIR" || got.File != ".claude.json" {
				t.Fatalf("plan = %+v", got)
			}
			var seed map[string]any
			if err := json.Unmarshal(got.Seed, &seed); err != nil {
				t.Fatal(err)
			}
			if len(seed) != 2 || seed["hasCompletedOnboarding"] != true || seed["theme"] != "dark" {
				t.Fatalf("seed = %s, want the onboarding flag and the theme only", got.Seed)
			}
			if err := mxcCheckConfigHome(got); err != nil {
				t.Fatalf("the helper refuses the daemon's own plan: %v", err)
			}
		})
	}
	if got, err := sandboxConfigHomeFor(nil, "x", home, noEnv, files(nil), none); got != nil || err != nil {
		t.Fatalf("a row with no config home planned %+v, %v", got, err)
	}
}

// TestMXCConfigHomeInTheBox: the helper refuses a planted config home, the
// box gets the variable pointed at its run folder (replacing any value) and
// the run's document grants that folder read-write.
func TestMXCConfigHomeInTheBox(t *testing.T) {
	ok := &mxcConfigHomePlan{Env: "CLAUDE_CONFIG_DIR", File: ".claude.json", Seed: json.RawMessage(`{"theme":"dark"}`)}
	for _, bad := range []*mxcConfigHomePlan{
		{Env: "PATH;X", File: ".claude.json", Seed: ok.Seed},
		{Env: "CLAUDE_CONFIG_DIR", File: `..\x`, Seed: ok.Seed},
		{Env: "CLAUDE_CONFIG_DIR", File: ".claude.json", Seed: json.RawMessage(`{"oauthAccount":{"a":1}}`)},
		{Env: "CLAUDE_CONFIG_DIR", File: ".claude.json", Seed: json.RawMessage(`[1]`)},
	} {
		if err := mxcCheckConfigHome(bad); err == nil {
			t.Errorf("the helper accepted %+v", bad)
		}
	}
	if err := mxcCheckConfigHome(ok); err != nil {
		t.Fatal(err)
	}
	box := `C:\t\observer-sbx-r9`
	env := mxcWithConfigHome([]string{"A=1", "claude_config_dir=C:\\real"}, ok, box)
	if strings.Join(env, "|") != `A=1|CLAUDE_CONFIG_DIR=C:\t\observer-sbx-r9\config` {
		t.Fatalf("env = %q", env)
	}
	if got := mxcWithConfigHome([]string{"A=1"}, nil, box); len(got) != 1 {
		t.Fatalf("no config home changed the env: %q", got)
	}
	plan := mxcPlanFile{RunID: "r9", Workspace: `C:\w`, Tier: "internet", ReadWrite: []string{`C:\w`}, ConfigHome: ok}
	doc, err := mxcRunDocument(plan, box, box+`\tmp`, []string{`C:\o\observer.exe`, "claude"}, []string{"A=1"}, 4321, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := doc.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `observer-sbx-r9\\config`) {
		t.Fatalf("the run's config folder is not granted: %s", b)
	}
}
