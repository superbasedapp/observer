package proxyroute

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeClaudeEnvFixture writes ~/.claude/settings.json under home with the
// given env block.
func writeClaudeEnvFixture(t *testing.T, home string, env map[string]any) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"env": env})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// claudeEnv returns settings.json's env block (nil when absent).
func claudeEnv(t *testing.T, home string) map[string]any {
	t.Helper()
	env, _ := readClaudeSettings(t, home)["env"].(map[string]any)
	return env
}

// TestRegisterClaudeCode_GatewayHints pins backlog item 14 follow-up 1: the
// durable route also turns on CLAUDE_CODE_GATEWAY_HINT_HEADERS (presence
// wins, so an operator's own value is never touched), an existing route of
// ours is topped up without flipping AlreadySet, and a dry run writes
// nothing.
func TestRegisterClaudeCode_GatewayHints(t *testing.T) {
	cases := []struct {
		name        string
		pre         map[string]any // nil = no settings.json
		dryRun      bool
		wantAdded   bool
		wantAlready bool
		wantHints   bool
		wantValue   any // env[CLAUDE_CODE_GATEWAY_HINT_HEADERS] after; nil = absent
	}{
		{name: "fresh route adds the switch", wantAdded: true, wantHints: true, wantValue: "1"},
		{name: "operator opt-out kept", pre: map[string]any{ClaudeGatewayHintEnv: "0"}, wantAdded: true, wantValue: "0"},
		{name: "operator empty value kept", pre: map[string]any{ClaudeGatewayHintEnv: ""}, wantAdded: true, wantValue: ""},
		{name: "existing route topped up", pre: map[string]any{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820"}, wantAlready: true, wantHints: true, wantValue: "1"},
		{name: "existing route with switch is a no-op", pre: map[string]any{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820", ClaudeGatewayHintEnv: "1"}, wantAlready: true, wantValue: "1"},
		{name: "another observer port is not touched", pre: map[string]any{"ANTHROPIC_BASE_URL": "http://127.0.0.1:18820"}, wantAlready: true, wantValue: nil},
		{name: "dry-run top-up reports but writes nothing", pre: map[string]any{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820"}, dryRun: true, wantAlready: true, wantHints: true, wantValue: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			if tc.pre != nil {
				writeClaudeEnvFixture(t, home, tc.pre)
			}
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home, DryRun: tc.dryRun})
			if err != nil {
				t.Fatal(err)
			}
			res := r.RegisterClaudeCode()
			if res.Error != nil {
				t.Fatalf("RegisterClaudeCode: %v", res.Error)
			}
			if res.Added != tc.wantAdded || res.AlreadySet != tc.wantAlready || res.GatewayHintsAdded != tc.wantHints {
				t.Fatalf("result Added=%v AlreadySet=%v GatewayHintsAdded=%v, want %v/%v/%v",
					res.Added, res.AlreadySet, res.GatewayHintsAdded, tc.wantAdded, tc.wantAlready, tc.wantHints)
			}
			if tc.pre == nil && tc.dryRun {
				return
			}
			got, present := claudeEnv(t, home)[ClaudeGatewayHintEnv]
			if tc.wantValue == nil {
				if present {
					t.Fatalf("%s = %v, want absent", ClaudeGatewayHintEnv, got)
				}
				return
			}
			if got != tc.wantValue {
				t.Fatalf("%s = %v, want %v", ClaudeGatewayHintEnv, got, tc.wantValue)
			}
		})
	}
}

// TestUnregisterClaudeCode_GatewayHints pins the symmetric removal: our "1"
// goes with our route, an operator's "0" stays, and a route that is not ours
// leaves the switch alone.
func TestUnregisterClaudeCode_GatewayHints(t *testing.T) {
	cases := []struct {
		name      string
		pre       map[string]any
		wantHints bool
		wantEnv   map[string]any // nil = env block dropped
	}{
		{name: "our route + our switch removed together", pre: map[string]any{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820", ClaudeGatewayHintEnv: "1"}, wantHints: true, wantEnv: nil},
		{name: "operator 0 survives", pre: map[string]any{"ANTHROPIC_BASE_URL": "http://127.0.0.1:8820", ClaudeGatewayHintEnv: "0"}, wantEnv: map[string]any{ClaudeGatewayHintEnv: "0"}},
		{name: "not our route: switch untouched", pre: map[string]any{"ANTHROPIC_BASE_URL": "https://gw.corp.example", ClaudeGatewayHintEnv: "1"}, wantEnv: map[string]any{"ANTHROPIC_BASE_URL": "https://gw.corp.example", ClaudeGatewayHintEnv: "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeClaudeEnvFixture(t, home, tc.pre)
			r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			res := r.UnregisterClaudeCode()
			if res.Error != nil {
				t.Fatalf("UnregisterClaudeCode: %v", res.Error)
			}
			if res.GatewayHintsAdded != tc.wantHints {
				t.Fatalf("GatewayHintsAdded = %v, want %v", res.GatewayHintsAdded, tc.wantHints)
			}
			env := claudeEnv(t, home)
			if len(env) != len(tc.wantEnv) {
				t.Fatalf("env = %v, want %v", env, tc.wantEnv)
			}
			for k, v := range tc.wantEnv {
				if env[k] != v {
					t.Fatalf("env[%s] = %v, want %v", k, env[k], v)
				}
			}
		})
	}
}

// TestRegisterClaudeCodeWindows_GatewayHints pins that the cross-OS writer
// (a Windows-side .claude reached from WSL) gets the same switch - it shares
// registerClaudeCodeAt.
func TestRegisterClaudeCodeWindows_GatewayHints(t *testing.T) {
	r, winHome := newWindowsRegistrar(t, 8820)
	res := r.RegisterClaudeCodeWindows()
	if res.Error != nil || !res.Added || !res.GatewayHintsAdded {
		t.Fatalf("RegisterClaudeCodeWindows = %+v, want Added + GatewayHintsAdded", res)
	}
	if got := claudeEnv(t, winHome)[ClaudeGatewayHintEnv]; got != "1" {
		t.Fatalf("%s = %v, want 1", ClaudeGatewayHintEnv, got)
	}
}
