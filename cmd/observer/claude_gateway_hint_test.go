package main

import (
	"testing"
)

// TestPrepareClaudeEnv_GatewayHintHeaders pins the launcher's
// CLAUDE_CODE_GATEWAY_HINT_HEADERS rule (backlog item 14): on only when the
// child routes to the observer proxy AND the user has not set the variable
// (presence wins, so an explicit "0" or "" is kept).
func TestPrepareClaudeEnv_GatewayHintHeaders(t *testing.T) {
	const proxy = "http://127.0.0.1:8820"
	cases := []struct {
		name     string
		parent   []string
		wantVal  string
		wantSet  bool
		wantInfo bool
	}{
		{"routed default", []string{"PATH=/usr/bin"}, "1", true, true},
		{"routed via preset proxy url", []string{"ANTHROPIC_BASE_URL=http://localhost:8820"}, "1", true, true},
		{"user opted out", []string{"CLAUDE_CODE_GATEWAY_HINT_HEADERS=0"}, "0", true, false},
		{"user set empty", []string{"CLAUDE_CODE_GATEWAY_HINT_HEADERS="}, "", true, false},
		{"user already on", []string{"CLAUDE_CODE_GATEWAY_HINT_HEADERS=1"}, "1", true, false},
		{"third-party gateway kept off", []string{"ANTHROPIC_BASE_URL=https://gateway.example.com"}, "", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, info, err := prepareClaudeEnv(tc.parent, proxy, "/nonexistent/.credentials.json")
			if err != nil {
				t.Fatalf("prepareClaudeEnv: %v", err)
			}
			v, ok := lookupEnvValue(env, claudeGatewayHintEnv)
			if ok != tc.wantSet || v != tc.wantVal {
				t.Errorf("%s = (%q, present=%v), want (%q, present=%v)", claudeGatewayHintEnv, v, ok, tc.wantVal, tc.wantSet)
			}
			if info.GatewayHintsSet != tc.wantInfo {
				t.Errorf("GatewayHintsSet = %v, want %v", info.GatewayHintsSet, tc.wantInfo)
			}
		})
	}
}

// TestClaudeAttachEnvForwardsGatewayHintOptOut pins that a caller's explicit
// hint-header setting crosses the attach socket; without it the
// daemon-spawned inner launcher would read the daemon's env and turn the
// headers on over the caller's "0".
func TestClaudeAttachEnvForwardsGatewayHintOptOut(t *testing.T) {
	got := claudeAttachEnv([]string{"CLAUDE_CODE_GATEWAY_HINT_HEADERS=0"})
	if len(got) != 1 || got[0] != "CLAUDE_CODE_GATEWAY_HINT_HEADERS=0" {
		t.Fatalf("claudeAttachEnv = %v, want [CLAUDE_CODE_GATEWAY_HINT_HEADERS=0]", got)
	}
}
