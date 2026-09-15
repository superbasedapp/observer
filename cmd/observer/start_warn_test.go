package main

import (
	"strings"
	"testing"
)

// TestAllowedNotWatchedWarning pins the DI-07 startup WARN's message shape
// (docs/plans/dashboard-install-gap-remediation-research-2026-09-02.md §5.4,
// §6.7). allowedNotWatchedWarning is pure — no config reading — so this
// table covers the empty/one/many shapes directly.
func TestAllowedNotWatchedWarning(t *testing.T) {
	tests := []struct {
		name        string
		unwatched   []string
		enabledLen  int
		defaultLen  int
		wantEmpty   bool
		wantSubstrs []string
	}{
		{
			name:      "nil unwatched produces no warning",
			unwatched: nil,
			wantEmpty: true,
		},
		{
			name:      "empty unwatched produces no warning",
			unwatched: []string{},
			wantEmpty: true,
		},
		{
			name:       "one tool",
			unwatched:  []string{"muse"},
			enabledLen: 17,
			defaultLen: 43,
			wantSubstrs: []string{
				"WARN ",
				"[terminal.launch].allowed_tools",
				"1 tool(s)",
				"[observer.watch].enabled_adapters (17 entries; the default has 43)",
				"muse",
				"never be captured",
				"Add them to enabled_adapters or delete the key",
			},
		},
		{
			name:       "many tools preserve order",
			unwatched:  []string{"muse", "prime-agent", "grok"},
			enabledLen: 18,
			defaultLen: 43,
			wantSubstrs: []string{
				"3 tool(s)",
				"muse, prime-agent, grok",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := allowedNotWatchedWarning(tt.unwatched, tt.enabledLen, tt.defaultLen)
			if tt.wantEmpty {
				if got != "" {
					t.Fatalf("allowedNotWatchedWarning(%v) = %q, want empty", tt.unwatched, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("allowedNotWatchedWarning(%v) = empty, want non-empty", tt.unwatched)
			}
			for _, sub := range tt.wantSubstrs {
				if !strings.Contains(got, sub) {
					t.Errorf("allowedNotWatchedWarning(%v) = %q, want substring %q", tt.unwatched, got, sub)
				}
			}
		})
	}
}
