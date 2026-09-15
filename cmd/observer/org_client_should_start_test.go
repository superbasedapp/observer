package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestOrgClientShouldStart is a table-driven pin of the four-state gate
// `observer start` uses to decide whether to construct the org client:
// Enabled, a config org_server_url, and a persisted enrolment row are
// three independent axes (CLAUDE.md "Module Boundaries" #5 — a decision
// table, not a growing if-ladder). Only "enabled with neither a config
// URL nor a persisted row" should return false — see start.go's
// orgClientShouldStart doc comment for the full truth table this pins.
func TestOrgClientShouldStart(t *testing.T) {
	tests := []struct {
		name         string
		enabled      bool
		url          string
		hasEnrolment bool
		want         bool
	}{
		{"disabled, no url, no row", false, "", false, false},
		{"disabled, url set, no row", false, "https://org.example", false, false},
		{"disabled, url set, row exists", false, "https://org.example", true, false},
		{"enabled, no url, no row — never enrolled", true, "", false, false},
		{"enabled, no url, row exists — BLOCK-1 shape, must stay active", true, "", true, true},
		{"enabled, url set, no row — enrolling now", true, "https://org.example", false, true},
		{"enabled, url set, row exists — fully wired", true, "https://org.example", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			hasEnrolment := func() bool {
				called = true
				return tt.hasEnrolment
			}
			cfg := config.OrgClientConfig{Enabled: tt.enabled, OrgServerURL: tt.url}
			got := orgClientShouldStart(cfg, hasEnrolment)
			if got != tt.want {
				t.Errorf("orgClientShouldStart(enabled=%v, url=%q, hasEnrolment=%v) = %v, want %v",
					tt.enabled, tt.url, tt.hasEnrolment, got, tt.want)
			}
			// The DB lookup is I/O — orgClientShouldStart must short-circuit
			// it whenever the config URL alone already decides the answer,
			// so a disabled or already-URL-configured node never probes the
			// database at all.
			wantCalled := tt.enabled && tt.url == ""
			if called != wantCalled {
				t.Errorf("hasEnrolment called = %v, want %v (should only be consulted when enabled with no config URL)", called, wantCalled)
			}
		})
	}
}
