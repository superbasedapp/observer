//go:build !sbo_omit_security && !sbo_omit_ui_dashboard

package main

import (
	"path/filepath"
	"testing"
)

// TestSecurityAssessRetentionDays: the loop reads evidence_retention_days from
// the config on every pass, and anything it cannot read keeps the evidence.
func TestSecurityAssessRetentionDays(t *testing.T) {
	cases := []struct {
		name string
		body string // "" writes no file
		want int
	}{
		{"no config file: keep", "", 0},
		{"unset: keep", "[security.assessments]\nrelax_pentest_local = false\n", 0},
		{"ninety days", "[security.assessments]\nevidence_retention_days = 90\n", 90},
		{"an invalid value: the config does not load, keep", "[security.assessments]\nevidence_retention_days = -4\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if tc.body != "" {
				writeFileT(t, path, tc.body)
			}
			if got := securityAssessRetentionDays(path); got != tc.want {
				t.Fatalf("retention = %d, want %d", got, tc.want)
			}
		})
	}
}
