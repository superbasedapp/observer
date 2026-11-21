package main

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestRequestGrantLine (demo finding #27): `observer requests` says a
// granted request's grant was revoked or ended, never "N days left".
func TestRequestGrantLine(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	week := now.Add(7 * 24 * time.Hour).UnixNano()
	cases := []struct {
		name string
		g    orgcontract.AccessRequestGrantSummary
		want []string
		not  string
	}{
		{"active", orgcontract.AccessRequestGrantSummary{ID: 3, Status: accessgrant.StatusActive, ExpiresAtNs: week}, []string{"G-3", "left"}, "revoked"},
		{"revoked with reason", orgcontract.AccessRequestGrantSummary{
			ID: 3, Status: accessgrant.StatusRevoked, ExpiresAtNs: week,
			RevokedAtNs: now.Add(-time.Hour).UnixNano(), RevokeReason: "budget deleted",
		}, []string{"G-3", "revoked 2026-11-10T11:00:00Z", "budget deleted"}, "left"},
		{"replaced by an extension", orgcontract.AccessRequestGrantSummary{
			ID: 3, Status: accessgrant.StatusRevoked, ExpiresAtNs: week,
			RevokedAtNs: now.Add(-time.Hour).UnixNano(), RevokeReason: "superseded by G-8",
		}, []string{"G-3, replaced by G-8 2026-11-10T11:00:00Z"}, "superseded"},
		{"revoked by an older server", orgcontract.AccessRequestGrantSummary{ID: 4, Status: accessgrant.StatusRevoked, ExpiresAtNs: week}, []string{"G-4, revoked"}, "left"},
		{"expired", orgcontract.AccessRequestGrantSummary{ID: 5, Status: accessgrant.StatusExpired, ExpiresAtNs: now.Add(-time.Minute).UnixNano()}, []string{"expired"}, "left"},
		{"past expiry the server still called active", orgcontract.AccessRequestGrantSummary{ID: 6, Status: accessgrant.StatusActive, ExpiresAtNs: now.Add(-time.Second).UnixNano()}, []string{"expired"}, "left"},
		{"exhausted", orgcontract.AccessRequestGrantSummary{ID: 7, Status: accessgrant.StatusExhausted, ExpiresAtNs: week}, []string{"every use spent"}, "left"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := requestGrantLine(&tc.g, now)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("requestGrantLine = %q, want it to contain %q", got, w)
				}
			}
			if tc.not != "" && strings.Contains(got, tc.not) {
				t.Errorf("requestGrantLine = %q, must not contain %q", got, tc.not)
			}
		})
	}
}
