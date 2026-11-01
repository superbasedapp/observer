package diag

import (
	"context"
	"strings"
	"testing"
)

// TestOrgEnrolmentReportsMachineProof (WINNODE item 4): a managed enrolment
// whose daemon signs no machine proof is a named WARN detail; an available
// proof is an OK detail; an individual enrolment shows nothing.
func TestOrgEnrolmentReportsMachineProof(t *testing.T) {
	cases := []struct {
		name     string
		tenancy  string
		report   string
		wantLine string
		wantWarn bool
	}{
		{
			"managed, no logon session", "managed", `{"available":false,"reason":"no Windows logon session","at":"2026-10-28T10:00:00Z"}`,
			"machine proof: machine proof unavailable: no Windows logon session", true,
		},
		{"managed, available", "managed", `{"available":true,"at":"2026-10-28T10:00:00Z"}`, "machine proof: available (daemon", false},
		{"individual ignores a stale report", "individual", `{"available":false,"reason":"x","at":"2026-10-28T10:00:00Z"}`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, database, _, _ := newTestEnv(t)
			cfg.OrgClient.Enabled = true
			cfg.OrgClient.OrgServerURL = "https://org.acme.example"
			insertEnrolmentRow(t, database, "https://org.acme.example")
			if _, err := database.Exec(`UPDATE org_enrolment SET tenancy = ?`, tc.tenancy); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec(`INSERT INTO schema_meta(key, value) VALUES(?, ?)`, orgMachineProofKey, tc.report); err != nil {
				t.Fatal(err)
			}
			c := checkOrgEnrolment(context.Background(), database, cfg)
			var got string
			for _, d := range c.Details {
				if strings.HasPrefix(d, "machine proof:") {
					got = d
				}
			}
			if tc.wantLine == "" {
				if got != "" {
					t.Fatalf("unexpected line %q", got)
				}
				return
			}
			if !strings.HasPrefix(got, tc.wantLine) {
				t.Fatalf("detail = %q, want %q", got, tc.wantLine)
			}
			if (c.Status == StatusWarn) != tc.wantWarn {
				t.Fatalf("status = %s, want warn=%v", c.Status, tc.wantWarn)
			}
		})
	}
}
