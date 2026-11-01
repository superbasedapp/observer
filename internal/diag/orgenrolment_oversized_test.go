package diag

import (
	"context"
	"strings"
	"testing"
)

// TestOrgEnrolmentReportsOversizedPushRows: a snapshot row too large for any
// push (the daemon's persisted report under schema_meta
// org_push_oversized_rows, internal/store/orgsnapoversize.go) surfaces on the
// doctor org enrolment check as a WARN detail with the family and sizes, and
// tells the operator what to change.
func TestOrgEnrolmentReportsOversizedPushRows(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = "https://org.acme.example"
	insertEnrolmentRow(t, database, "https://org.acme.example")
	if _, err := database.Exec(`INSERT INTO schema_meta(key, value) VALUES(?, ?)`, orgPushOversizedKey,
		`[{"family":"session_network","rows":2,"largest_bytes":2345678,"budget_bytes":983040,"last_seen":"2026-10-27T16:00:00Z"}]`); err != nil {
		t.Fatalf("seed report: %v", err)
	}

	c := checkOrgEnrolment(context.Background(), database, cfg)
	if c.Status != StatusWarn {
		t.Fatalf("status=%s want WARN - %q %v", c.Status, c.Message, c.Details)
	}
	found := false
	for _, d := range c.Details {
		if strings.HasPrefix(d, "oversized:") && strings.Contains(d, "session_network: 2 row(s)") &&
			strings.Contains(d, "983040-byte") && strings.Contains(d, "2345678 bytes") && strings.Contains(d, "max_push_bytes") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no oversized detail line: %v", c.Details)
	}
}

// TestOrgEnrolmentNoOversizedReportStaysQuiet: without a report there is no
// detail line and no WARN from it.
func TestOrgEnrolmentNoOversizedReportStaysQuiet(t *testing.T) {
	cfg, database, _, _ := newTestEnv(t)
	cfg.OrgClient.Enabled = true
	cfg.OrgClient.OrgServerURL = "https://org.acme.example"
	insertEnrolmentRow(t, database, "https://org.acme.example")
	c := checkOrgEnrolment(context.Background(), database, cfg)
	for _, d := range c.Details {
		if strings.HasPrefix(d, "oversized:") {
			t.Fatalf("unexpected oversized line %q", d)
		}
	}
}
