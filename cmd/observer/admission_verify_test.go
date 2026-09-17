//go:build !no_obs

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// verifyRowByCheck returns the row for a named check, or a zero row.
func verifyRowByCheck(rows []admissionVerifyRow, check string) admissionVerifyRow {
	for _, r := range rows {
		if r.Check == check {
			return r
		}
	}
	return admissionVerifyRow{}
}

// TestRunAdmissionVerifyPass drives the happy path: admission enabled with a
// deterministic-only policy and no judge configured. Lint passes, the judge row
// is SKIP (no judge), and the audit chain is intact over an empty table.
func TestRunAdmissionVerifyPass(t *testing.T) {
	ctx := context.Background()
	conn, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cfg := config.Default()
	cfg.Observability.Enabled = true
	cfg.Observability.Admission.Enabled = true
	cfg.Observability.Admission.Mode = "observe"
	cfg.Observability.Admission.Criterion = []config.AdmissionCriterionConfig{
		{ID: "jailbreak", Type: "jailbreak", Name: "Jailbreak", Decision: "deny", Severity: "high"},
	}

	rows, fatal := runAdmissionVerify(ctx, cfg, conn)
	if len(fatal) != 0 {
		t.Fatalf("unexpected fatal lint: %v", fatal)
	}
	if r := verifyRowByCheck(rows, "policy lint"); r.Status != "PASS" {
		t.Errorf("policy lint = %q (%s), want PASS", r.Status, r.Detail)
	}
	if r := verifyRowByCheck(rows, "judge reachability"); r.Status != "SKIP" {
		t.Errorf("judge reachability = %q (%s), want SKIP (no judge configured)", r.Status, r.Detail)
	}
	if r := verifyRowByCheck(rows, "audit chain"); r.Status != "PASS" {
		t.Errorf("audit chain = %q (%s), want PASS", r.Status, r.Detail)
	}
}

// TestRunAdmissionVerifyFatalLint pins that a bad prefilter regex surfaces as a
// FAIL lint row with the fatal message listed for the table footer, while the
// audit-chain row is skipped (admission disabled here).
func TestRunAdmissionVerifyFatalLint(t *testing.T) {
	ctx := context.Background()
	conn, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cfg := config.Default()
	cfg.Observability.Enabled = true
	cfg.Observability.Admission.Enabled = false // chain row should SKIP
	cfg.Observability.Admission.Prefilter.Deny = []string{"["}

	rows, fatal := runAdmissionVerify(ctx, cfg, conn)
	if len(fatal) == 0 {
		t.Fatal("expected a fatal lint message for the bad regex")
	}
	if r := verifyRowByCheck(rows, "policy lint"); r.Status != "FAIL" {
		t.Errorf("policy lint = %q (%s), want FAIL", r.Status, r.Detail)
	}
	if r := verifyRowByCheck(rows, "audit chain"); r.Status != "SKIP" {
		t.Errorf("audit chain = %q (%s), want SKIP (admission disabled)", r.Status, r.Detail)
	}
}
