package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestRetentionPushHold pins T-830 / T-839 end to end through runRetention
// and the doctor check, one row per node posture: a node that is not enrolled
// ages the row out as before; an enrolled node keeps it until the push cursor
// passes it, whether the push is running or PAUSED ([org_client].enabled =
// false, D-673), and doctor WARNs meanwhile; past held_max_mb the oldest held
// row goes anyway and doctor FAILs.
func TestRetentionPushHold(t *testing.T) {
	tests := []struct {
		name       string
		orgEnabled bool
		enrolled   bool
		pushed     bool
		bigRow     bool // inflate the held row past a 1 MB held_max_mb
		wantLeft   int
		wantStatus diag.Status
		wantMsg    string
	}{
		{"org off, not enrolled: local-only retention deletes", false, false, false, false, 0, diag.StatusOK, "local-only"},
		{"org on, not enrolled: local-only retention deletes", true, false, false, false, 0, diag.StatusOK, "local-only"},
		{"enrolled, push paused: row held and doctor warns", false, true, false, false, 1, diag.StatusWarn, "retention held 1 rows awaiting push"},
		{"enrolled, not pushed: row held and doctor warns", true, true, false, false, 1, diag.StatusWarn, "retention held 1 rows awaiting push"},
		{"enrolled, pushed: row deleted", true, true, true, false, 0, diag.StatusOK, "no aged rows"},
		{"enrolled, held past held_max_mb: oldest held row deleted and doctor fails", true, true, false, true, 0, diag.StatusFail, "retention deleted 1 unsent rows"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			st := store.New(database)
			if _, err := st.Ingest(ctx, []models.ToolEvent{{
				SourceFile: "f", SourceEventID: "old", SessionID: "sess-old", ProjectRoot: "/repo",
				Timestamp: time.Now().AddDate(0, 0, -400), Tool: models.ToolClaudeCode,
				ActionType: models.ActionRunCommand, Target: "go test", Success: true,
			}}, nil, store.IngestOptions{}); err != nil {
				t.Fatal(err)
			}
			if tc.enrolled {
				if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "org-1", OrgServerURL: "https://org.example", UserID: "u-1"}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.pushed {
				var a, s int64
				if err := database.QueryRowContext(ctx, `SELECT (SELECT MAX(id) FROM actions), (SELECT MAX(rowid) FROM sessions)`).Scan(&a, &s); err != nil {
					t.Fatal(err)
				}
				if err := st.SavePushCursor(ctx, store.PushCursor{Actions: a, Sessions: s}); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.Default()
			cfg.OrgClient.Enabled = tc.orgEnabled
			cfg.Observer.Retention.MaxDBSizeMB = 0
			if tc.bigRow {
				// About 2.2 MB of stored tool input against a 1 MB ceiling.
				if _, err := database.ExecContext(ctx, `UPDATE actions SET raw_tool_input = hex(randomblob(1100000))`); err != nil {
					t.Fatal(err)
				}
				cfg.Observer.Retention.HeldMaxMB = 1
				if check := retentionPushHoldCheck(ctx, cfg, database); check.Status != diag.StatusFail ||
					!strings.Contains(check.Message, "the next retention pass deletes the oldest 1 unsent rows") {
					t.Fatalf("doctor before prune = %v %q, want FAIL naming the next pass", check.Status, check.Message)
				}
			}

			check := retentionPushHoldCheck(ctx, cfg, database)
			if !tc.pushed && tc.wantStatus == diag.StatusWarn {
				if check.Status != diag.StatusWarn || !strings.Contains(check.Message, tc.wantMsg) {
					t.Fatalf("doctor before prune = %v %q, want WARN %q", check.Status, check.Message, tc.wantMsg)
				}
			}
			res, err := runRetention(ctx, cfg, database)
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := st.CountActions(ctx); n != tc.wantLeft {
				t.Fatalf("actions left = %d, want %d (held=%+v)", n, tc.wantLeft, res.HeldForPush)
			}
			if tc.wantLeft > 0 && res.HeldForPush.Total() == 0 {
				t.Fatalf("held rows not reported: %+v", res.HeldForPush)
			}
			if tc.bigRow && res.HoldCap.ShedActions != 1 {
				t.Fatalf("hold cap = %+v, want one shed action", res.HoldCap)
			}
			check = retentionPushHoldCheck(ctx, cfg, database)
			if check.Status != tc.wantStatus || !strings.Contains(check.Message, tc.wantMsg) {
				t.Fatalf("doctor = %v %q, want %v containing %q", check.Status, check.Message, tc.wantStatus, tc.wantMsg)
			}
		})
	}
}
