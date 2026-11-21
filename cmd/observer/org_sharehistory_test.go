package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/orgenrol"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Share history (T-159): `observer org backfill --all [--confirm]` and the
// Settings > Enrolment "Share history" action run ONE performer
// (performOrgBackfill), so the dry run, the rewind and the counts cannot
// differ between the CLI and the dashboard.

// historyStore is a store with three captured sessions whose push cursor is
// seeded at the high-water mark, as `observer enroll` leaves it: everything
// predates enrolment and nothing is eligible.
func historyStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if _, err := database.ExecContext(ctx, `INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/p', '2026-09-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"s1", "s2", "s3"} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO sessions (id, tool, started_at, project_id) VALUES (?, 'claude-code', '2026-09-01T00:00:00Z', 1)`, id); err != nil {
			t.Fatal(err)
		}
	}
	st := store.New(database)
	max, err := st.CurrentMaxIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SavePushCursor(ctx, max); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPerformOrgBackfillDryRunThenConfirm(t *testing.T) {
	ctx := context.Background()
	st := historyStore(t)
	before, _ := st.LoadPushCursor(ctx)

	dry, err := performOrgBackfill(ctx, st, false)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Rewound || dry.Eligible != 0 || dry.WouldUnlock != 3 || dry.Total != 3 {
		t.Fatalf("dry run = %+v", dry)
	}
	if after, _ := st.LoadPushCursor(ctx); after != before {
		t.Fatalf("a dry run moved the cursor: %+v -> %+v", before, after)
	}

	done, err := performOrgBackfill(ctx, st, true)
	if err != nil {
		t.Fatal(err)
	}
	if !done.Rewound || done.WouldUnlock != 3 {
		t.Fatalf("confirm = %+v", done)
	}
	if after, _ := st.LoadPushCursor(ctx); after != (store.PushCursor{}) {
		t.Fatalf("cursor after confirm = %+v, want zero", after)
	}
	// A second dry run: everything is now eligible, nothing more to unlock.
	again, err := performOrgBackfill(ctx, st, false)
	if err != nil || again.Eligible != 3 || again.WouldUnlock != 0 {
		t.Fatalf("after rewind = %+v, %v", again, err)
	}
}

// TestOrgBackfillCLIOutputUnchanged: the CLI prints the counts, plus the
// cross-enrolment note on a dry run that would unlock history (D-273 item 2,
// review M3-12, amended by D-43): it names the current organization and says
// that a previous enrolment's sessions stay on this machine.
func TestOrgBackfillCLIOutputUnchanged(t *testing.T) {
	var buf bytes.Buffer
	printOrgBackfillReport(&buf, orgBackfillReport{Eligible: 0, WouldUnlock: 3, Total: 3}, "Acme")
	want := "currently eligible: 0 rows\nwould unlock:       3 more rows (captured under this organization)\n\n" +
		backfillCrossEnrolmentWarning("Acme") + "\n\nDRY RUN - pass --confirm to rewind the cursor.\n"
	if buf.String() != want {
		t.Fatalf("dry run output:\n%q\nwant\n%q", buf.String(), want)
	}
	if w := backfillCrossEnrolmentWarning("Acme"); !strings.Contains(w, "previous enrolment") ||
		!strings.Contains(w, "go to Acme") || !strings.Contains(w, "stay on this machine") {
		t.Fatalf("warning = %q", w)
	}
	buf.Reset()
	printOrgBackfillReport(&buf, orgBackfillReport{Eligible: 4}, "Acme")
	if strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("nothing to unlock, yet warned: %q", buf.String())
	}
	buf.Reset()
	printOrgBackfillReport(&buf, orgBackfillReport{Eligible: 0, WouldUnlock: 3, Total: 3, Rewound: true}, "Acme")
	if !strings.HasSuffix(buf.String(), "cursor reset to 0; the next push cycles will ship every row captured under this organization.\n") {
		t.Fatalf("confirm output: %q", buf.String())
	}
}

// TestDashboardCopyPointsHistoryAtThePage: the "predate enrolment" reason the
// dashboard shows points at the page's own action, never at the CLI.
func TestDashboardCopyPointsHistoryAtThePage(t *testing.T) {
	got := dashboardCopy(pushEligibilityReason(0, 42, nil))
	if strings.Contains(got, "observer org backfill") || strings.Contains(got, "`") {
		t.Fatalf("UI copy names the CLI: %q", got)
	}
	if !strings.Contains(got, "Share history") {
		t.Fatalf("UI copy does not point at the Share history action: %q", got)
	}
}

func TestEnrolDashboardShareHistoryNeedsAnEnrolment(t *testing.T) {
	d, _, _ := testEnrolDashboard(t)
	_, err := d.ShareHistory(context.Background(), false)
	wantFailure(t, err, orgenrol.CodeNotEnrolled)
}
