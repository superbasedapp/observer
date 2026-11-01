package retention

import (
	"context"
	"database/sql"
	"testing"
)

// cursorsAt returns the actions id and sessions rowid of the action whose
// session is sess-<id> in the seed() fixture.
func cursorsAt(t *testing.T, d *sql.DB, id string) PushHold {
	t.Helper()
	var h PushHold
	if err := d.QueryRow(`SELECT a.id, s.rowid FROM actions a JOIN sessions s ON s.id = a.session_id WHERE s.id = ?`, "sess-"+id).
		Scan(&h.ActionsCursor, &h.SessionsCursor); err != nil {
		t.Fatalf("cursor for %s: %v", id, err)
	}
	return h
}

// TestRun_PushHoldKeepsUnpushedRows pins T-830 one row per case: under a push
// hold the age pass deletes only rows the org already accepted, reports the
// rest as held, and a nil hold (a solo node) is unchanged.
func TestRun_PushHoldKeepsUnpushedRows(t *testing.T) {
	tests := []struct {
		name         string
		hold         func(d *sql.DB) *PushHold
		wantDeleted  int
		wantSessions int
		wantHeld     HeldForPush
		wantLeft     int
	}{
		// MaxAgeDays 30 ages the -200d and -90d rows; -10d stays regardless.
		{"no hold (solo node) deletes every aged row", func(*sql.DB) *PushHold { return nil }, 2, 2, HeldForPush{}, 1},
		{"nothing pushed holds every aged row", func(*sql.DB) *PushHold { return &PushHold{} }, 0, 0, HeldForPush{Actions: 2}, 3},
		{"oldest pushed deletes only it", func(d *sql.DB) *PushHold { h := cursorsAt(t, d, "a"); return &h }, 1, 1, HeldForPush{Actions: 1}, 2},
		{"everything pushed deletes every aged row", func(d *sql.DB) *PushHold { h := cursorsAt(t, d, "c"); return &h }, 2, 2, HeldForPush{}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, st := seed(t)
			d := openExisting(t, dbPath)
			res, err := New(d).Run(context.Background(), Options{MaxAgeDays: 30, DBPath: dbPath, PushHold: tc.hold(d)})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.ActionsDeleted != tc.wantDeleted || res.OrphanedSessionsDeleted != tc.wantSessions {
				t.Errorf("deleted actions=%d sessions=%d, want %d/%d", res.ActionsDeleted, res.OrphanedSessionsDeleted, tc.wantDeleted, tc.wantSessions)
			}
			if res.HeldForPush != tc.wantHeld {
				t.Errorf("held = %+v, want %+v", res.HeldForPush, tc.wantHeld)
			}
			if n, _ := st.CountActions(context.Background()); n != tc.wantLeft {
				t.Errorf("remaining actions = %d, want %d", n, tc.wantLeft)
			}
		})
	}
}

// TestRun_PushHoldBoundsSizeCapPass pins that the size-cap shed obeys the
// hold too: an unpushed action is never deleted to chase the cap.
func TestRun_PushHoldBoundsSizeCapPass(t *testing.T) {
	dbPath, st := seed(t)
	d := openExisting(t, dbPath)
	res, err := New(d).Run(context.Background(), Options{MaxDBSizeMB: 1, DBPath: dbPath, PushHold: &PushHold{}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ActionsDeleted != 0 {
		t.Fatalf("size-cap pass deleted %d unpushed actions", res.ActionsDeleted)
	}
	if n, _ := st.CountActions(context.Background()); n != 3 {
		t.Errorf("remaining actions = %d, want 3", n)
	}
}

// TestCountHeldForPush pins the doctor/dashboard read: nil hold or no horizon
// holds nothing; otherwise aged rows above the cursor are counted.
func TestCountHeldForPush(t *testing.T) {
	dbPath, _ := seed(t)
	d := openExisting(t, dbPath)
	ctx := context.Background()
	if h, err := CountHeldForPush(ctx, d, 30, nil); err != nil || h.Total() != 0 {
		t.Fatalf("nil hold = %+v, %v", h, err)
	}
	if h, err := CountHeldForPush(ctx, d, 0, &PushHold{}); err != nil || h.Total() != 0 {
		t.Fatalf("no horizon = %+v, %v", h, err)
	}
	h, err := CountHeldForPush(ctx, d, 30, &PushHold{})
	if err != nil || h.Actions != 2 {
		t.Fatalf("held = %+v, %v, want 2 aged actions", h, err)
	}
}
