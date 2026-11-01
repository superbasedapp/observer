package retention

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// actionBytes returns the held-size estimate of the action whose session is
// sess-<id> in the seed() fixture, through the same expression the ceiling
// uses.
func actionBytes(t *testing.T, d *sql.DB, id string) int64 {
	t.Helper()
	var n int64
	if err := d.QueryRow(`SELECT `+actionHeldBytesExpr+` FROM actions WHERE session_id = ?`, "sess-"+id).Scan(&n); err != nil {
		t.Fatalf("action bytes for %s: %v", id, err)
	}
	return n
}

// insertGuardEvent writes one guard_events row aged by age and returns its id
// and held-size estimate.
func insertGuardEvent(t *testing.T, d *sql.DB, age time.Duration) (int64, int64) {
	t.Helper()
	var id, sz int64
	if err := d.QueryRow(`INSERT INTO guard_events (ts, rule_id, reason, chain_prev, chain_hash)
		VALUES (?, 'R-101', 'fixture reason', '', 'h') RETURNING id`,
		fakeNow.Add(age).Format(time.RFC3339Nano)).Scan(&id); err != nil {
		t.Fatalf("insert guard event: %v", err)
	}
	if err := d.QueryRow(`SELECT `+guardHeldBytesExpr+` FROM guard_events WHERE id = ?`, id).Scan(&sz); err != nil {
		t.Fatalf("guard bytes: %v", err)
	}
	return id, sz
}

// TestRun_HoldCapReleasesOldestHeldRows pins the T-839 ceiling one row per
// case. The seed holds two aged actions (-200d "a", -90d "b") with nothing
// pushed, plus (when guard is set) one guard_events row at -300d, OLDER than
// both. Past the cap, the OLDEST held rows across both tables are released,
// newest-first accumulation deciding exactly how many, and no more.
func TestRun_HoldCapReleasesOldestHeldRows(t *testing.T) {
	tests := []struct {
		name string
		// capOf computes the cap from the per-row sizes (a, b, g).
		capOf         func(a, b, g int64) int64
		guard         bool
		wantDeleted   int
		wantShedAct   int64
		wantShedGuard int64
		wantHeld      int64 // held actions after the pass
		wantGuardKept bool  // the guard row is above GuardKeepFromID
	}{
		{"no ceiling holds everything", func(a, b, g int64) int64 { return 0 }, false, 0, 0, 0, 2, true},
		{"held exactly at the cap is kept", func(a, b, g int64) int64 { return a + b }, false, 0, 0, 0, 2, true},
		{"one row over releases only the oldest", func(a, b, g int64) int64 { return b }, false, 1, 1, 0, 1, true},
		{"a tiny cap releases every held row", func(a, b, g int64) int64 { return 1 }, false, 2, 2, 0, 0, true},
		{"the oldest held row is a guard event: it goes first", func(a, b, g int64) int64 { return a + b }, true, 0, 0, 1, 2, false},
		{"guard first, then the oldest action", func(a, b, g int64) int64 { return b }, true, 1, 1, 1, 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, st := seed(t)
			d := openExisting(t, dbPath)
			a, b := actionBytes(t, d, "a"), actionBytes(t, d, "b")
			var g, gid int64
			hold := &PushHold{}
			if tc.guard {
				gid, g = insertGuardEvent(t, d, -300*24*time.Hour)
				hold.GuardMaxAgeDays = 30
			}
			hold.MaxHeldBytes = tc.capOf(a, b, g)
			res, err := New(d).Run(context.Background(), Options{MaxAgeDays: 30, DBPath: dbPath, PushHold: hold})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.ActionsDeleted != tc.wantDeleted {
				t.Errorf("deleted = %d, want %d", res.ActionsDeleted, tc.wantDeleted)
			}
			if res.HoldCap.ShedActions != tc.wantShedAct || res.HoldCap.ShedGuardEvents != tc.wantShedGuard {
				t.Errorf("shed = %+v, want actions %d guard %d", res.HoldCap, tc.wantShedAct, tc.wantShedGuard)
			}
			if want := a + b + g; res.HoldCap.HeldBytes != want {
				t.Errorf("held bytes = %d, want %d", res.HoldCap.HeldBytes, want)
			}
			if res.HeldForPush.Actions != tc.wantHeld {
				t.Errorf("held actions = %d, want %d", res.HeldForPush.Actions, tc.wantHeld)
			}
			if tc.guard && (gid >= res.GuardKeepFromID) != tc.wantGuardKept {
				t.Errorf("guard row %d vs keep floor %d, want kept=%v", gid, res.GuardKeepFromID, tc.wantGuardKept)
			}
			if n, _ := st.CountActions(context.Background()); n != 3-tc.wantDeleted {
				t.Errorf("remaining actions = %d, want %d", n, 3-tc.wantDeleted)
			}
		})
	}
}

// TestRun_HoldsGuardEventsAndAccountObservations pins the two tables the
// T-839 review found unheld, one row per hold posture: an aged guard_events
// row and an aged account observation of an unpushed session survive the
// pass under a hold, and go without one (a node that is not enrolled).
func TestRun_HoldsGuardEventsAndAccountObservations(t *testing.T) {
	tests := []struct {
		name          string
		hold          func(d *sql.DB, guardID int64) *PushHold
		wantObsKept   bool
		wantGuardKept bool
	}{
		{"not enrolled: both age out", func(*sql.DB, int64) *PushHold { return nil }, false, false},
		{"enrolled, nothing pushed: both held", func(*sql.DB, int64) *PushHold { return &PushHold{GuardMaxAgeDays: 30} }, true, true},
		{"enrolled, everything pushed: both age out", func(d *sql.DB, guardID int64) *PushHold {
			h := cursorsAt(t, d, "c")
			h.GuardEventsCursor = guardID
			h.GuardMaxAgeDays = 30
			return &h
		}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dbPath, st := seed(t)
			d := openExisting(t, dbPath)
			ctx := context.Background()
			gid, _ := insertGuardEvent(t, d, -100*24*time.Hour)
			if err := st.RecordToolAccounts(ctx, []models.ToolAccountObservation{{
				SessionID: "sess-a", Tool: models.ToolCursor, BindingKind: "message", BindingID: "m", Role: "assistant",
				Email: "fixture@example.invalid", Source: "fixture", Scope: "test", Stage: "activity",
				ObservedAt: fakeNow.Add(-200 * 24 * time.Hour),
			}}); err != nil {
				t.Fatal(err)
			}
			res, err := New(d).Run(ctx, Options{MaxAgeDays: 30, DBPath: dbPath, PushHold: tc.hold(d, gid)})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			// The guard sweep runs after Run in the composition root; drive it
			// the same way, with the floor Run computed.
			if _, err := store.New(d).PruneGuardRows(ctx, 30, res.GuardKeepFromID); err != nil {
				t.Fatalf("PruneGuardRows: %v", err)
			}
			var obs, guard int
			if err := d.QueryRow(`SELECT count(*) FROM tool_account_observations WHERE session_id = 'sess-a'`).Scan(&obs); err != nil {
				t.Fatal(err)
			}
			if err := d.QueryRow(`SELECT count(*) FROM guard_events WHERE id = ?`, gid).Scan(&guard); err != nil {
				t.Fatal(err)
			}
			if (obs == 1) != tc.wantObsKept {
				t.Errorf("account observation kept = %v, want %v", obs == 1, tc.wantObsKept)
			}
			if (guard == 1) != tc.wantGuardKept {
				t.Errorf("guard event kept = %v, want %v", guard == 1, tc.wantGuardKept)
			}
			if tc.wantGuardKept && res.HeldForPush.GuardEvents != 1 {
				t.Errorf("held guard events = %d, want 1", res.HeldForPush.GuardEvents)
			}
		})
	}
}
