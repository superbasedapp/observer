package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/proccapture"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// seedCaptureForOrg writes, through the one capture writer: a session rollup
// group in the current minute (with an argv preview), the same group 8 days
// ago (outside the wire window), a machine rollup (session NULL), the
// session's stats row, the machine stats row, and an exemplar run carrying
// the capture columns.
func seedCaptureForOrg(t *testing.T, s *Store) (string, time.Time) {
	t.Helper()
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	now := time.Now().UTC()
	bucket := proccapture.BucketStart(now, time.Minute)
	old := proccapture.BucketStart(now.AddDate(0, 0, -8), time.Minute)
	key := proccapture.GroupKey{
		SessionID: sess, BucketStart: bucket, Kind: proccapture.GroupService,
		ParentProcessKey: "root-1", ServiceRootKey: "root-1", ExeBasename: "docker.exe", ArgvTemplateHash: "h1",
	}
	oldKey := key
	oldKey.BucketStart = old
	machine := proccapture.GroupKey{BucketStart: bucket, Kind: proccapture.GroupUnattributed, ExeBasename: "git", ArgvTemplateHash: "h2"}

	root := execRun("root-1", sess, pid, 300, now.Add(-time.Minute))
	root.CaptureClass = string(proccapture.ClassServiceRoot)
	root.ServiceRootKey = "root-1"

	if _, err := s.PersistCapture(ctx, []procmodel.ProcessRun{root}, proccapture.Delta{
		Rollups: []proccapture.Rollup{
			{
				Key: key, ActionID: 7, Count: 4, FailedCount: 1, DurationSumMs: 40, DurationMaxMs: 20, CPUSumMs: 8, PeakRSSBytes: 64,
				FirstSeen: now, LastSeen: now, ExampleArgvPreview: "docker.exe stats --no-stream", ExampleProcessKey: "k-ex",
			},
			{Key: oldKey, Count: 9, FirstSeen: now.AddDate(0, 0, -8), LastSeen: now.AddDate(0, 0, -8)},
			{Key: machine, Count: 2, FirstSeen: now, LastSeen: now},
		},
		Stats: map[string]proccapture.Stats{
			sess: {Observed: 15, Kept: 1, ServiceRolledUp: 13, Dropped: 1, BudgetHits: 2},
			"":   {Observed: 2, RolledUp: 2},
		},
		Folds: map[string]int64{"root-1": 3},
	}); err != nil {
		t.Fatalf("PersistCapture: %v", err)
	}
	return sess, now
}

func TestSelectSessionProcessRollupRows_WindowMachineAndGate(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, _ := seedCaptureForOrg(t, s)

	raw, err := s.SelectSessionProcessRollupRows(ctx, ShareOptions{FullContent: true})
	if err != nil {
		t.Fatalf("SelectSessionProcessRollupRows: %v", err)
	}
	// Only the in-window session group: the 8-day-old bucket is outside the
	// window and the machine rollup never ships.
	if len(raw) != 1 {
		t.Fatalf("rows = %d, want 1: %+v", len(raw), raw)
	}
	r := raw[0]
	if r.SessionID != sess || r.GroupKind != "service" || r.ServiceRootKey != "root-1" || r.ParentProcessKey != "root-1" ||
		r.ExeBasename != "docker.exe" || r.ArgvTemplateHash != "h1" || r.ActionID != 7 || r.Count != 4 || r.FailedCount != 1 ||
		r.DurationSumMs != 40 || r.DurationMaxMs != 20 || r.CPUSumMs != 8 || r.PeakRSSBytes != 64 ||
		r.ExampleProcessKey != "k-ex" || r.BucketStart == "" || r.FirstSeen == "" || r.LastSeen == "" {
		t.Fatalf("row = %+v", r)
	}
	if r.ExampleArgvPreview != "docker.exe stats --no-stream" {
		t.Fatalf("raw-content posture must ship the example argv, got %q", r.ExampleArgvPreview)
	}

	// The Select re-applies the gate: without raw content the argv preview is
	// empty and every count still ships.
	bare, err := s.SelectSessionProcessRollupRows(ctx, ShareOptions{})
	if err != nil {
		t.Fatalf("SelectSessionProcessRollupRows bare: %v", err)
	}
	if len(bare) != 1 || bare[0].ExampleArgvPreview != "" || bare[0].Count != 4 {
		t.Fatalf("metadata-only posture: %+v", bare)
	}
}

func TestSelectSessionProcessCaptureStatsRows_ExcludesMachineAndStale(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, _ := seedCaptureForOrg(t, s)

	rows, err := s.SelectSessionProcessCaptureStatsRows(ctx)
	if err != nil {
		t.Fatalf("SelectSessionProcessCaptureStatsRows: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 (the machine row never ships): %+v", len(rows), rows)
	}
	got := rows[0]
	want := orgcontract.SessionProcessCaptureStatsRow{SessionID: sess, Observed: 15, Kept: 1, ServiceRolledUp: 13, Dropped: 1, BudgetHits: 2, UpdatedAt: got.UpdatedAt}
	if got != want || got.UpdatedAt == "" {
		t.Fatalf("stats = %+v, want %+v", got, want)
	}

	// A stats row last changed before the window does not ship.
	if _, err := s.db.ExecContext(ctx, `UPDATE process_capture_stats SET updated_at = ? WHERE session_id = ?`,
		timestamp(time.Now().UTC().AddDate(0, 0, -8)), sess); err != nil {
		t.Fatal(err)
	}
	rows, err = s.SelectSessionProcessCaptureStatsRows(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("stale stats shipped: %+v %v", rows, err)
	}
}

// TestSelectSessionProcessRollupRows_CapsPerSessionNewestFirst pins the
// per-session cap: the newest sessionProcessRollupCap buckets ship, the
// oldest are dropped, and another session keeps its own allowance.
func TestSelectSessionProcessRollupRows_CapsPerSessionNewestFirst(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, pid := mustProjectAndSession(t, s)
	seedSession(t, s, "sess-other", pid)
	now := proccapture.BucketStart(time.Now().UTC(), time.Minute)
	const over = 3
	rollups := make([]proccapture.Rollup, 0, sessionProcessRollupCap+over+1)
	for i := 0; i < sessionProcessRollupCap+over; i++ {
		rollups = append(rollups, proccapture.Rollup{Key: proccapture.GroupKey{
			SessionID:   sess,
			BucketStart: now.Add(-time.Duration(i) * time.Minute), Kind: proccapture.GroupBudget, ExeBasename: "node",
		}, Count: 1})
	}
	rollups = append(rollups, proccapture.Rollup{Key: proccapture.GroupKey{
		SessionID:   "sess-other",
		BucketStart: now, Kind: proccapture.GroupFold, ExeBasename: "conhost.exe",
	}, Count: 5})
	if _, err := s.PersistCapture(ctx, nil, proccapture.Delta{Rollups: rollups}); err != nil {
		t.Fatalf("PersistCapture: %v", err)
	}
	rows, err := s.SelectSessionProcessRollupRows(ctx, ShareOptions{AdminManaged: true})
	if err != nil {
		t.Fatalf("SelectSessionProcessRollupRows: %v", err)
	}
	per := map[string]int{}
	oldest := map[string]string{}
	for _, r := range rows {
		per[r.SessionID]++
		if o, ok := oldest[r.SessionID]; !ok || r.BucketStart < o {
			oldest[r.SessionID] = r.BucketStart
		}
	}
	if per[sess] != sessionProcessRollupCap || per["sess-other"] != 1 {
		t.Fatalf("per-session rows = %v, want %d and 1", per, sessionProcessRollupCap)
	}
	wantOldest := now.Add(-time.Duration(sessionProcessRollupCap-1) * time.Minute).UTC().Format(time.RFC3339)
	if oldest[sess] != wantOldest {
		t.Fatalf("oldest kept bucket = %s, want %s (the newest %d ship)", oldest[sess], wantOldest, sessionProcessRollupCap)
	}
}

// TestSelectUnpushedSince_ProcessCaptureWireGated pins the push composition:
// a metadata-only node ships no capture rows (the whole session-process tier
// is shipsRawContent()-gated), an enterprise node ships both slices stamped
// with its org and user, and the exemplar SessionProcessRow carries the
// capture columns.
func TestSelectUnpushedSince_ProcessCaptureWireGated(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sess, _ := seedCaptureForOrg(t, s)

	teams, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u",
		ShareOptions{CacheDetail: true, ProcessDetail: true, RoutingSummary: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("teams SelectUnpushedSince: %v", err)
	}
	if len(teams.SessionProcessRollups) != 0 || len(teams.SessionProcessCaptureStats) != 0 || len(teams.SessionProcesses) != 0 {
		t.Fatalf("capture wire shipped under metadata-only posture: rollups=%d stats=%d runs=%d",
			len(teams.SessionProcessRollups), len(teams.SessionProcessCaptureStats), len(teams.SessionProcesses))
	}

	ent, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u", ShareOptions{AdminManaged: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("enterprise SelectUnpushedSince: %v", err)
	}
	if len(ent.SessionProcessRollups) != 1 || len(ent.SessionProcessCaptureStats) != 1 {
		t.Fatalf("enterprise capture wire: rollups=%d stats=%d", len(ent.SessionProcessRollups), len(ent.SessionProcessCaptureStats))
	}
	for _, r := range ent.SessionProcessRollups {
		if r.OrgID != "o" || r.UserEmail != "u" || r.SessionID != sess || r.ExampleArgvPreview == "" {
			t.Fatalf("rollup row not stamped / gated: %+v", r)
		}
	}
	if st := ent.SessionProcessCaptureStats[0]; st.OrgID != "o" || st.UserEmail != "u" || st.Observed != 15 {
		t.Fatalf("stats row: %+v", st)
	}
	var found bool
	for _, p := range ent.SessionProcesses {
		if p.RunKey == "root-1" {
			found = true
			if p.CaptureClass != "service_root" || p.ServiceRootKey != "root-1" || p.FoldCount != 3 {
				t.Fatalf("exemplar row capture columns: %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("exemplar root-1 missing from SessionProcesses: %d rows", len(ent.SessionProcesses))
	}
	if !ent.hasSessionAggregates() {
		t.Fatal("a batch carrying capture rows must count as aggregate-bearing")
	}
}
