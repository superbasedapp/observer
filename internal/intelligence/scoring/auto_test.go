package scoring_test

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/scoring"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedBase is the timestamp seed() anchors every action to.
var seedBase = time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)

func addAction(t *testing.T, database *sql.DB, sessionID, root, eventID string, ts time.Time) {
	t.Helper()
	ev := models.ToolEvent{
		SourceFile: "f-" + sessionID, SourceEventID: eventID, SessionID: sessionID,
		ProjectRoot: root, Timestamp: ts, Tool: models.ToolClaudeCode,
		Model: "claude-sonnet-4-20250514", ActionType: models.ActionEditFile,
		Target: "late.go", Success: true,
	}
	if _, err := store.New(database).Ingest(context.Background(), []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
}

func scoredActionCount(t *testing.T, database *sql.DB, sessionID string) sql.NullInt64 {
	t.Helper()
	var n sql.NullInt64
	if err := database.QueryRow(`SELECT scored_action_count FROM sessions WHERE id = ?`, sessionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWrite_PersistsBreakdownAndStamp(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-W", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, offsetSec: 0, turnIndex: 1},
		{action: models.ActionEditFile, target: "a.go", success: true, offsetSec: 5, turnIndex: 2},
	})
	stamp := time.Date(2026, 9, 27, 8, 0, 0, 0, time.UTC)
	s := scoring.New(database).WithNow(func() time.Time { return stamp })
	sc, err := s.ScoreSession(context.Background(), "sess-W")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(context.Background(), sc); err != nil {
		t.Fatal(err)
	}
	var ee, cs sql.NullFloat64
	var at sql.NullString
	var n sql.NullInt64
	if err := database.QueryRow(`SELECT exploration_efficiency, continuity_score, scored_at, scored_action_count
		FROM sessions WHERE id = 'sess-W'`).Scan(&ee, &cs, &at, &n); err != nil {
		t.Fatal(err)
	}
	if !ee.Valid || ee.Float64 != sc.ExplorationEff {
		t.Errorf("exploration_efficiency = %+v, want %v", ee, sc.ExplorationEff)
	}
	if !cs.Valid || cs.Float64 != sc.ContinuityScore {
		t.Errorf("continuity_score = %+v, want %v", cs, sc.ContinuityScore)
	}
	if !at.Valid || at.String != stamp.Format(time.RFC3339Nano) {
		t.Errorf("scored_at = %+v, want %s", at, stamp.Format(time.RFC3339Nano))
	}
	if !n.Valid || n.Int64 != 2 {
		t.Errorf("scored_action_count = %+v, want 2", n)
	}
	// The four weighted components must reproduce the persisted score.
	want := scoring.WeightRedundancy*(1-sc.RedundancyRatio) + scoring.WeightError*(1-sc.ErrorRate) +
		scoring.WeightExploration*sc.ExplorationEff + scoring.WeightContinuity*sc.ContinuityScore
	if d := want - sc.QualityScore; d > 1e-12 || d < -1e-12 {
		t.Errorf("components give %v, QualityScore %v", want, sc.QualityScore)
	}
}

func TestBatchScore_LimitAndIDs(t *testing.T) {
	cases := []struct {
		name       string
		opts       scoring.BatchOptions
		wantScored int
		wantIDs    []string // sessions that must end up scored
	}{
		{name: "limit bounds a pass", opts: scoring.BatchOptions{OnlyUnscored: true, Limit: 2}, wantScored: 2},
		{name: "ids restrict the pass", opts: scoring.BatchOptions{IDs: []string{"sess-L2"}}, wantScored: 1, wantIDs: []string{"sess-L2"}},
		{name: "no limit scores all with actions", opts: scoring.BatchOptions{OnlyUnscored: true}, wantScored: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			database := openDB(t)
			for _, id := range []string{"sess-L1", "sess-L2", "sess-L3"} {
				seed(t, database, id, []seedEvent{{action: models.ActionReadFile, target: "a.go", success: true}})
			}
			res, err := scoring.New(database).BatchScore(context.Background(), tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if res.Scored != tc.wantScored {
				t.Errorf("Scored = %d, want %d (%+v)", res.Scored, tc.wantScored, res)
			}
			for _, id := range tc.wantIDs {
				if !scoredActionCount(t, database, id).Valid {
					t.Errorf("%s not scored", id)
				}
			}
		})
	}
}

func TestSessionsActiveBetween(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-A1", []seedEvent{{action: models.ActionReadFile, target: "a.go", success: true, offsetSec: 0}})
	seed(t, database, "sess-A2", []seedEvent{{action: models.ActionReadFile, target: "a.go", success: true, offsetSec: 3600}})
	s := scoring.New(database)
	cases := []struct {
		name     string
		from, to time.Time
		want     map[string]bool
	}{
		{"both", seedBase.Add(-time.Minute), seedBase.Add(2 * time.Hour), map[string]bool{"sess-A1": true, "sess-A2": true}},
		{"from is exclusive", seedBase, seedBase.Add(2 * time.Hour), map[string]bool{"sess-A2": true}},
		{"to is inclusive", seedBase.Add(-time.Minute), seedBase, map[string]bool{"sess-A1": true}},
		{"empty window", seedBase, seedBase, map[string]bool{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.SessionsActiveBetween(context.Background(), tc.from, tc.to)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for _, id := range got {
				if !tc.want[id] {
					t.Errorf("unexpected %s", id)
				}
			}
		})
	}
}

// TestAutoScorer_Tick walks the daemon scorer through a realistic sequence:
// the backlog pass scores idle sessions but not a still-active one, the
// per-tick cap spreads a backlog over ticks, and a session that later gets
// new activity is re-scored once it goes idle again.
func TestAutoScorer_Tick(t *testing.T) {
	ctx := context.Background()
	database := openDB(t)
	rootOld := seed(t, database, "sess-old1", []seedEvent{{action: models.ActionReadFile, target: "a.go", success: true}})
	seed(t, database, "sess-old2", []seedEvent{{action: models.ActionReadFile, target: "b.go", success: true}})
	now := seedBase.Add(3 * time.Hour)
	// sess-live's last action is 5 minutes before "now": not idle yet.
	seed(t, database, "sess-live", []seedEvent{{action: models.ActionReadFile, target: "c.go", success: true, offsetSec: int(3*time.Hour/time.Second) - 300}})

	clock := now
	auto := scoring.NewAuto(scoring.New(database), scoring.AutoOptions{
		Idle:       30 * time.Minute,
		MaxPerTick: 1,
		Lookback:   time.Hour,
		Now:        func() time.Time { return clock },
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	// Tick 1: cap 1 → exactly one of the two idle sessions is scored.
	res, err := auto.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Rescored.Scored + res.Backlog.Scored; got != 1 {
		t.Fatalf("tick 1 scored %d, want 1 (%+v)", got, res)
	}
	// Tick 2: the other idle session; sess-live is still active and skipped.
	clock = now.Add(time.Minute)
	if _, err := auto.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"sess-old1", "sess-old2"} {
		if !scoredActionCount(t, database, id).Valid {
			t.Errorf("%s not scored after two ticks", id)
		}
	}
	if scoredActionCount(t, database, "sess-live").Valid {
		t.Errorf("sess-live scored while still active")
	}

	// sess-old1 gets a new action; an hour later it is idle again and the
	// re-score pass refreshes it (2 actions now) - and scores sess-live.
	addAction(t, database, "sess-old1", rootOld, "late-1", now.Add(2*time.Minute))
	clock = now.Add(time.Hour)
	auto.Opts().MaxPerTick = 10
	res, err = auto.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rescored.Scored < 1 {
		t.Errorf("tick 3 rescored %d, want >= 1 (%+v)", res.Rescored.Scored, res)
	}
	if n := scoredActionCount(t, database, "sess-old1"); !n.Valid || n.Int64 != 2 {
		t.Errorf("sess-old1 scored_action_count = %+v, want 2 after re-score", n)
	}
	if !scoredActionCount(t, database, "sess-live").Valid {
		t.Errorf("sess-live not scored once idle")
	}
}

// TestEvictedBetween pins the (start, end] TEXT-window semantics the
// preloaded eviction lookup must keep from the former per-read SQL predicate.
func TestEvictedBetween(t *testing.T) {
	t0 := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	stamps := []string{
		t0.Add(time.Minute).Format(time.RFC3339Nano),
		t0.Add(10 * time.Minute).Format(time.RFC3339Nano),
	}
	cases := []struct {
		name       string
		stamps     []string
		start, end time.Time
		want       bool
	}{
		{"event inside", stamps, t0, t0.Add(2 * time.Minute), true},
		{"start is exclusive", stamps, t0.Add(time.Minute), t0.Add(2 * time.Minute), false},
		{"end is inclusive", stamps, t0, t0.Add(time.Minute), true},
		{"gap between events", stamps, t0.Add(2 * time.Minute), t0.Add(9 * time.Minute), false},
		{"empty window", stamps, t0.Add(time.Minute), t0.Add(time.Minute), false},
		{"no events", nil, t0, t0.Add(time.Hour), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scoring.EvictedBetween(tc.stamps, tc.start, tc.end); got != tc.want {
				t.Errorf("evictedBetween = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewAuto_Defaults(t *testing.T) {
	a := scoring.NewAuto(scoring.New(nil), scoring.AutoOptions{Interval: -1, MaxPerTick: -5, Lookback: -1})
	if a.Opts().Interval != scoring.DefaultAutoInterval || a.Opts().Idle != scoring.DefaultAutoIdle ||
		a.Opts().MaxPerTick != scoring.DefaultAutoMaxPerTick || a.Opts().Lookback != 0 {
		t.Errorf("defaults not applied: %+v", *a.Opts())
	}
}
