package scoring_test

import (
	"context"
	"database/sql"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/scoring"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "score.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

type seedEvent struct {
	action    string
	target    string
	success   bool
	freshness string
	turnIndex int
	offsetSec int
}

func seed(t *testing.T, database *sql.DB, sessionID string, evs []seedEvent) string {
	t.Helper()
	ctx := context.Background()
	st := store.New(database)
	root := t.TempDir()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	var events []models.ToolEvent
	for i, e := range evs {
		events = append(events, models.ToolEvent{
			SourceFile:    "f-" + sessionID,
			SourceEventID: idFor(i),
			SessionID:     sessionID,
			ProjectRoot:   root,
			Timestamp:     base.Add(time.Duration(e.offsetSec) * time.Second),
			TurnIndex:     e.turnIndex,
			Tool:          models.ToolClaudeCode,
			Model:         "claude-sonnet-4-20250514",
			ActionType:    e.action,
			Target:        e.target,
			Success:       e.success,
		})
	}
	if _, err := st.Ingest(ctx, events, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// Apply freshness overrides directly — the test doesn't wire the
	// classifier.
	for i, e := range evs {
		if e.freshness == "" {
			continue
		}
		if _, err := database.ExecContext(ctx,
			`UPDATE actions SET freshness = ? WHERE source_event_id = ?`,
			e.freshness, idFor(i)); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func idFor(i int) string {
	return "e" + itoa(i)
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var out []byte
	for i > 0 {
		out = append([]byte{digits[i%10]}, out...)
		i /= 10
	}
	return string(out)
}

func TestScoreSession_Empty(t *testing.T) {
	database := openDB(t)
	s := scoring.New(database)
	got, err := s.ScoreSession(context.Background(), "nothing")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.TotalActions != 0 || got.QualityScore != 0 {
		t.Errorf("empty session should be zero: %+v", got)
	}
	if got.TurnsToFirstEdit != -1 {
		t.Errorf("empty session TurnsToFirstEdit should be -1: %+v", got)
	}
}

func TestScoreSession_PerfectRun(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-A", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, offsetSec: 0, turnIndex: 1},
		{action: models.ActionEditFile, target: "a.go", success: true, offsetSec: 10, turnIndex: 2},
		{action: models.ActionRunCommand, target: "go test", success: true, offsetSec: 20, turnIndex: 3},
	})
	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-A")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.ErrorRate != 0 {
		t.Errorf("ErrorRate: got %v, want 0", got.ErrorRate)
	}
	if got.RedundancyRatio != 0 {
		t.Errorf("RedundancyRatio: got %v, want 0", got.RedundancyRatio)
	}
	if got.ExplorationEff != 1 {
		t.Errorf("ExplorationEff: got %v, want 1 (edited the one file we read)", got.ExplorationEff)
	}
	if got.TurnsToFirstEdit != 2 {
		t.Errorf("TurnsToFirstEdit: got %d, want 2", got.TurnsToFirstEdit)
	}
	// Quality: 0.4*(1-0) + 0.3*(1-0) + 0.2*1 + 0.1*continuity(3)
	// continuity(3) = 1-exp(-3/20) ≈ 0.1393
	want := 0.4 + 0.3 + 0.2 + 0.1*(1-math.Exp(-3.0/20.0))
	if diff := got.QualityScore - want; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("QualityScore: got %v, want %v", got.QualityScore, want)
	}
}

func TestScoreSession_StaleReadsPenalizeRedundancy(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-B", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 0, turnIndex: 1},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 2},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "fresh", offsetSec: 20, turnIndex: 3},
		{action: models.ActionRunCommand, target: "go test", success: true, offsetSec: 30, turnIndex: 4},
	})
	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-B")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// 2 stale reads out of 4 read/run actions → 0.5
	if got.RedundancyRatio != 0.5 {
		t.Errorf("RedundancyRatio: got %v, want 0.5", got.RedundancyRatio)
	}
	// No edits → exploration 0
	if got.ExplorationEff != 0 {
		t.Errorf("ExplorationEff: got %v, want 0", got.ExplorationEff)
	}
	if got.TurnsToFirstEdit != -1 {
		t.Errorf("TurnsToFirstEdit: got %v, want -1", got.TurnsToFirstEdit)
	}
}

func TestScoreSession_FailuresIncreaseErrorRate(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-C", []seedEvent{
		{action: models.ActionRunCommand, target: "go test", success: false, offsetSec: 0, turnIndex: 1},
		{action: models.ActionEditFile, target: "a.go", success: true, offsetSec: 10, turnIndex: 2},
		{action: models.ActionRunCommand, target: "go test", success: true, offsetSec: 20, turnIndex: 3},
	})
	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-C")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.TotalFailures != 1 {
		t.Errorf("TotalFailures: %d", got.TotalFailures)
	}
	want := 1.0 / 3
	if diff := got.ErrorRate - want; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("ErrorRate: got %v, want %v", got.ErrorRate, want)
	}
}

func TestWrite_PersistsColumns(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-D", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, offsetSec: 0, turnIndex: 1},
		{action: models.ActionEditFile, target: "a.go", success: true, offsetSec: 5, turnIndex: 2},
	})
	s := scoring.New(database)
	scores, err := s.ScoreSession(context.Background(), "sess-D")
	if err != nil {
		t.Fatalf("score: %v", err)
	}
	if err := s.Write(context.Background(), scores); err != nil {
		t.Fatalf("write: %v", err)
	}
	var q float64
	var tfe sql.NullInt64
	if err := database.QueryRowContext(context.Background(),
		`SELECT quality_score, turns_to_first_edit FROM sessions WHERE id = ?`,
		"sess-D").Scan(&q, &tfe); err != nil {
		t.Fatal(err)
	}
	if q <= 0 {
		t.Errorf("quality_score not persisted: %v", q)
	}
	if !tfe.Valid || tfe.Int64 != 2 {
		t.Errorf("turns_to_first_edit: %+v", tfe)
	}
}

func TestBatchScore_OnlyUnscored(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-E", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, offsetSec: 0, turnIndex: 1},
	})
	seed(t, database, "sess-F", []seedEvent{
		{action: models.ActionEditFile, target: "a.go", success: true, offsetSec: 0, turnIndex: 1},
	})
	// Pre-score sess-E so it's excluded under OnlyUnscored.
	if _, err := database.ExecContext(context.Background(),
		`UPDATE sessions SET quality_score = 0.5 WHERE id = 'sess-E'`); err != nil {
		t.Fatal(err)
	}
	res, err := scoring.New(database).BatchScore(context.Background(), scoring.BatchOptions{OnlyUnscored: true})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if res.Considered != 1 {
		t.Errorf("Considered: %d, want 1", res.Considered)
	}
	if res.Scored != 1 {
		t.Errorf("Scored: %d, want 1", res.Scored)
	}
}

func TestContinuityFrom(t *testing.T) {
	cases := []struct {
		in     int
		approx float64
	}{
		{0, 0},
		{1, 0.049},
		{14, 0.503},
		{50, 0.918},
	}
	for _, tc := range cases {
		got := scoring.ContinuityFrom(tc.in)
		if diff := got - tc.approx; diff > 0.01 || diff < -0.01 {
			t.Errorf("ContinuityFrom(%d) = %v, want ~%v", tc.in, got, tc.approx)
		}
	}
}

// insertCacheEvent is a tiny helper for the §14.1 freshness-join
// tests. Inserts a single cache_events row at the supplied
// timestamp + kind so the splitStaleReads logic has data to
// classify against.
func insertCacheEvent(t *testing.T, database *sql.DB, sessionID, kind string, offsetSec int) {
	t.Helper()
	base := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)
	ts := base.Add(time.Duration(offsetSec) * time.Second).UTC().Format(time.RFC3339Nano)
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO cache_events
		   (session_id, tier, timestamp, model, kind, cause)
		 VALUES (?, 'proxy', ?, 'claude-sonnet-4-20250514', ?, '')`,
		sessionID, ts, kind)
	if err != nil {
		t.Fatal(err)
	}
}

// TestScoreSession_StaleSplitNilWithoutCache pins the spec §14.1
// invariant: sessions without ANY cache_events leave the three
// new fields nil. No fake zeros for Tier 3 / pre-backfill /
// non-Anthropic providers.
func TestScoreSession_StaleSplitNilWithoutCache(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-nil", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "fresh", offsetSec: 0, turnIndex: 1},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 2},
	})
	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-nil")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.StaleReadsWasteful != nil {
		t.Errorf("StaleReadsWasteful = %v, want nil (no cache_events for session)", *got.StaleReadsWasteful)
	}
	if got.StaleReadsNecessary != nil {
		t.Errorf("StaleReadsNecessary = %v, want nil", *got.StaleReadsNecessary)
	}
	if got.RedundancyRatioWasteful != nil {
		t.Errorf("RedundancyRatioWasteful = %v, want nil", *got.RedundancyRatioWasteful)
	}
}

// TestScoreSession_StaleSplitWasteful pins the all-wasteful case:
// the session has cache_events (so the split is active) but NO
// compaction_reset / expiry_rewrite intervened between the stale
// re-read and its prior read → all stale reads count as wasteful.
func TestScoreSession_StaleSplitWasteful(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-waste", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "fresh", offsetSec: 0, turnIndex: 1},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 2},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 20, turnIndex: 3},
		{action: models.ActionRunCommand, target: "go test", success: true, offsetSec: 30, turnIndex: 4},
	})
	// Seed a benign hit event so sessionHasCacheEvents returns true.
	insertCacheEvent(t, database, "sess-waste", "hit", 5)

	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-waste")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.StaleReadsWasteful == nil || *got.StaleReadsWasteful != 2 {
		t.Errorf("StaleReadsWasteful = %v, want 2", got.StaleReadsWasteful)
	}
	if got.StaleReadsNecessary == nil || *got.StaleReadsNecessary != 0 {
		t.Errorf("StaleReadsNecessary = %v, want 0", got.StaleReadsNecessary)
	}
	if got.RedundancyRatioWasteful == nil || *got.RedundancyRatioWasteful != 0.5 {
		t.Errorf("RedundancyRatioWasteful = %v, want 0.5 (2 wasteful / 4 read-or-run)", got.RedundancyRatioWasteful)
	}
}

// TestScoreSession_StaleSplitCompactionMarksNecessary pins the
// classifier: a compaction_reset between the prior read and the
// re-read marks the stale read as necessary, not wasteful.
func TestScoreSession_StaleSplitCompactionMarksNecessary(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-comp", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "fresh", offsetSec: 0, turnIndex: 1},
		// Compaction at offset 5 (between the prior read and the stale re-read at 10).
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 2},
		// Another stale re-read at 20, after compaction but with NO further compaction.
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 20, turnIndex: 3},
	})
	insertCacheEvent(t, database, "sess-comp", "compaction_reset", 5)

	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-comp")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Read at offset 10: prior read was at 0; compaction at 5 → NECESSARY.
	// Read at offset 20: prior read was at 10; no compaction in (10, 20] → WASTEFUL.
	if got.StaleReadsNecessary == nil || *got.StaleReadsNecessary != 1 {
		t.Errorf("StaleReadsNecessary = %v, want 1 (compaction at offset 5)", got.StaleReadsNecessary)
	}
	if got.StaleReadsWasteful == nil || *got.StaleReadsWasteful != 1 {
		t.Errorf("StaleReadsWasteful = %v, want 1 (no compaction in (10,20])", got.StaleReadsWasteful)
	}
}

// TestScoreSession_StaleSplitExpiryAlsoMarksNecessary pins that
// expiry_rewrite events (TTL eviction) also count as eviction
// for the wasteful/necessary split — same semantics as
// compaction.
func TestScoreSession_StaleSplitExpiryAlsoMarksNecessary(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-exp", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "fresh", offsetSec: 0, turnIndex: 1},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 2},
	})
	insertCacheEvent(t, database, "sess-exp", "expiry_rewrite", 5)

	got, err := scoring.New(database).ScoreSession(context.Background(), "sess-exp")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.StaleReadsNecessary == nil || *got.StaleReadsNecessary != 1 {
		t.Errorf("StaleReadsNecessary = %v, want 1 (expiry should count as eviction)", got.StaleReadsNecessary)
	}
}

// TestScoreSession_StaleSplitWritePersists pins the round-trip:
// the split fields land in the DB via UPDATE sessions and round-
// trip back through a follow-up read.
func TestScoreSession_StaleSplitWritePersists(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-rt", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "fresh", offsetSec: 0, turnIndex: 1},
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 2},
	})
	insertCacheEvent(t, database, "sess-rt", "hit", 5)

	s := scoring.New(database)
	got, err := s.ScoreSession(context.Background(), "sess-rt")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	// Read back the three columns directly.
	var wasteful, necessary sql.NullInt64
	var ratio sql.NullFloat64
	if err := database.QueryRow(`SELECT
		stale_reads_wasteful, stale_reads_necessary, redundancy_ratio_wasteful
		FROM sessions WHERE id = ?`, "sess-rt").Scan(&wasteful, &necessary, &ratio); err != nil {
		t.Fatal(err)
	}
	if !wasteful.Valid || wasteful.Int64 != 1 {
		t.Errorf("stale_reads_wasteful = %+v, want 1", wasteful)
	}
	if !necessary.Valid || necessary.Int64 != 0 {
		t.Errorf("stale_reads_necessary = %+v, want 0", necessary)
	}
	if !ratio.Valid {
		t.Errorf("redundancy_ratio_wasteful not persisted")
	}
}

// TestScoreSession_StaleSplitNilFieldsRoundTrip pins that a
// session WITHOUT cache_events round-trips to NULL columns —
// not zero.
func TestScoreSession_StaleSplitNilFieldsRoundTrip(t *testing.T) {
	database := openDB(t)
	seed(t, database, "sess-rt-nil", []seedEvent{
		{action: models.ActionReadFile, target: "a.go", success: true, freshness: "stale", offsetSec: 10, turnIndex: 1},
	})
	s := scoring.New(database)
	got, err := s.ScoreSession(context.Background(), "sess-rt-nil")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	var wasteful, necessary sql.NullInt64
	var ratio sql.NullFloat64
	if err := database.QueryRow(`SELECT
		stale_reads_wasteful, stale_reads_necessary, redundancy_ratio_wasteful
		FROM sessions WHERE id = ?`, "sess-rt-nil").Scan(&wasteful, &necessary, &ratio); err != nil {
		t.Fatal(err)
	}
	if wasteful.Valid {
		t.Errorf("stale_reads_wasteful must be NULL on cache-less session; got %d", wasteful.Int64)
	}
	if necessary.Valid {
		t.Errorf("stale_reads_necessary must be NULL on cache-less session; got %d", necessary.Int64)
	}
	if ratio.Valid {
		t.Errorf("redundancy_ratio_wasteful must be NULL on cache-less session; got %v", ratio.Float64)
	}
}
