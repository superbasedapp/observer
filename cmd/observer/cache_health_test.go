package main

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
)

// openCacheHealthTestDB opens a fresh observer DB so the cache
// tables migration 036 lands.
func openCacheHealthTestDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ch.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	return database, func() { database.Close() }
}

// seedCacheEvent writes a minimal cache_events row.
func seedCacheEvent(t *testing.T, database *sql.DB, sessionID string, kind cachetrack.Kind) {
	t.Helper()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind)
		 VALUES (?, 'proxy', '2026-06-08T12:00:00Z', 'm', ?)`,
		sessionID, string(kind))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

// seedDiagnosticEvent writes a cache_events row with full
// diagnostic columns (cause + predicted_kind) so the new
// breakdown tests can exercise the surface.
func seedDiagnosticEvent(t *testing.T, database *sql.DB, sessionID, model string, kind cachetrack.Kind, cause cachetrack.Cause, predictedKind cachetrack.Kind) {
	t.Helper()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, predicted_kind)
		 VALUES (?, 'proxy', '2026-06-09T12:00:00Z', ?, ?, ?, ?)`,
		sessionID, model, string(kind), string(cause), string(predictedKind))
	if err != nil {
		t.Fatalf("seed diagnostic: %v", err)
	}
}

// seedTokenEvent writes a cache_events row with tokens_read +
// tokens_written populated so the read:write consistency check
// has data to bite on.
func seedTokenEvent(t *testing.T, database *sql.DB, sessionID, model string, kind cachetrack.Kind, cause cachetrack.Cause, tokensRead, tokensWritten int64) {
	t.Helper()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO cache_events (session_id, tier, timestamp, model, kind, cause, predicted_kind, tokens_read, tokens_written)
		 VALUES (?, 'proxy', '2026-06-09T12:00:00Z', ?, ?, ?, 'write', ?, ?)`,
		sessionID, model, string(kind), string(cause), tokensRead, tokensWritten)
	if err != nil {
		t.Fatalf("seed token event: %v", err)
	}
}

// defaultThresholds returns the P0 thresholds with the secondary
// checks at their default operator settings (3.0× / 80%).
func defaultThresholds(minEvents int, maxRate float64) cacheHealthThresholds {
	return cacheHealthThresholds{
		MinEvents:           minEvents,
		MaxRate:             maxRate,
		MaxRewriteReadRatio: 3.0,
		MaxCauseShare:       0.80,
	}
}

// TestComputeCacheHealth_PassesGate verifies the P0 gate triggers
// PASS when graded events ≥ minEvents and rate ≤ maxRate.
func TestComputeCacheHealth_PassesGate(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	for i := 0; i < 100; i++ {
		seedCacheEvent(t, database, "sA", cachetrack.KindHit)
		seedCacheEvent(t, database, "sA", cachetrack.KindWrite)
	}

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(200, 0.05))
	if err != nil {
		t.Fatalf("computeCacheHealth: %v", err)
	}
	if !report.GatePassed {
		t.Errorf("gate did not pass: graded=%d rate=%.4f", report.GradedEvents, report.Rate)
	}
	if report.GradedEvents != 200 {
		t.Errorf("graded = %d, want 200", report.GradedEvents)
	}
	if report.Rate != 0 {
		t.Errorf("rate = %.4f, want 0", report.Rate)
	}
}

// TestComputeCacheHealth_InsufficientEventsFailsGate verifies the
// soak minimum is enforced — a corpus with too few events FAILs
// regardless of the rate.
func TestComputeCacheHealth_InsufficientEventsFailsGate(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	for i := 0; i < 50; i++ {
		seedCacheEvent(t, database, "sA", cachetrack.KindHit)
	}

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(200, 0.05))
	if err != nil {
		t.Fatal(err)
	}
	if report.GatePassed {
		t.Error("gate should not pass with only 50 graded events (need ≥ 200)")
	}
}

// TestComputeCacheHealth_PerSessionBreakdown verifies the
// per-session rollup matches the aggregate.
func TestComputeCacheHealth_PerSessionBreakdown(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	seedCacheEvent(t, database, "sA", cachetrack.KindHit)
	seedCacheEvent(t, database, "sA", cachetrack.KindWrite)
	seedCacheEvent(t, database, "sB", cachetrack.KindHit)

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(1, 1.0))
	if err != nil {
		t.Fatal(err)
	}
	if report.UniqueSessions != 2 {
		t.Errorf("UniqueSessions = %d, want 2", report.UniqueSessions)
	}
	if len(report.PerSession) != 2 {
		t.Fatalf("per-session rows = %d, want 2", len(report.PerSession))
	}
}

// TestComputeCacheHealth_DiagnosticBreakdown verifies the
// operator-requested mispredict breakdown: each mispredict
// event carries kind + cause + predicted_kind so a failing or
// marginal gate is diagnosable by CAUSE, not just by the rate.
// The CauseBreakdown rollup orders by frequency descending so
// dominant causes surface first.
func TestComputeCacheHealth_DiagnosticBreakdown(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	// A modest fixture: 5 hits (suffix_growth), 5 writes
	// (suffix_growth), 2 system_changed invalidation writes,
	// and 3 mispredicts that came from different causes so the
	// breakdown is non-trivial.
	for i := 0; i < 5; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-7",
			cachetrack.KindHit, cachetrack.CauseSuffixGrowth, cachetrack.KindHit)
	}
	for i := 0; i < 5; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-7",
			cachetrack.KindWrite, cachetrack.CauseSuffixGrowth, cachetrack.KindWrite)
	}
	for i := 0; i < 2; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-7",
			cachetrack.KindInvalidationRewrite, cachetrack.CauseSystemChanged, cachetrack.KindHit)
	}
	seedDiagnosticEvent(t, database, "sA", "claude-opus-4-7",
		cachetrack.KindMispredict, cachetrack.CauseUnknown, cachetrack.KindHit)
	seedDiagnosticEvent(t, database, "sA", "claude-opus-4-7",
		cachetrack.KindMispredict, cachetrack.CauseToolsOrSystemChanged, cachetrack.KindHit)
	seedDiagnosticEvent(t, database, "sB", "claude-opus-4-7",
		cachetrack.KindMispredict, cachetrack.CauseBlockDiverged, cachetrack.KindWrite)

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(1, 1.0))
	if err != nil {
		t.Fatalf("computeCacheHealth: %v", err)
	}

	// MispredictEvents must contain 3 entries, each with the
	// full diagnostic triple.
	if len(report.MispredictEvents) != 3 {
		t.Fatalf("MispredictEvents = %d, want 3", len(report.MispredictEvents))
	}
	for _, ev := range report.MispredictEvents {
		if ev.Kind != string(cachetrack.KindMispredict) {
			t.Errorf("ev.Kind = %q, want mispredict", ev.Kind)
		}
		if ev.Cause == "" {
			t.Errorf("ev.Cause empty — diagnosability lost: %+v", ev)
		}
		if ev.PredictedKind == "" {
			t.Errorf("ev.PredictedKind empty — diagnosability lost: %+v", ev)
		}
	}

	// CauseBreakdown must surface the 2 system_changed events
	// FIRST (most frequent among rolled causes after the 10
	// suffix_growth). Walk the slice and confirm
	// suffix_growth → 12 (5 hit + 5 write + 0 misp marker on it),
	// system_changed → 2, plus the 3 single-fire mispredict
	// causes.
	got := map[string]int{}
	for _, c := range report.CauseBreakdown {
		got[c.Cause] = c.Count
	}
	if got["suffix_growth"] != 10 {
		t.Errorf("CauseBreakdown[suffix_growth] = %d, want 10", got["suffix_growth"])
	}
	if got["system_changed"] != 2 {
		t.Errorf("CauseBreakdown[system_changed] = %d, want 2", got["system_changed"])
	}
	if got["unknown"] != 1 || got["tools_or_system_changed"] != 1 || got["block_diverged"] != 1 {
		t.Errorf("CauseBreakdown missing per-mispredict causes: %+v", got)
	}

	// CauseBreakdown ordering — suffix_growth (10) before
	// system_changed (2) before the 3 unit-count entries.
	if report.CauseBreakdown[0].Cause != "suffix_growth" {
		t.Errorf("CauseBreakdown[0] = %q, want suffix_growth (highest count)", report.CauseBreakdown[0].Cause)
	}
	if report.CauseBreakdown[1].Cause != "system_changed" {
		t.Errorf("CauseBreakdown[1] = %q, want system_changed", report.CauseBreakdown[1].Cause)
	}
}

// TestComputeCacheHealth_InconsistentRewriteDetected models the
// f81cec3f soak shape: a long run of "system_changed" events with
// read >> write. A real system invalidation rebuilds the prefix
// cold (read ≈ 0); the check flags these as mechanically
// inconsistent so a mislabeled cause is caught even when the rate
// gate is silent. KindWrite under suffix_growth (large read +
// small write) must NOT trip because that IS the healthy shape.
func TestComputeCacheHealth_InconsistentRewriteDetected(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	// 5 "system_changed" invalidation rewrites mimicking f81cec3f:
	// read=17806 / write=147 → ratio ≈ 121×. All five must surface
	// regardless of how few there are (no min count for the
	// secondary check; it's per-event).
	for i := 0; i < 5; i++ {
		seedTokenEvent(t, database, "sA", "claude-opus-4-8",
			cachetrack.KindInvalidationRewrite, cachetrack.CauseSystemChanged,
			17806, 147)
	}
	// 50 healthy suffix_growth KindWrite events with the same
	// read >> write shape — MUST NOT trip the check, because the
	// kind itself reports a warm growth write, not an invalidation.
	for i := 0; i < 50; i++ {
		seedTokenEvent(t, database, "sA", "claude-opus-4-8",
			cachetrack.KindWrite, cachetrack.CauseSuffixGrowth,
			17806, 147)
	}

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(1, 1.0))
	if err != nil {
		t.Fatalf("computeCacheHealth: %v", err)
	}
	if len(report.InconsistentRewriteEvents) != 5 {
		t.Fatalf("InconsistentRewriteEvents = %d, want 5 (suffix_growth KindWrites must NOT trip; only the rewrite-kind events should)",
			len(report.InconsistentRewriteEvents))
	}
	for _, e := range report.InconsistentRewriteEvents {
		if e.Kind != string(cachetrack.KindInvalidationRewrite) {
			t.Errorf("unexpected kind in inconsistent list: %q", e.Kind)
		}
		if e.Ratio < 100 {
			t.Errorf("ratio = %.1f, want ≥ 100×", e.Ratio)
		}
	}
	if report.InconsistentRewriteThreshold != 3.0 {
		t.Errorf("InconsistentRewriteThreshold = %v, want 3.0", report.InconsistentRewriteThreshold)
	}
}

// TestComputeCacheHealth_DominantCauseDetected models the
// f81cec3f 198/201 system_changed share (98.5%). One non-
// suffix_growth cause over the threshold must surface in
// DominantCause; the gate verdict is unaffected.
func TestComputeCacheHealth_DominantCauseDetected(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	// 198 system_changed invalidation rewrites + 3 other-cause
	// events. Share = 198/201 ≈ 98.5%, well over the 80% default.
	for i := 0; i < 198; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-8",
			cachetrack.KindInvalidationRewrite, cachetrack.CauseSystemChanged, cachetrack.KindWrite)
	}
	for i := 0; i < 2; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-8",
			cachetrack.KindInvalidationRewrite, cachetrack.CauseToolsChanged, cachetrack.KindWrite)
	}
	seedDiagnosticEvent(t, database, "sA", "claude-opus-4-8",
		cachetrack.KindMispredict, cachetrack.CauseUnknown, cachetrack.KindWrite)

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(1, 1.0))
	if err != nil {
		t.Fatalf("computeCacheHealth: %v", err)
	}
	if report.DominantCause == nil {
		t.Fatalf("DominantCause = nil; want non-nil with cause=system_changed")
	}
	if report.DominantCause.Cause != string(cachetrack.CauseSystemChanged) {
		t.Errorf("DominantCause.Cause = %q, want system_changed", report.DominantCause.Cause)
	}
	if report.DominantCause.Count != 198 {
		t.Errorf("DominantCause.Count = %d, want 198", report.DominantCause.Count)
	}
	if report.DominantCause.Share < 0.95 {
		t.Errorf("DominantCause.Share = %.4f, want > 0.95", report.DominantCause.Share)
	}
	// Gate is independent of the dominance check; this fixture
	// has 200 graded events at 0% rate so it should PASS the
	// rate gate even with the dominant cause warning.
	if !report.GatePassed {
		t.Errorf("gate should still PASS independent of cause concentration; got FAIL")
	}
}

// TestComputeCacheHealth_HealthyDistributionNoDominantCause: a
// healthy session with suffix_growth dominating must NOT surface
// suffix_growth in DominantCause (it's excluded by design — every
// long session is suffix_growth-dominated).
func TestComputeCacheHealth_HealthyDistributionNoDominantCause(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	for i := 0; i < 95; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-8",
			cachetrack.KindWrite, cachetrack.CauseSuffixGrowth, cachetrack.KindWrite)
	}
	for i := 0; i < 5; i++ {
		seedDiagnosticEvent(t, database, "sA", "claude-opus-4-8",
			cachetrack.KindInvalidationRewrite, cachetrack.CauseSystemChanged, cachetrack.KindWrite)
	}

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(1, 1.0))
	if err != nil {
		t.Fatalf("computeCacheHealth: %v", err)
	}
	if report.DominantCause != nil {
		t.Errorf("DominantCause = %+v; want nil — suffix_growth dominance is healthy and excluded", report.DominantCause)
	}
}

// TestComputeCacheHealth_HandoffRehydrationNotDominant: a
// handoff-heavy corpus (many kind=reanchor cause=handoff_rehydration
// rehydration writes) must NOT surface handoff_rehydration in
// DominantCause — the by-design first-turn cold write is a baseline
// cause, excluded from the concentration WARN alongside suffix_growth.
func TestComputeCacheHealth_HandoffRehydrationNotDominant(t *testing.T) {
	t.Parallel()
	database, cleanup := openCacheHealthTestDB(t)
	defer cleanup()

	// 200 rehydration writes (kind=reanchor → not graded, but counted
	// in CauseBreakdown) vs a handful of graded suffix_growth writes.
	// Their share over GradedEvents is enormous; without the exclusion
	// handoff_rehydration would be flagged as the dominant cause.
	for i := 0; i < 200; i++ {
		seedDiagnosticEvent(t, database, "sHO", "claude-opus-4-8",
			cachetrack.KindReanchor, cachetrack.CauseHandoffRehydration, cachetrack.KindReanchor)
	}
	for i := 0; i < 10; i++ {
		seedDiagnosticEvent(t, database, "sHO", "claude-opus-4-8",
			cachetrack.KindWrite, cachetrack.CauseSuffixGrowth, cachetrack.KindWrite)
	}

	report, err := computeCacheHealth(context.Background(), database, defaultThresholds(1, 1.0))
	if err != nil {
		t.Fatalf("computeCacheHealth: %v", err)
	}
	if report.DominantCause != nil {
		t.Errorf("DominantCause = %+v; want nil — handoff_rehydration is a by-design baseline cause, excluded", report.DominantCause)
	}
}

// TestPrintCacheHealth covers the human-readable rendering.
func TestPrintCacheHealth(t *testing.T) {
	t.Parallel()
	r := CacheHealthReport{
		TotalEvents:    250,
		GradedEvents:   200,
		Mispredicts:    5,
		Rate:           0.025,
		MinEvents:      200,
		MaxRate:        0.05,
		GatePassed:     true,
		UniqueSessions: 3,
		PerSession: []SessionHealthRow{
			{SessionID: "sA", GradedEvents: 100, Mispredicts: 2, Rate: 0.02},
		},
		InconsistentRewriteThreshold: 3.0,
		MaxCauseShare:                0.80,
	}
	var buf bytes.Buffer
	printCacheHealth(&buf, r)
	out := buf.String()
	for _, want := range []string{
		"PASS",
		"graded events", "≥ 200", "0.0250", "sA",
		"read:write consistency: CLEAN",
		"cause concentration: CLEAN",
	} {
		if !chContains(out, want) {
			t.Errorf("output missing %q\noutput:\n%s", want, out)
		}
	}
}

// TestPrintCacheHealth_WithWarnings exercises the WARN paths so
// they're visible to operators triaging a soak result.
func TestPrintCacheHealth_WithWarnings(t *testing.T) {
	t.Parallel()
	r := CacheHealthReport{
		TotalEvents:    201,
		GradedEvents:   201,
		Mispredicts:    1,
		Rate:           0.005,
		MinEvents:      200,
		MaxRate:        0.05,
		GatePassed:     true,
		UniqueSessions: 1,
		InconsistentRewriteEvents: []InconsistentRewriteEvent{
			{
				SessionID: "sA", Timestamp: "2026-06-09T20:16:44Z", Model: "claude-opus-4-8",
				Kind: "invalidation_rewrite", Cause: "system_changed",
				TokensRead: 17806, TokensWritten: 147, Ratio: 121.13,
			},
		},
		InconsistentRewriteThreshold: 3.0,
		DominantCause: &DominantCauseRow{
			Cause: "system_changed", Count: 198, Share: 0.985,
		},
		MaxCauseShare: 0.80,
	}
	var buf bytes.Buffer
	printCacheHealth(&buf, r)
	out := buf.String()
	for _, want := range []string{
		"read:write consistency: WARN — 1 event(s)",
		"ratio=121.1x",
		"cause concentration: WARN",
		"system_changed at 198/201 graded (98.5%)",
	} {
		if !chContains(out, want) {
			t.Errorf("output missing %q\noutput:\n%s", want, out)
		}
	}
}

// chContains is a tiny local helper (package already has a
// `contains` symbol in learn.go).
func chContains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
