package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
)

func TestProjectQualityDayUpsertHistoryAndPrune(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/repo/q", "")
	if err != nil {
		t.Fatal(err)
	}
	at := func(y int, m time.Month, d, h int) time.Time { return time.Date(y, m, d, h, 0, 0, 0, time.UTC) }

	first := codequality.DayPoint{
		Day: "2026-11-03", MeasuredAt: at(2026, 11, 3, 8),
		CoverageState: codequality.StateMeasured, CoverageLines: 100, CoverageCovered: 40, CoverageReports: 1,
		CoverageReportAt: at(2026, 11, 2, 9),
		DupState:         codequality.StateCodeIntelOff,
	}
	if err := s.UpsertProjectQualityDay(ctx, pid, first); err != nil {
		t.Fatal(err)
	}
	// A later measurement the same day replaces the row.
	later := first
	later.MeasuredAt = at(2026, 11, 3, 14)
	later.CoverageCovered = 55
	if err := s.UpsertProjectQualityDay(ctx, pid, later); err != nil {
		t.Fatal(err)
	}
	next := codequality.DayPoint{
		Day: "2026-11-04", MeasuredAt: at(2026, 11, 4, 1), CoverageState: codequality.StateNoReport,
		DupState: codequality.StateMeasured, DupEligibleSymbols: 10, DupClonedSymbols: 2, DupEligibleLines: 200, DupClonedLines: 30, DupGroups: 1,
		ComplexityState: codequality.StateMeasured, ComplexityFunctions: 40, ComplexityOver: 3, ComplexitySum: 160, ComplexityP90: 9, ComplexityMax: 31,
	}
	if err := s.UpsertProjectQualityDay(ctx, pid, next); err != nil {
		t.Fatal(err)
	}

	hist, err := s.LoadProjectQualityHistory(ctx, pid, at(2026, 11, 1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[0].Day != "2026-11-03" || hist[0].CoverageCovered != 55 || !hist[0].MeasuredAt.Equal(later.MeasuredAt) {
		t.Fatalf("history = %+v", hist)
	}
	if !hist[0].CoverageReportAt.Equal(first.CoverageReportAt) || !hist[1].CoverageReportAt.IsZero() {
		t.Fatalf("report times: %v / %v (an absent time must stay zero)", hist[0].CoverageReportAt, hist[1].CoverageReportAt)
	}
	if hist[1].DupState != codequality.StateMeasured || hist[1].DupClonedLines != 30 {
		t.Fatalf("dup = %+v", hist[1])
	}
	if h := hist[1]; h.ComplexityState != codequality.StateMeasured || h.ComplexityFunctions != 40 || h.ComplexityOver != 3 ||
		h.ComplexitySum != 160 || h.ComplexityP90 != 9 || h.ComplexityMax != 31 {
		t.Fatalf("complexity = %+v", h)
	}
	if hist[0].ComplexityState != "" {
		t.Fatalf("a point without complexity reads state %q, want empty", hist[0].ComplexityState)
	}
	latest, ok, err := s.LatestProjectQualityDay(ctx, pid)
	if err != nil || !ok || latest.Day != "2026-11-04" {
		t.Fatalf("latest = %+v %v %v", latest, ok, err)
	}
	if _, ok, err := s.LatestProjectQualityDay(ctx, pid+999); err != nil || ok {
		t.Fatalf("unknown project: ok=%v err=%v", ok, err)
	}

	// A row far in the future prunes everything older than the history window.
	far := next
	far.Day = "2028-01-01"
	if err := s.UpsertProjectQualityDay(ctx, pid, far); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM project_quality_daily WHERE project_id = ?`, pid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows after prune = %d, want 1", n)
	}

	if err := s.UpsertProjectQualityDay(ctx, pid, codequality.DayPoint{}); err == nil {
		t.Fatal("a point with no day must be refused")
	}
}
