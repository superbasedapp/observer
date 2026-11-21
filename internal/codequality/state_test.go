package codequality

import (
	"testing"
	"time"
)

// One case per row of each state table, in table order.

func TestCoverageStateRows(t *testing.T) {
	cases := []struct {
		f    CoverageFacts
		want State
	}{
		{CoverageFacts{Enabled: false, Found: 3, Lines: 10}, StateOff},
		{CoverageFacts{Enabled: true, RootMissing: true}, StateRootMissing},
		{CoverageFacts{Enabled: true}, StateNoReport},
		{CoverageFacts{Enabled: true, Problems: 1}, StateUnreadable},
		{CoverageFacts{Enabled: true, Found: 1, Lines: 0}, StateNoLines},
		{CoverageFacts{Enabled: true, Found: 1, Problems: 2, Lines: 5}, StateMeasured},
	}
	if len(cases) != len(coverageRules) {
		t.Fatalf("one case per rule: %d cases, %d rules", len(cases), len(coverageRules))
	}
	for i, c := range cases {
		got, reason := CoverageState(c.f)
		if got != c.want || reason == "" {
			t.Errorf("row %d: got %q (%q), want %q", i, got, reason, c.want)
		}
	}
}

func TestDuplicationStateRows(t *testing.T) {
	cases := []struct {
		f    DuplicationFacts
		want State
	}{
		{DuplicationFacts{Enabled: false, CodeIntelOn: true, IndexedFiles: 5, EligibleSymbols: 5}, StateOff},
		{DuplicationFacts{Enabled: true, NotInBuild: true}, StateNotInBuild},
		{DuplicationFacts{Enabled: true, Archived: true}, StateArchived},
		{DuplicationFacts{Enabled: true, CodeIntelOn: false}, StateCodeIntelOff},
		{DuplicationFacts{Enabled: true, CodeIntelOn: true}, StateNotIndexed},
		{DuplicationFacts{Enabled: true, CodeIntelOn: true, IndexedFiles: 3}, StateNoSymbols},
		{DuplicationFacts{Enabled: true, CodeIntelOn: false, IndexedFiles: 3, EligibleSymbols: 1}, StateMeasured},
	}
	if len(cases) != len(duplicationRules) {
		t.Fatalf("one case per rule: %d cases, %d rules", len(cases), len(duplicationRules))
	}
	for i, c := range cases {
		got, reason := DuplicationState(c.f)
		if got != c.want || reason == "" {
			t.Errorf("row %d: got %q (%q), want %q", i, got, reason, c.want)
		}
	}
}

func TestMeasureCoverageHidesNumbersWhenNotMeasured(t *testing.T) {
	found := []Found{{RelPath: "lcov.info", Report: Report{Format: FormatLCOV, Lines: 10, Covered: 5, Files: []FileCoverage{{Path: "a", Lines: 10, Covered: 5}}}}}
	off := MeasureCoverage(false, false, found, nil)
	if off.State != StateOff || off.Percent != nil || off.Lines != 0 {
		t.Fatalf("off = %+v", off)
	}
	on := MeasureCoverage(true, false, found, []Problem{{RelPath: "z", Kind: ProblemTooLarge}, {RelPath: "a", Kind: ProblemSymlink}})
	if on.State != StateMeasured || on.Percent == nil || *on.Percent != 50 {
		t.Fatalf("on = %+v", on)
	}
	if on.Problems[0].RelPath != "a" {
		t.Fatalf("problems sorted: %+v", on.Problems)
	}
}

func TestMeasureDuplicationStaleAndNotInBuild(t *testing.T) {
	in := DuplicationInput{
		Index:   IndexFacts{Key: "/r", IndexedFiles: 2},
		Symbols: []Symbol{sym(1, "a.go", "function", 1, 10), sym(2, "b.go", "function", 1, 10)},
		Buckets: append(bucketsFor(1, 500, 12), bucketsFor(2, 500, 12)...),
	}
	off := MeasureDuplication(true, false, in)
	if off.State != StateMeasured || !off.Stale || off.ClonedSymbols != 2 {
		t.Fatalf("index from when codeintel was on = %+v", off)
	}
	on := MeasureDuplication(true, true, in)
	if on.Stale {
		t.Fatal("codeintel on is not stale")
	}
	nb := MeasureDuplication(true, true, DuplicationInput{Index: IndexFacts{NotInBuild: true}})
	if nb.State != StateNotInBuild || nb.LineShare != nil {
		t.Fatalf("not in build = %+v", nb)
	}
}

func TestPointFromAndChange(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 12, 0, 0, 0, time.UTC) }
	m := Measurement{
		MeasuredAt: day(3),
		Coverage: CoverageResult{State: StateMeasured, CoverageFigure: CoverageFigure{
			Lines: 200, Covered: 100,
			Reports:      []ReportSummary{{Use: UseCounted}, {Use: UseSameRun}},
			NewestReport: day(2),
		}},
		Duplication: DuplicationResult{State: StateCodeIntelOff},
	}
	p := PointFrom(m)
	if p.Day != "2026-11-03" || p.CoverageReports != 1 || *p.CoveragePercent() != 50 || p.DupLineShare() != nil {
		t.Fatalf("point = %+v", p)
	}
	points := []DayPoint{
		p,
		{Day: "2026-11-01", CoverageState: StateMeasured, CoverageLines: 100, CoverageCovered: 40, DupState: StateMeasured, DupEligibleLines: 100, DupClonedLines: 10},
		{Day: "2026-11-02", CoverageState: StateNoReport, DupState: StateMeasured, DupEligibleLines: 100, DupClonedLines: 12},
	}
	c := CoverageChange(points)
	if c.Days != 2 || c.FromDay != "2026-11-01" || c.ToDay != "2026-11-03" || c.Delta == nil || *c.Delta != 10 {
		t.Fatalf("coverage change = %+v", c)
	}
	d := DuplicationChange(points)
	if d.Days != 2 || *d.From != 10 || *d.To != 12 {
		t.Fatalf("dup change = %+v", d)
	}
	one := CoverageChange(points[:1])
	if one.Days != 1 || one.Delta != nil {
		t.Fatalf("one point has no delta: %+v", one)
	}
}
