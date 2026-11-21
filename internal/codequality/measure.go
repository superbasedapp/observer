package codequality

import (
	"sort"
	"time"
)

// CoverageResult is one project's coverage answer: its state, the reason,
// and (StateMeasured) the figure. Problems lists the reports that exist but
// were not used, in any state.
type CoverageResult struct {
	State  State
	Reason string
	CoverageFigure
	Problems []Problem
}

// DuplicationResult is one project's duplication answer.
type DuplicationResult struct {
	State  State
	Reason string
	DuplicationFigure
	Index IndexFacts
	// Stale: measured from an index left from when code intelligence was
	// on; it is no longer refreshed.
	Stale bool
}

// Measurement is one measurement of one project.
type Measurement struct {
	MeasuredAt  time.Time
	Coverage    CoverageResult
	Duplication DuplicationResult
	Complexity  ComplexityResult
}

// MeasureCoverage composes the coverage answer from the reports found and
// the problems met, through the coverage state table.
func MeasureCoverage(enabled, rootMissing bool, found []Found, problems []Problem) CoverageResult {
	res := CoverageResult{Problems: append([]Problem(nil), problems...)}
	sort.SliceStable(res.Problems, func(i, j int) bool { return res.Problems[i].RelPath < res.Problems[j].RelPath })
	if enabled && !rootMissing {
		res.CoverageFigure = Combine(found)
	}
	res.State, res.Reason = CoverageState(CoverageFacts{
		Enabled: enabled, RootMissing: rootMissing, Found: len(found),
		Problems: len(problems), Lines: res.Lines,
	})
	if res.State != StateMeasured {
		// Keep the report list (it explains no_lines / unreadable) but no
		// numbers a reader could take for a measurement.
		res.Lines, res.Covered, res.Percent, res.LeastCovered = 0, 0, nil, nil
	}
	return res
}

// MeasureDuplication composes the duplication answer from the store's
// index read, through the duplication state table.
func MeasureDuplication(enabled, codeIntelOn bool, in DuplicationInput) DuplicationResult {
	res := DuplicationResult{Index: in.Index}
	if enabled && !in.Index.NotInBuild {
		res.DuplicationFigure = Duplicate(in.Symbols, in.Buckets)
	}
	res.State, res.Reason = DuplicationState(DuplicationFacts{
		Enabled: enabled, CodeIntelOn: codeIntelOn, NotInBuild: in.Index.NotInBuild,
		Archived: in.Index.Archived, IndexedFiles: in.Index.IndexedFiles,
		EligibleSymbols: res.EligibleSymbols,
	})
	if res.State != StateMeasured {
		res.DuplicationFigure = DuplicationFigure{EligibleSymbols: res.EligibleSymbols}
		return res
	}
	res.Stale = !codeIntelOn
	return res
}

// Day is the UTC calendar day a measurement belongs to.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// DayPoint is one project's stored daily value: numbers and states only,
// never a path from a report or a symbol name. The store keeps one per
// project per UTC day; a later measurement the same day replaces it.
type DayPoint struct {
	Day                string
	MeasuredAt         time.Time
	CoverageState      State
	CoverageLines      int
	CoverageCovered    int
	CoverageReports    int
	CoverageReportAt   time.Time // newest counted report's modification time
	DupState           State
	DupEligibleSymbols int
	DupClonedSymbols   int
	DupEligibleLines   int
	DupClonedLines     int
	DupGroups          int
	DupIndexedAt       time.Time
	// ComplexityState is "" on a row written before the complexity columns
	// existed (migration 221): not recorded, read as not measured.
	ComplexityState     State
	ComplexityFunctions int
	ComplexityOver      int
	ComplexitySum       int
	ComplexityP90       int
	ComplexityMax       int
}

// PointFrom is the stored daily value of m.
func PointFrom(m Measurement) DayPoint {
	p := DayPoint{
		Day: Day(m.MeasuredAt), MeasuredAt: m.MeasuredAt,
		CoverageState: m.Coverage.State, DupState: m.Duplication.State,
	}
	if m.Coverage.State == StateMeasured {
		p.CoverageLines, p.CoverageCovered = m.Coverage.Lines, m.Coverage.Covered
		for _, r := range m.Coverage.Reports {
			if r.Use == UseCounted {
				p.CoverageReports++
			}
		}
		p.CoverageReportAt = m.Coverage.NewestReport
	}
	if m.Duplication.State == StateMeasured {
		d := m.Duplication
		p.DupEligibleSymbols, p.DupClonedSymbols = d.EligibleSymbols, d.ClonedSymbols
		p.DupEligibleLines, p.DupClonedLines, p.DupGroups = d.EligibleLines, d.ClonedLines, d.Groups
		p.DupIndexedAt = d.Index.LastIndexedAt
	}
	p.ComplexityState = m.Complexity.State
	if m.Complexity.State == StateMeasured {
		c := m.Complexity
		p.ComplexityFunctions, p.ComplexityOver, p.ComplexitySum = c.Functions, c.Over, c.Sum
		p.ComplexityP90, p.ComplexityMax = c.P90, c.Max
	}
	return p
}

// CoveragePercent is the point's line coverage, nil when not measured.
func (p DayPoint) CoveragePercent() *float64 {
	if p.CoverageState != StateMeasured {
		return nil
	}
	return Percent(p.CoverageCovered, p.CoverageLines)
}

// DupLineShare is the point's duplicated-line share, nil when not measured.
func (p DayPoint) DupLineShare() *float64 {
	if p.DupState != StateMeasured {
		return nil
	}
	return Percent(p.DupClonedLines, p.DupEligibleLines)
}

// ComplexityOverShare is the point's share of functions over
// ComplexityThreshold, nil when not measured.
func (p DayPoint) ComplexityOverShare() *float64 {
	if p.ComplexityState != StateMeasured {
		return nil
	}
	return Percent(p.ComplexityOver, p.ComplexityFunctions)
}

// Change is a metric's movement over the history: its first and last
// measured values (in day order) and the difference in percentage points.
// Points where the metric was not measured are skipped, never read as 0.
type Change struct {
	FromDay string   `json:"from_day,omitempty"`
	ToDay   string   `json:"to_day,omitempty"`
	From    *float64 `json:"from,omitempty"`
	To      *float64 `json:"to,omitempty"`
	// Delta is To - From in percentage points; nil with fewer than two
	// measured days.
	Delta *float64 `json:"delta,omitempty"`
	// Days counts the measured days.
	Days int `json:"days"`
}

// CoverageChange is the coverage movement over points.
func CoverageChange(points []DayPoint) Change { return change(points, DayPoint.CoveragePercent) }

// DuplicationChange is the duplicated-line-share movement over points.
func DuplicationChange(points []DayPoint) Change { return change(points, DayPoint.DupLineShare) }

// ComplexityChange is the movement of the share of functions over
// ComplexityThreshold.
func ComplexityChange(points []DayPoint) Change { return change(points, DayPoint.ComplexityOverShare) }

func change(points []DayPoint, value func(DayPoint) *float64) Change {
	ordered := append([]DayPoint(nil), points...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Day < ordered[j].Day })
	var c Change
	for _, p := range ordered {
		v := value(p)
		if v == nil {
			continue
		}
		c.Days++
		if c.From == nil {
			c.From, c.FromDay = v, p.Day
		}
		c.To, c.ToDay = v, p.Day
	}
	if c.Days >= 2 {
		d := *c.To - *c.From
		c.Delta = &d
	}
	return c
}
