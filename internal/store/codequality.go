package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/codequality"
)

// codequality.go is the ONE owner of project_quality_daily (agent migrations
// 219 and 221, the Projects page's quality-metric trend; docs/projects-page.md
// "Quality metrics"). One row per project per UTC day, the last
// measurement of the day wins. Numbers and states only.
//
// NODE-LOCAL: orgpush.go never names the table (privacy sentinel,
// tests/invariant/privacy_test.go).
//
// The codeintel reads the duplication and complexity figures need live
// beside it in codequality_dup.go and codequality_cx.go
// (codequality_dup_omit.go in a build without the codeintel component).

// QualityHistoryDays is how long daily rows are kept: the upsert prunes the
// project's rows older than this.
const QualityHistoryDays = 400

// UpsertProjectQualityDay writes p as projectID's row for p.Day, replacing
// an earlier measurement of the same day, and prunes the project's rows
// older than QualityHistoryDays before p.Day.
func (s *Store) UpsertProjectQualityDay(ctx context.Context, projectID int64, p codequality.DayPoint) error {
	if projectID <= 0 || p.Day == "" {
		return fmt.Errorf("store.UpsertProjectQualityDay: project %d day %q", projectID, p.Day)
	}
	day, err := time.Parse("2006-01-02", p.Day)
	if err != nil {
		return fmt.Errorf("store.UpsertProjectQualityDay: day: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.UpsertProjectQualityDay: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO project_quality_daily (
			project_id, day, measured_at,
			coverage_state, coverage_lines, coverage_covered, coverage_reports, coverage_report_at,
			dup_state, dup_eligible_symbols, dup_cloned_symbols, dup_eligible_lines, dup_cloned_lines, dup_groups, dup_indexed_at,
			complexity_state, complexity_functions, complexity_over, complexity_sum, complexity_p90, complexity_max)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(project_id, day) DO UPDATE SET
			measured_at = excluded.measured_at,
			coverage_state = excluded.coverage_state,
			coverage_lines = excluded.coverage_lines,
			coverage_covered = excluded.coverage_covered,
			coverage_reports = excluded.coverage_reports,
			coverage_report_at = excluded.coverage_report_at,
			dup_state = excluded.dup_state,
			dup_eligible_symbols = excluded.dup_eligible_symbols,
			dup_cloned_symbols = excluded.dup_cloned_symbols,
			dup_eligible_lines = excluded.dup_eligible_lines,
			dup_cloned_lines = excluded.dup_cloned_lines,
			dup_groups = excluded.dup_groups,
			dup_indexed_at = excluded.dup_indexed_at,
			complexity_state = excluded.complexity_state,
			complexity_functions = excluded.complexity_functions,
			complexity_over = excluded.complexity_over,
			complexity_sum = excluded.complexity_sum,
			complexity_p90 = excluded.complexity_p90,
			complexity_max = excluded.complexity_max`,
		projectID, p.Day, timestamp(p.MeasuredAt),
		string(p.CoverageState), p.CoverageLines, p.CoverageCovered, p.CoverageReports, optionalTimestamp(p.CoverageReportAt),
		string(p.DupState), p.DupEligibleSymbols, p.DupClonedSymbols, p.DupEligibleLines, p.DupClonedLines, p.DupGroups, optionalTimestamp(p.DupIndexedAt),
		string(p.ComplexityState), p.ComplexityFunctions, p.ComplexityOver, p.ComplexitySum, p.ComplexityP90, p.ComplexityMax,
	); err != nil {
		return fmt.Errorf("store.UpsertProjectQualityDay: upsert: %w", err)
	}
	cutoff := day.AddDate(0, 0, -QualityHistoryDays).Format("2006-01-02")
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM project_quality_daily WHERE project_id = ? AND day < ?`, projectID, cutoff); err != nil {
		return fmt.Errorf("store.UpsertProjectQualityDay: prune: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.UpsertProjectQualityDay: commit: %w", err)
	}
	return nil
}

// qualityDayColumns is the read column list of scanQualityDay (an absent
// time is stored as "" through commits.go's optionalTimestamp).
const qualityDayColumns = `day, measured_at,
	coverage_state, coverage_lines, coverage_covered, coverage_reports, coverage_report_at,
	dup_state, dup_eligible_symbols, dup_cloned_symbols, dup_eligible_lines, dup_cloned_lines, dup_groups, dup_indexed_at,
	complexity_state, complexity_functions, complexity_over, complexity_sum, complexity_p90, complexity_max`

func scanQualityDay(r rowScanner) (codequality.DayPoint, error) {
	var p codequality.DayPoint
	var measured, reportAt, indexedAt, covState, dupState, cxState string
	if err := r.Scan(&p.Day, &measured,
		&covState, &p.CoverageLines, &p.CoverageCovered, &p.CoverageReports, &reportAt,
		&dupState, &p.DupEligibleSymbols, &p.DupClonedSymbols, &p.DupEligibleLines, &p.DupClonedLines, &p.DupGroups, &indexedAt,
		&cxState, &p.ComplexityFunctions, &p.ComplexityOver, &p.ComplexitySum, &p.ComplexityP90, &p.ComplexityMax); err != nil {
		return p, err
	}
	p.MeasuredAt = parseStoredTime(measured)
	p.CoverageReportAt = parseStoredTime(reportAt)
	p.DupIndexedAt = parseStoredTime(indexedAt)
	p.CoverageState = codequality.State(covState)
	p.DupState = codequality.State(dupState)
	p.ComplexityState = codequality.State(cxState)
	return p, nil
}

// LoadProjectQualityHistory returns projectID's daily rows with day >=
// since's UTC day, oldest first.
func (s *Store) LoadProjectQualityHistory(ctx context.Context, projectID int64, since time.Time) ([]codequality.DayPoint, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+qualityDayColumns+` FROM project_quality_daily
		  WHERE project_id = ? AND day >= ? ORDER BY day`, projectID, codequality.Day(since))
	if err != nil {
		return nil, fmt.Errorf("store.LoadProjectQualityHistory: %w", err)
	}
	defer rows.Close()
	var out []codequality.DayPoint
	for rows.Next() {
		p, err := scanQualityDay(rows)
		if err != nil {
			return nil, fmt.Errorf("store.LoadProjectQualityHistory: scan: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// LatestProjectQualityDay returns projectID's newest daily row, ok=false
// when it has none.
func (s *Store) LatestProjectQualityDay(ctx context.Context, projectID int64) (codequality.DayPoint, bool, error) {
	p, err := scanQualityDay(s.db.QueryRowContext(ctx,
		`SELECT `+qualityDayColumns+` FROM project_quality_daily
		  WHERE project_id = ? ORDER BY day DESC LIMIT 1`, projectID))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return codequality.DayPoint{}, false, nil
	case err != nil:
		return codequality.DayPoint{}, false, fmt.Errorf("store.LatestProjectQualityDay: %w", err)
	}
	return p, true, nil
}
