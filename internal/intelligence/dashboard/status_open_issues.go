//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// status_open_issues.go computes /api/status's open-issue count, the
// sidebar's "Code security" badge. A feature-owned file: with
// sbo_omit_security status_open_issues_omit.go answers nil instead, and the
// badge hides.

// statusOpenIssues counts the open security issues the way the Code
// security page header does (web/src/pages/codesecurity/OverviewTab.tsx
// OPEN_ISSUES_PARAMS: grouped by issue, status open, no other filter), so
// the badge and the header's "N critical, M high open" never disagree. One
// SecFindingGroups read with a one-group page: its Total and BySeverity
// count every group the filter makes, not the page. It runs inside the
// /api/status scan (scanStatus), so it is memoized with the snapshot for
// statusSnapshotTTL. nil when the read fails, so the badge hides instead of
// showing a fabricated zero.
func (s *Server) statusOpenIssues(ctx context.Context, database *sql.DB) *diag.OpenIssueCounts {
	page, err := store.New(database).SecFindingGroups(ctx,
		store.SecFindingFilter{Status: policy.FindingStatusOpen},
		store.SecGroupQuery{By: store.SecGroupIssue, Limit: 1})
	if err != nil {
		s.opts.Logger.Warn("status: open security issue count failed", "err", err)
		return nil
	}
	return &diag.OpenIssueCounts{
		Total:    page.Total,
		Critical: page.BySeverity[string(policy.FindingSeverityCritical)],
		High:     page.BySeverity[string(policy.FindingSeverityHigh)],
	}
}
