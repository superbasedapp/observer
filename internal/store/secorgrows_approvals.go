//go:build !sbo_omit_security

package store

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// secorgrows_approvals.go is the one writer of sec_org_baseline_approvals
// (agent migration 194, NODE-LOCAL, lane LEFT-SHARED): the org's approvals
// of this node's baseline references, as the in-force security managed
// pull last served them. The table only labels a baseline "approved by the
// org"; nothing decides on it. Its read, which joins the project's own
// finding rows, lives with the other sec_* reads (secorgrows_reads.go,
// SecOrgBaselineApproval).

// ReplaceSecOrgBaselineApprovals replaces the stored approvals with the
// in-force pull's list (nil clears).
func (s *Store) ReplaceSecOrgBaselineApprovals(ctx context.Context, pullVersion int64, approvals []orgcontract.SecurityBaselineApproval) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.ReplaceSecOrgBaselineApprovals: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sec_org_baseline_approvals`); err != nil {
		return fmt.Errorf("store.ReplaceSecOrgBaselineApprovals: %w", err)
	}
	for _, a := range approvals {
		if _, err := tx.ExecContext(ctx, `INSERT INTO sec_org_baseline_approvals (project_key, ref_kind, ref, approved_at, pull_version)
			VALUES (?, ?, ?, ?, ?) ON CONFLICT (project_key, ref_kind, ref) DO UPDATE SET approved_at = excluded.approved_at, pull_version = excluded.pull_version`,
			a.Project, a.RefKind, a.Ref, a.ApprovedAt, pullVersion); err != nil {
			return fmt.Errorf("store.ReplaceSecOrgBaselineApprovals: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.ReplaceSecOrgBaselineApprovals: %w", err)
	}
	return nil
}
