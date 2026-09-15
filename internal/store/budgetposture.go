package store

import "github.com/marmutapp/superbased-observer/internal/orgcontract"

// The org BUDGET posture seam
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3d, wave W3b).
//
// The posture is a LIVE fact about the running guard and the last budget
// fetch — it is not stored in any table, and there is deliberately no
// budget table on the node at all. So this is a pure func seam, bound by
// cmd/observer's guard wiring, and orgpush.go composes it through
// composeBudgetPosture: the RoutingSummaries / ObsOrgProviders pattern, for the
// same reason (one owner per concern, and the push SELECT keeps its module
// boundary).
//
// WHAT IT MAY CARRY is fixed by orgcontract.BudgetPostureRow and pinned by
// tests/invariant/privacy_test.go: enums and booleans only. No cap value and no
// resolved scope — a resolved scope names a TEAM, and a cap value is a number
// an admin can correlate back to one team's budget row. Both are already known
// to the server that signed them.

// BudgetPostureProvider returns this node's current budget posture. ok=false
// means "nothing to report" (the guard is off, or the rail has never run), in
// which case NO row ships and the envelope stays byte-identical to a
// pre-feature node's.
type BudgetPostureProvider func() (orgcontract.BudgetPostureRow, bool)

// SetBudgetPostureProvider wires the posture seam. Idempotent; nil restores
// "no posture reported".
func (s *Store) SetBudgetPostureProvider(p BudgetPostureProvider) { s.budgetPosture = p }

// composeBudgetPosture resolves the posture row for one push envelope.
//
// It is a FUNCTION rather than an inline read for the reason the privacy
// sentinel encodes: the push SELECT must stay free of any subsystem's table
// names, and a posture that later grew a durable backing table would then be
// read HERE, not there. Composing through the seam from day one means that
// change never has to move.
//
// It is UNGATED by [org_client.share] on purpose, and that is a deliberate
// posture call rather than an oversight: the row discloses whether the node is
// enforcing a budget THE ORG ITSELF AUTHORED and signed, in enums. It names no
// project, no session, no path, no command, no model and no number. Withholding
// it would leave an admin unable to tell "not covered" from "not reported",
// which is exactly the honesty failure §3.3d exists to prevent. A node that
// wants to disclose nothing here turns the rail off ([guard.budget].from_org =
// false), and the row then says so.
func (s *Store) composeBudgetPosture() *orgcontract.BudgetPostureRow {
	if s.budgetPosture == nil {
		return nil
	}
	row, ok := s.budgetPosture()
	if !ok {
		return nil
	}
	return &row
}
