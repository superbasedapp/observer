package main

import (
	"context"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// nodeInterventionPostureProvider adds a live controller report to the
// existing budget posture without changing the proxy guard's claims. Only a
// closed aggregate enum leaves the node; no PID, path, argument, cap or usage
// value is added to the organization wire.
func nodeInterventionPostureProvider(ctx context.Context, st *store.Store, dbPath string, base store.BudgetPostureProvider) store.BudgetPostureProvider {
	return func() (orgcontract.BudgetPostureRow, bool) {
		if base == nil {
			return orgcontract.BudgetPostureRow{}, false
		}
		row, ok := base()
		if !ok {
			return row, false
		}
		row.DirectControl = "control_unavailable"
		reportCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		auth, err := nodeInterventionAuthority(reportCtx, st, os.Getuid(), time.Now().UTC())
		if err != nil {
			return row, true
		}
		if !auth.Authorized {
			row.DirectControl = "not_required"
			return row, true
		}
		status, err := readNodeInterventionStatus(reportCtx, st, dbPath)
		if err != nil {
			return row, true
		}
		switch status.State {
		case "pending_control", "control_unavailable":
			row.DirectControl = status.State
		case "partial":
			// A valid report can still describe failed inventory, signalling or
			// audit. The aggregate org enum must not attest usable process
			// control when the local controller reports that capability lost.
			if status.ProcessCutoff == "active" {
				row.DirectControl = orgcontract.DirectControlPartial
			}
		}
		return row, true
	}
}
