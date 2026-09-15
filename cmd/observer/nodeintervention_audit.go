package main

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// recordNodeInterventionOutcomes runs after reconciliation has released every
// authority, policy and pricing fence. Audit writes must never run inside a
// signal callback, which already holds the SQLite write reservation.
func recordNodeInterventionOutcomes(ctx context.Context, st *store.Store, outcomes []intervention.Outcome) error {
	auditCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, outcome := range outcomes {
		if outcome.Status == "allowed" || outcome.Status == "not_authorized" {
			continue
		}
		if err := st.InsertNodeProcessControlAudit(auditCtx, nodeInterventionAudit(outcome, time.Now().UTC())); err != nil {
			return fmt.Errorf("node intervention: record process outcome: %w", err)
		}
	}
	return nil
}

func nodeInterventionAudit(outcome intervention.Outcome, at time.Time) store.NodeProcessControlAudit {
	var tool string
	for _, surface := range integration.AllInterventionSurfaces() {
		if surface.ID == outcome.Workload.SurfaceID {
			tool = surface.Tool
			break
		}
	}
	id := outcome.Workload.Identity
	return store.NodeProcessControlAudit{
		TS: at, Surface: outcome.Workload.SurfaceID, Tool: tool, SessionID: outcome.Workload.SessionID,
		PID: id.PID, UID: id.UID, BootID: id.BootID, StartTicks: id.StartTicks,
		ExecutableDevice: id.Executable.Device, ExecutableInode: id.Executable.Inode,
		RuleID: outcome.RuleID, Reason: outcome.Reason, Status: outcome.Status,
		TermAttempted: outcome.TermAttempted, KillAttempted: outcome.KillAttempted,
		Stopped: outcome.Stopped, AlreadyExited: outcome.AlreadyExited,
		ControlVerified: outcome.ControlVerified, ErrorPresent: outcome.Err != nil,
		AuthorityFingerprint: outcome.Authority, BudgetFingerprint: outcome.BudgetBinding,
		PolicyRevision: outcome.PolicyRevision, MetadataHash: outcome.BudgetDocumentSHA256,
		PricingDocumentRequired: outcome.PricingDocumentRequired, PricingDocumentKnown: outcome.PricingDocumentKnown,
		PricingDocumentPresent: outcome.PricingDocumentPresent, PricingDocumentFingerprint: outcome.PricingDocumentSHA256,
	}
}
